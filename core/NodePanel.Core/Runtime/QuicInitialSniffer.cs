using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal static class QuicInitialSniffer
{
    private const uint VersionDraft29 = 0xff00001d;
    private const uint Version1 = 0x00000001;
    private const int AeadTagLength = 16;
    private const int HeaderProtectionSampleLength = 16;
    private const int MaxCryptoDataLength = 32767;
    private static readonly byte[] QuicSalt =
    [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
    ];
    private static readonly byte[] QuicSaltOld =
    [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
        0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
    ];

    public static SniffContentProbeState Detect(ReadOnlySpan<byte> payload, out string domain)
    {
        domain = string.Empty;
        if (payload.Length == 0)
        {
            return SniffContentProbeState.NoClue;
        }

        var cryptoData = new byte[MaxCryptoDataLength];
        var cryptoLength = 0;
        var packetOffset = 0;
        var parsedValidPacket = false;
        while (packetOffset < payload.Length)
        {
            var packetState = TryProcessPacket(
                payload[packetOffset..],
                cryptoData,
                ref cryptoLength,
                out var consumed,
                out domain);
            if (packetState == SniffContentProbeState.Matched)
            {
                return SniffContentProbeState.Matched;
            }

            if (packetState == SniffContentProbeState.Rejected)
            {
                return parsedValidPacket ? SniffContentProbeState.NeedMoreData : SniffContentProbeState.Rejected;
            }

            if (packetState == SniffContentProbeState.NoClue)
            {
                return parsedValidPacket ? SniffContentProbeState.NeedMoreData : SniffContentProbeState.NoClue;
            }

            parsedValidPacket = true;
            if (consumed <= 0)
            {
                return SniffContentProbeState.NeedMoreData;
            }

            packetOffset += consumed;
        }

        return parsedValidPacket ? SniffContentProbeState.NeedMoreData : SniffContentProbeState.Rejected;
    }

    private static SniffContentProbeState TryProcessPacket(
        ReadOnlySpan<byte> payload,
        byte[] cryptoData,
        ref int cryptoLength,
        out int consumed,
        out string domain)
    {
        consumed = 0;
        domain = string.Empty;
        if (payload.Length < 1)
        {
            return SniffContentProbeState.NoClue;
        }

        var typeByte = payload[0];
        var isLongHeader = (typeByte & 0x80) != 0;
        var hasFixedBit = (typeByte & 0x40) != 0;
        if (!isLongHeader || !hasFixedBit)
        {
            return SniffContentProbeState.Rejected;
        }

        if (payload.Length < 6)
        {
            return SniffContentProbeState.NoClue;
        }

        var version = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(1, 4));
        if (version != Version1 && version != VersionDraft29)
        {
            return SniffContentProbeState.Rejected;
        }

        var position = 5;
        if (!TryReadByte(payload, ref position, out var destinationConnectionIdLength) ||
            !TryReadBytes(payload, ref position, destinationConnectionIdLength, out var destinationConnectionId) ||
            !TryReadByte(payload, ref position, out var sourceConnectionIdLength) ||
            !TryReadBytes(payload, ref position, sourceConnectionIdLength, out _))
        {
            return SniffContentProbeState.NeedMoreData;
        }

        var isInitialPacket = ((typeByte & 0x30) >> 4) == 0x0;
        if (isInitialPacket)
        {
            if (!TryReadVarInt(payload, ref position, out var tokenLength) ||
                tokenLength > (ulong)(payload.Length - position) ||
                !TryReadBytes(payload, ref position, (int)tokenLength, out _))
            {
                return SniffContentProbeState.NeedMoreData;
            }
        }

        if (!TryReadVarInt(payload, ref position, out var packetLength) ||
            packetLength < 4)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        var headerLength = position;
        var totalPacketLength = checked(headerLength + (int)packetLength);
        if (payload.Length < totalPacketLength)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        consumed = totalPacketLength;
        if (!isInitialPacket)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        var packet = payload[..totalPacketLength].ToArray();
        if (packet.Length < headerLength + 4 + HeaderProtectionSampleLength)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        var initialSecret = HMACSHA256.HashData(
            version == Version1 ? QuicSalt : QuicSaltOld,
            destinationConnectionId.ToArray());
        var secret = HkdfExpandLabel(initialSecret, "client in", 32);
        var headerProtectionKey = HkdfExpandLabel(secret, "quic hp", 16);
        var key = HkdfExpandLabel(secret, "quic key", 16);
        var iv = HkdfExpandLabel(secret, "quic iv", 12);

        Span<byte> mask = stackalloc byte[16];
        if (!TryApplyHeaderProtection(packet, headerLength, headerProtectionKey, mask, out var packetNumberLength))
        {
            return SniffContentProbeState.Rejected;
        }

        if (headerLength + packetNumberLength > packet.Length)
        {
            return SniffContentProbeState.Rejected;
        }

        var protectedPayloadLength = (int)packetLength - packetNumberLength;
        if (protectedPayloadLength <= AeadTagLength ||
            headerLength + packetNumberLength + protectedPayloadLength > packet.Length)
        {
            return SniffContentProbeState.Rejected;
        }

        var packetNumberBytes = packet.AsSpan(headerLength, packetNumberLength);
        var nonce = CreatePacketNonce(iv, packetNumberBytes);
        var associatedData = packet.AsSpan(0, headerLength + packetNumberLength).ToArray();
        var ciphertext = packet.AsSpan(headerLength + packetNumberLength, protectedPayloadLength - AeadTagLength).ToArray();
        var tag = packet.AsSpan(packet.Length - AeadTagLength, AeadTagLength).ToArray();
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aead = new AesGcm(key, AeadTagLength);
            aead.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        }
        catch (CryptographicException)
        {
            return SniffContentProbeState.Rejected;
        }

        if (!TryCollectCryptoFrames(plaintext, cryptoData, ref cryptoLength))
        {
            return SniffContentProbeState.Rejected;
        }

        if (TryParseClientHello(cryptoData.AsSpan(0, cryptoLength), out domain))
        {
            return SniffContentProbeState.Matched;
        }

        return SniffContentProbeState.NeedMoreData;
    }

    private static bool TryCollectCryptoFrames(
        ReadOnlySpan<byte> plaintext,
        byte[] cryptoData,
        ref int cryptoLength)
    {
        var position = 0;
        while (position < plaintext.Length)
        {
            var frameType = plaintext[position++];
            while (frameType == 0x00 && position < plaintext.Length)
            {
                frameType = plaintext[position++];
            }

            switch (frameType)
            {
                case 0x00:
                case 0x01:
                    break;
                case 0x02:
                case 0x03:
                    if (!TrySkipAckFrame(plaintext, ref position, frameType == 0x03))
                    {
                        return false;
                    }

                    break;
                case 0x06:
                    if (!TryReadVarInt(plaintext, ref position, out var offset) ||
                        !TryReadVarInt(plaintext, ref position, out var length) ||
                        length > (ulong)(plaintext.Length - position))
                    {
                        return false;
                    }

                    var cryptoEnd = checked((int)(offset + length));
                    if (cryptoEnd > cryptoData.Length)
                    {
                        return false;
                    }

                    plaintext.Slice(position, (int)length).CopyTo(cryptoData.AsSpan((int)offset, (int)length));
                    cryptoLength = Math.Max(cryptoLength, cryptoEnd);
                    position += (int)length;
                    break;
                case 0x1c:
                    if (!TryReadVarInt(plaintext, ref position, out _) ||
                        !TryReadVarInt(plaintext, ref position, out _) ||
                        !TryReadVarInt(plaintext, ref position, out var reasonLength) ||
                        reasonLength > (ulong)(plaintext.Length - position))
                    {
                        return false;
                    }

                    position += (int)reasonLength;
                    break;
                default:
                    return false;
            }
        }

        return true;
    }

    private static bool TrySkipAckFrame(ReadOnlySpan<byte> plaintext, ref int position, bool hasEcn)
    {
        if (!TryReadVarInt(plaintext, ref position, out _) ||
            !TryReadVarInt(plaintext, ref position, out _) ||
            !TryReadVarInt(plaintext, ref position, out var ackRangeCount) ||
            !TryReadVarInt(plaintext, ref position, out _))
        {
            return false;
        }

        for (ulong index = 0; index < ackRangeCount; index++)
        {
            if (!TryReadVarInt(plaintext, ref position, out _) ||
                !TryReadVarInt(plaintext, ref position, out _))
            {
                return false;
            }
        }

        if (!hasEcn)
        {
            return true;
        }

        return TryReadVarInt(plaintext, ref position, out _) &&
               TryReadVarInt(plaintext, ref position, out _) &&
               TryReadVarInt(plaintext, ref position, out _);
    }

    private static bool TryParseClientHello(ReadOnlySpan<byte> cryptoData, out string domain)
    {
        domain = string.Empty;
        if (cryptoData.Length < 4)
        {
            return false;
        }

        var record = new byte[5 + cryptoData.Length];
        record[0] = 0x16;
        record[1] = 0x03;
        record[2] = 0x03;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), (ushort)cryptoData.Length);
        cryptoData.CopyTo(record.AsSpan(5));

        if (!RuntimeTlsClientHelloParser.TryParse(record, out var metadata) ||
            string.IsNullOrWhiteSpace(metadata.ServerName))
        {
            return false;
        }

        domain = metadata.ServerName;
        return true;
    }

    private static bool TryApplyHeaderProtection(
        byte[] packet,
        int headerLength,
        ReadOnlySpan<byte> headerProtectionKey,
        Span<byte> mask,
        out int packetNumberLength)
    {
        packetNumberLength = 0;
        if (packet.Length < headerLength + 4 + HeaderProtectionSampleLength)
        {
            return false;
        }

        var sample = packet.AsSpan(headerLength + 4, HeaderProtectionSampleLength).ToArray();
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = headerProtectionKey.ToArray();
        using var encryptor = aes.CreateEncryptor();
        var protectedMask = encryptor.TransformFinalBlock(sample, 0, sample.Length);
        protectedMask.CopyTo(mask);

        packet[0] ^= (byte)(mask[0] & 0x0f);
        packetNumberLength = (packet[0] & 0x03) + 1;
        if (packetNumberLength > 4 || packet.Length < headerLength + packetNumberLength)
        {
            return false;
        }

        for (var index = 0; index < packetNumberLength; index++)
        {
            packet[headerLength + index] ^= mask[index + 1];
        }

        return true;
    }

    private static byte[] CreatePacketNonce(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> packetNumberBytes)
    {
        var nonce = iv.ToArray();
        for (var index = 0; index < packetNumberBytes.Length; index++)
        {
            nonce[nonce.Length - packetNumberBytes.Length + index] ^= packetNumberBytes[index];
        }

        return nonce;
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, string label, int length)
        => RuntimeHkdf.ExpandLabelSha256(secret, label, length);

    private static byte[] HkdfExpand(ReadOnlySpan<byte> pseudorandomKey, ReadOnlySpan<byte> info, int length)
        => RuntimeHkdf.ExpandSha256(pseudorandomKey, info, length);

    private static bool TryReadVarInt(ReadOnlySpan<byte> payload, ref int position, out ulong value)
    {
        value = 0;
        if (position >= payload.Length)
        {
            return false;
        }

        var first = payload[position];
        var prefix = first >> 6;
        var length = 1 << prefix;
        if (position + length > payload.Length)
        {
            return false;
        }

        value = (ulong)(first & 0x3f);
        for (var index = 1; index < length; index++)
        {
            value = (value << 8) | (ulong)payload[position + index];
        }

        position += length;
        return true;
    }

    private static bool TryReadByte(ReadOnlySpan<byte> payload, ref int position, out int value)
    {
        value = 0;
        if (position >= payload.Length)
        {
            return false;
        }

        value = payload[position++];
        return true;
    }

    private static bool TryReadBytes(ReadOnlySpan<byte> payload, ref int position, int length, out ReadOnlySpan<byte> slice)
    {
        slice = ReadOnlySpan<byte>.Empty;
        if (length < 0 || position + length > payload.Length)
        {
            return false;
        }

        slice = payload.Slice(position, length);
        position += length;
        return true;
    }
}

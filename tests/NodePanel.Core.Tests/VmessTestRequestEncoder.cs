using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

internal static class VmessTestRequestEncoder
{
    private static readonly byte[] SaltAuthIdEncryptionKey = Encoding.ASCII.GetBytes("AES Auth ID Encryption");
    private static readonly byte[] SaltVmessHeaderPayloadAeadKey = Encoding.ASCII.GetBytes("VMess Header AEAD Key");
    private static readonly byte[] SaltVmessHeaderPayloadAeadIv = Encoding.ASCII.GetBytes("VMess Header AEAD Nonce");
    private static readonly byte[] SaltVmessHeaderPayloadLengthAeadKey = Encoding.ASCII.GetBytes("VMess Header AEAD Key_Length");
    private static readonly byte[] SaltVmessHeaderPayloadLengthAeadIv = Encoding.ASCII.GetBytes("VMess Header AEAD Nonce_Length");

    public static byte[] BuildRequestHeader(
        VmessUser user,
        VmessRequest request,
        byte[]? authId = null,
        byte[]? connectionNonce = null)
    {
        var headerPayload = BuildRequestPayload(request);
        authId ??= CreateAuthId(user);
        connectionNonce ??= [1, 2, 3, 4, 5, 6, 7, 8];
        var payloadLengthBytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(payloadLengthBytes, checked((ushort)headerPayload.Length));

        var encryptedHeaderLength = EncryptAead(
            VmessAeadKdf.Kdf16(user.CmdKey, SaltVmessHeaderPayloadLengthAeadKey, authId, connectionNonce),
            VmessAeadKdf.Kdf(user.CmdKey, SaltVmessHeaderPayloadLengthAeadIv, authId, connectionNonce).AsSpan(0, 12).ToArray(),
            payloadLengthBytes,
            authId);
        var encryptedHeaderPayload = EncryptAead(
            VmessAeadKdf.Kdf16(user.CmdKey, SaltVmessHeaderPayloadAeadKey, authId, connectionNonce),
            VmessAeadKdf.Kdf(user.CmdKey, SaltVmessHeaderPayloadAeadIv, authId, connectionNonce).AsSpan(0, 12).ToArray(),
            headerPayload,
            authId);

        using var stream = new MemoryStream();
        stream.Write(authId);
        stream.Write(encryptedHeaderLength);
        stream.Write(connectionNonce);
        stream.Write(encryptedHeaderPayload);
        return stream.ToArray();
    }

    public static byte[] CreateAuthId(VmessUser user, long? timestamp = null, uint? random = null)
    {
        var authIdPlaintext = BuildAuthIdPlaintext(timestamp, random);
        return EncryptEcb(
            VmessAeadKdf.Kdf16(user.CmdKey, SaltAuthIdEncryptionKey),
            authIdPlaintext);
    }

    private static byte[] BuildRequestPayload(VmessRequest request)
    {
        using var stream = new MemoryStream();
        stream.WriteByte(request.Version);
        stream.Write(request.RequestBodyIv);
        stream.Write(request.RequestBodyKey);
        stream.WriteByte(request.ResponseHeader);
        stream.WriteByte(request.Option);
        stream.WriteByte((byte)request.Security);
        stream.WriteByte(0);
        stream.WriteByte((byte)request.Command);

        var header = stream.ToArray();
        var checksum = ComputeFnv1a(header);
        var payload = new byte[header.Length + 4];
        Buffer.BlockCopy(header, 0, payload, 0, header.Length);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(header.Length, 4), checksum);
        return payload;
    }

    private static byte[] BuildAuthIdPlaintext(long? timestamp, uint? random)
    {
        var authId = new byte[16];
        BinaryPrimitives.WriteInt64BigEndian(authId.AsSpan(0, 8), timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        if (random.HasValue)
        {
            BinaryPrimitives.WriteUInt32BigEndian(authId.AsSpan(8, 4), random.Value);
        }
        else
        {
            RandomNumberGenerator.Fill(authId.AsSpan(8, 4));
        }
        BinaryPrimitives.WriteUInt32BigEndian(authId.AsSpan(12, 4), ComputeCrc32(authId.AsSpan(0, 12)));
        return authId;
    }

    private static byte[] EncryptEcb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key.ToArray();
        using var encryptor = aes.CreateEncryptor();
        var output = new byte[plaintext.Length];
        var input = plaintext.ToArray();
        var written = encryptor.TransformBlock(input, 0, input.Length, output, 0);
        Assert.Equal(output.Length, written);
        return output;
    }

    private static byte[] EncryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> additionalData)
    {
        var output = new byte[plaintext.Length + 16];
        using var aead = new AesGcm(key.ToArray(), 16);
        aead.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, 16),
            additionalData);
        return output;
    }

    private static uint ComputeFnv1a(ReadOnlySpan<byte> data)
    {
        const uint offsetBasis = 2166136261;
        const uint prime = 16777619;

        var hash = offsetBasis;
        foreach (var value in data)
        {
            hash ^= value;
            hash *= prime;
        }

        return hash;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0
                    ? (crc >> 1) ^ 0xEDB88320u
                    : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }
}

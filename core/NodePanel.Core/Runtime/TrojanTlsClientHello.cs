using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NodePanel.Core.Runtime;

public sealed record TrojanTlsClientHelloMetadata
{
    public int LegacyVersion { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<int> CipherSuites { get; init; } = Array.Empty<int>();

    public IReadOnlyList<int> Extensions { get; init; } = Array.Empty<int>();

    public IReadOnlyList<int> SupportedGroups { get; init; } = Array.Empty<int>();

    public IReadOnlyList<int> EcPointFormats { get; init; } = Array.Empty<int>();

    public string Ja3Text { get; init; } = string.Empty;

    public string Ja3Hash { get; init; } = string.Empty;
}

internal static class TrojanTlsClientHelloReader
{
    private const int MaxClientHelloBytes = 18 * 1024;

    public static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var header = new byte[5];
        var read = await ReadAvailableAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return Array.Empty<byte>();
        }

        if (read < header.Length)
        {
            return header.AsSpan(0, read).ToArray();
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
        var targetLength = Math.Min(MaxClientHelloBytes, header.Length + recordLength);
        var buffer = new byte[targetLength];
        header.CopyTo(buffer, 0);

        var remaining = targetLength - header.Length;
        if (remaining <= 0)
        {
            return buffer;
        }

        var payloadRead = await ReadAvailableAsync(
            stream,
            buffer.AsMemory(header.Length, remaining),
            cancellationToken).ConfigureAwait(false);
        var totalRead = header.Length + payloadRead;
        return totalRead == buffer.Length ? buffer : buffer.AsSpan(0, totalRead).ToArray();
    }

    private static async Task<int> ReadAvailableAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                break;
            }

            read += current;
        }

        return read;
    }
}

public static class TrojanTlsClientHelloParser
{
    public static bool TryParse(ReadOnlySpan<byte> payload, out TrojanTlsClientHelloMetadata metadata)
    {
        metadata = new TrojanTlsClientHelloMetadata();
        if (payload.Length < 9 || payload[0] != 0x16 || payload[5] != 0x01)
        {
            return false;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        var availableLength = Math.Min(payload.Length, recordLength + 5);
        if (availableLength < 9)
        {
            return false;
        }

        var handshakeLength =
            (payload[6] << 16) |
            (payload[7] << 8) |
            payload[8];
        var handshakeEnd = Math.Min(availableLength, 9 + handshakeLength);
        if (handshakeEnd < 43)
        {
            return false;
        }

        var position = 9;
        var legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;
        position += 32;

        if (!TryAdvanceVariableBlock(payload, handshakeEnd, ref position, 1))
        {
            return false;
        }

        if (position + 2 > handshakeEnd)
        {
            return false;
        }

        var cipherSuiteLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;
        if (position + cipherSuiteLength > handshakeEnd || (cipherSuiteLength & 1) != 0)
        {
            return false;
        }

        var cipherSuites = ReadUInt16List(payload.Slice(position, cipherSuiteLength), removeGrease: true);
        position += cipherSuiteLength;

        if (!TryAdvanceVariableBlock(payload, handshakeEnd, ref position, 1))
        {
            return false;
        }

        if (position + 2 > handshakeEnd)
        {
            return false;
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;
        var extensionsEnd = Math.Min(handshakeEnd, position + extensionsLength);

        var extensionIds = new List<int>();
        var applicationProtocols = new List<string>();
        var supportedGroups = new List<int>();
        var ecPointFormats = new List<int>();
        var serverName = string.Empty;

        while (position + 4 <= extensionsEnd)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
            var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position + 2, 2));
            position += 4;
            if (position + extensionLength > extensionsEnd)
            {
                return false;
            }

            if (!IsGreaseValue(extensionType))
            {
                extensionIds.Add(extensionType);
            }

            var extensionPayload = payload.Slice(position, extensionLength);
            switch (extensionType)
            {
                case 0x0000:
                    serverName = ReadServerName(extensionPayload);
                    break;
                case 0x0010:
                    applicationProtocols = ReadApplicationProtocols(extensionPayload);
                    break;
                case 0x000a:
                    supportedGroups = ReadSupportedGroups(extensionPayload);
                    break;
                case 0x000b:
                    ecPointFormats = ReadEcPointFormats(extensionPayload);
                    break;
            }

            position += extensionLength;
        }

        var ja3Text = BuildJa3Text(legacyVersion, cipherSuites, extensionIds, supportedGroups, ecPointFormats);
        metadata = new TrojanTlsClientHelloMetadata
        {
            LegacyVersion = legacyVersion,
            ServerName = serverName,
            ApplicationProtocols = applicationProtocols,
            CipherSuites = cipherSuites,
            Extensions = extensionIds,
            SupportedGroups = supportedGroups,
            EcPointFormats = ecPointFormats,
            Ja3Text = ja3Text,
            Ja3Hash = Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(ja3Text)))
        };
        return true;
    }

    private static string BuildJa3Text(
        int legacyVersion,
        IReadOnlyList<int> cipherSuites,
        IReadOnlyList<int> extensions,
        IReadOnlyList<int> supportedGroups,
        IReadOnlyList<int> ecPointFormats)
        => string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{legacyVersion},{Join(cipherSuites)},{Join(extensions)},{Join(supportedGroups)},{Join(ecPointFormats)}");

    private static string Join(IReadOnlyList<int> values)
        => values.Count == 0
            ? string.Empty
            : string.Join("-", values);

    private static string ReadServerName(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 5)
        {
            return string.Empty;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var position = 2;
        var listEnd = Math.Min(payload.Length, position + listLength);

        while (position + 3 <= listEnd)
        {
            var nameType = payload[position];
            var nameLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position + 1, 2));
            position += 3;
            if (position + nameLength > listEnd)
            {
                return string.Empty;
            }

            if (nameType == 0)
            {
                return NormalizeServerName(Encoding.ASCII.GetString(payload.Slice(position, nameLength)));
            }

            position += nameLength;
        }

        return string.Empty;
    }

    private static List<string> ReadApplicationProtocols(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return [];
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var position = 2;
        var listEnd = Math.Min(payload.Length, position + listLength);
        var protocols = new List<string>();

        while (position < listEnd)
        {
            var length = payload[position];
            position++;
            if (position + length > listEnd)
            {
                break;
            }

            var protocol = Encoding.ASCII.GetString(payload.Slice(position, length)).Trim().ToLowerInvariant();
            if (protocol.Length > 0)
            {
                protocols.Add(protocol);
            }

            position += length;
        }

        return protocols;
    }

    private static List<int> ReadSupportedGroups(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return [];
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var list = payload.Slice(2, Math.Min(payload.Length - 2, listLength));
        return ReadUInt16List(list, removeGrease: true);
    }

    private static List<int> ReadEcPointFormats(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0)
        {
            return [];
        }

        var listLength = Math.Min(payload[0], payload.Length - 1);
        var formats = new List<int>(listLength);
        for (var index = 0; index < listLength; index++)
        {
            formats.Add(payload[index + 1]);
        }

        return formats;
    }

    private static List<int> ReadUInt16List(ReadOnlySpan<byte> payload, bool removeGrease)
    {
        var values = new List<int>(payload.Length / 2);
        for (var index = 0; index + 1 < payload.Length; index += 2)
        {
            var value = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(index, 2));
            if (removeGrease && IsGreaseValue(value))
            {
                continue;
            }

            values.Add(value);
        }

        return values;
    }

    private static bool TryAdvanceVariableBlock(ReadOnlySpan<byte> payload, int availableLength, ref int position, int lengthBytes)
    {
        if (position + lengthBytes > availableLength)
        {
            return false;
        }

        var length = lengthBytes switch
        {
            1 => payload[position],
            2 => BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2)),
            _ => 0
        };
        position += lengthBytes;

        if (position + length > availableLength)
        {
            return false;
        }

        position += length;
        return true;
    }

    private static bool IsGreaseValue(int value)
        => (value & 0x0f0f) == 0x0a0a && ((value >> 8) & 0xff) == (value & 0xff);

    private static string NormalizeServerName(string value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().TrimEnd('.').ToLowerInvariant();
}

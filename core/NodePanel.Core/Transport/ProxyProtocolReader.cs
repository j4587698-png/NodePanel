using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NodePanel.Core.Transport;

public sealed record ProxyProtocolReadResult(EndPoint? RemoteEndPoint, EndPoint? LocalEndPoint);

public static class ProxyProtocolReader
{
    private const int SignatureLength = 12;
    private const int Version2FixedHeaderLength = 16;
    private const int MaxVersion1HeaderLength = 108;

    private static ReadOnlySpan<byte> Version2Signature
        => new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A };

    public static async Task<ProxyProtocolReadResult> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var signatureOrPrefix = new byte[SignatureLength];
        await ReadExactAsync(stream, signatureOrPrefix, cancellationToken).ConfigureAwait(false);

        if (signatureOrPrefix.AsSpan().SequenceEqual(Version2Signature))
        {
            return await ReadVersion2Async(stream, cancellationToken).ConfigureAwait(false);
        }

        return await ReadVersion1Async(stream, signatureOrPrefix, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<ProxyProtocolReadResult> ReadVersion1Async(
        Stream stream,
        byte[] initialBytes,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(MaxVersion1HeaderLength);
        buffer.Write(initialBytes, 0, initialBytes.Length);

        while (buffer.Length < MaxVersion1HeaderLength)
        {
            var next = new byte[1];
            await ReadExactAsync(stream, next, cancellationToken).ConfigureAwait(false);
            buffer.WriteByte(next[0]);

            var bytes = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
            if (bytes.Length >= 2 && bytes[^2] == '\r' && bytes[^1] == '\n')
            {
                return ParseVersion1(bytes[..^2]);
            }
        }

        throw new InvalidDataException("PROXY protocol v1 header exceeds the supported length.");
    }

    private static ProxyProtocolReadResult ParseVersion1(ReadOnlySpan<byte> header)
    {
        var text = Encoding.ASCII.GetString(header);
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !string.Equals(parts[0], "PROXY", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Invalid PROXY protocol v1 header.");
        }

        if (string.Equals(parts[1], "UNKNOWN", StringComparison.Ordinal))
        {
            return new ProxyProtocolReadResult(null, null);
        }

        if (parts.Length != 6)
        {
            throw new InvalidDataException("Invalid PROXY protocol v1 header field count.");
        }

        if (!IPAddress.TryParse(parts[2], out var sourceAddress) ||
            !IPAddress.TryParse(parts[3], out var destinationAddress) ||
            !ushort.TryParse(parts[4], out var sourcePort) ||
            !ushort.TryParse(parts[5], out var destinationPort))
        {
            throw new InvalidDataException("Invalid PROXY protocol v1 address or port.");
        }

        return new ProxyProtocolReadResult(
            new IPEndPoint(sourceAddress, sourcePort),
            new IPEndPoint(destinationAddress, destinationPort));
    }

    private static async Task<ProxyProtocolReadResult> ReadVersion2Async(Stream stream, CancellationToken cancellationToken)
    {
        var remainingHeader = new byte[Version2FixedHeaderLength - SignatureLength];
        await ReadExactAsync(stream, remainingHeader, cancellationToken).ConfigureAwait(false);

        var versionAndCommand = remainingHeader[0];
        if ((versionAndCommand & 0xF0) != 0x20)
        {
            throw new InvalidDataException("Unsupported PROXY protocol version.");
        }

        var command = versionAndCommand & 0x0F;
        var transport = remainingHeader[1];
        var addressLength = BinaryPrimitives.ReadUInt16BigEndian(remainingHeader.AsSpan(2, 2));

        var addressBytes = new byte[addressLength];
        if (addressLength > 0)
        {
            await ReadExactAsync(stream, addressBytes, cancellationToken).ConfigureAwait(false);
        }

        if (command == 0x00)
        {
            return new ProxyProtocolReadResult(null, null);
        }

        return transport switch
        {
            0x11 => ParseVersion2Ipv4(addressBytes),
            0x21 => ParseVersion2Ipv6(addressBytes),
            _ => throw new InvalidDataException($"Unsupported PROXY protocol v2 transport family: 0x{transport:X2}.")
        };
    }

    private static ProxyProtocolReadResult ParseVersion2Ipv4(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 12)
        {
            throw new InvalidDataException("PROXY protocol v2 IPv4 payload is incomplete.");
        }

        return new ProxyProtocolReadResult(
            new IPEndPoint(new IPAddress(bytes[..4]), BinaryPrimitives.ReadUInt16BigEndian(bytes[8..10])),
            new IPEndPoint(new IPAddress(bytes[4..8]), BinaryPrimitives.ReadUInt16BigEndian(bytes[10..12])));
    }

    private static ProxyProtocolReadResult ParseVersion2Ipv6(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 36)
        {
            throw new InvalidDataException("PROXY protocol v2 IPv6 payload is incomplete.");
        }

        return new ProxyProtocolReadResult(
            new IPEndPoint(new IPAddress(bytes[..16]), BinaryPrimitives.ReadUInt16BigEndian(bytes[32..34])),
            new IPEndPoint(new IPAddress(bytes[16..32]), BinaryPrimitives.ReadUInt16BigEndian(bytes[34..36])));
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading the PROXY protocol header.");
            }

            offset += read;
        }
    }
}

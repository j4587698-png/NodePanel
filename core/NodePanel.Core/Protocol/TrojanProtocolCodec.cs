using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NodePanel.Core.Protocol;

internal static class TrojanProtocolCodec
{
    public const int UserHashLength = 56;
    public const int MaxUdpPayloadLength = 8192;
    public const int MaxAddressPortLength = 1 + 1 + byte.MaxValue + 2;
    public const int UdpFrameOverhead = MaxAddressPortLength + 2 + 2;

    public static async ValueTask<string> ReadAddressAsync(Stream stream, CancellationToken cancellationToken)
    {
        var addressType = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        return await ReadAddressAsync(stream, addressType, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<string?> TryReadAddressAsync(Stream stream, CancellationToken cancellationToken)
    {
        var addressType = await TryReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (addressType is null)
        {
            return null;
        }

        return await ReadAddressAsync(stream, addressType.Value, cancellationToken).ConfigureAwait(false);
    }

    public static int WriteAddressPort(Span<byte> destination, string host, int port)
    {
        if (port is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");
        }

        if (IPAddress.TryParse(host, out var ipAddress))
        {
            var addressBytes = ipAddress.GetAddressBytes();
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                destination[0] = 0x01;
                addressBytes.CopyTo(destination[1..]);
                BinaryPrimitives.WriteUInt16BigEndian(destination[5..], (ushort)port);
                return 7;
            }

            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                destination[0] = 0x04;
                addressBytes.CopyTo(destination[1..]);
                BinaryPrimitives.WriteUInt16BigEndian(destination[17..], (ushort)port);
                return 19;
            }
        }

        var domainBytes = Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("Trojan domain address must be between 1 and 255 ASCII bytes.");
        }

        destination[0] = 0x03;
        destination[1] = (byte)domainBytes.Length;
        domainBytes.CopyTo(destination[2..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[(2 + domainBytes.Length)..], (ushort)port);
        return 4 + domainBytes.Length;
    }

    public static async ValueTask<ushort> ReadUInt16Async(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[2];
        await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
        return BinaryPrimitives.ReadUInt16BigEndian(buffer);
    }

    public static void WriteUInt16(Span<byte> destination, ushort value)
        => BinaryPrimitives.WriteUInt16BigEndian(destination, value);

    public static async ValueTask<byte> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
        return buffer[0];
    }

    public static async ValueTask<byte?> TryReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        var read = await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        return buffer[0];
    }

    public static async ValueTask ReadCrlfAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[2];
        await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
        if (buffer[0] != '\r' || buffer[1] != '\n')
        {
            throw new InvalidDataException("Trojan header CRLF is invalid.");
        }
    }

    public static void WriteCrlf(Span<byte> destination)
    {
        destination[0] = (byte)'\r';
        destination[1] = (byte)'\n';
    }

    public static async ValueTask ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while reading trojan payload.");
            }

            offset += read;
        }
    }

    private static async ValueTask<string> ReadAddressAsync(Stream stream, byte addressType, CancellationToken cancellationToken)
    {
        return addressType switch
        {
            0x01 => await ReadIpAddressAsync(stream, 4, cancellationToken).ConfigureAwait(false),
            0x04 => await ReadIpAddressAsync(stream, 16, cancellationToken).ConfigureAwait(false),
            0x03 => await ReadDomainAsync(stream, cancellationToken).ConfigureAwait(false),
            _ => throw new InvalidDataException($"Unsupported address type: {addressType}")
        };
    }

    private static async ValueTask<string> ReadIpAddressAsync(Stream stream, int byteCount, CancellationToken cancellationToken)
    {
        var bytes = new byte[byteCount];
        await ReadExactAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
        return new IPAddress(bytes).ToString();
    }

    private static async ValueTask<string> ReadDomainAsync(Stream stream, CancellationToken cancellationToken)
    {
        var length = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        var bytes = new byte[length];
        await ReadExactAsync(stream, bytes, cancellationToken).ConfigureAwait(false);
        return Encoding.ASCII.GetString(bytes);
    }
}

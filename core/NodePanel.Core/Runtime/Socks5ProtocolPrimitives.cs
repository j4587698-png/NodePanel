using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class Socks5ProtocolConstants
{
    public const byte Version = 0x05;
    public const byte CommandConnect = 0x01;
    public const byte CommandUdpAssociate = 0x03;

    public const byte AuthenticationMethodNone = 0x00;
    public const byte AuthenticationMethodUsernamePassword = 0x02;
    public const byte AuthenticationMethodNoAcceptable = 0xFF;
    public const byte AuthenticationVersionUsernamePassword = 0x01;
    public const byte AuthenticationStatusSucceeded = 0x00;
    public const byte AuthenticationStatusFailed = 0xFF;

    public const byte ReplySucceeded = 0x00;
    public const byte ReplyGeneralFailure = 0x01;
    public const byte ReplyCommandNotSupported = 0x07;
}

internal static class Socks4ProtocolConstants
{
    public const byte Version = 0x04;
    public const byte CommandConnect = 0x01;

    public const byte ReplyGranted = 0x5A;
    public const byte ReplyRejected = 0x5B;
}

internal static class Socks5AddressCodec
{
    public static int GetSerializedLength(string host)
    {
        if (IPAddress.TryParse(host, out var ipAddress))
        {
            return ipAddress.AddressFamily switch
            {
                System.Net.Sockets.AddressFamily.InterNetwork => 1 + 4 + 2,
                System.Net.Sockets.AddressFamily.InterNetworkV6 => 1 + 16 + 2,
                _ => throw new InvalidDataException($"Unsupported SOCKS5 address family: {host}.")
            };
        }

        var domainBytes = Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("SOCKS5 domain address must be between 1 and 255 ASCII bytes.");
        }

        return 1 + 1 + domainBytes.Length + 2;
    }

    public static int WriteAddressPort(Span<byte> destination, string host, int port)
    {
        if (port is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 0 and 65535.");
        }

        if (IPAddress.TryParse(host, out var ipAddress))
        {
            var addressBytes = ipAddress.GetAddressBytes();
            return ipAddress.AddressFamily switch
            {
                System.Net.Sockets.AddressFamily.InterNetwork => WriteIp(destination, 0x01, addressBytes, port),
                System.Net.Sockets.AddressFamily.InterNetworkV6 => WriteIp(destination, 0x04, addressBytes, port),
                _ => throw new InvalidDataException($"Unsupported SOCKS5 address family: {host}.")
            };
        }

        var domainBytes = Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("SOCKS5 domain address must be between 1 and 255 ASCII bytes.");
        }

        destination[0] = 0x03;
        destination[1] = (byte)domainBytes.Length;
        domainBytes.CopyTo(destination[2..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2 + domainBytes.Length, 2), (ushort)port);
        return 4 + domainBytes.Length;
    }

    public static (string Host, int Port, int Consumed) ReadAddressPort(ReadOnlySpan<byte> source)
    {
        if (source.Length < 1)
        {
            throw new InvalidDataException("SOCKS5 target address is incomplete.");
        }

        return source[0] switch
        {
            0x01 => ReadIp(source, 4),
            0x04 => ReadIp(source, 16),
            0x03 => ReadDomain(source),
            var value => throw new InvalidDataException($"Unsupported SOCKS5 address type: {value}.")
        };
    }

    private static int WriteIp(Span<byte> destination, byte addressType, byte[] addressBytes, int port)
    {
        destination[0] = addressType;
        addressBytes.CopyTo(destination[1..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(1 + addressBytes.Length, 2), (ushort)port);
        return 1 + addressBytes.Length + 2;
    }

    private static (string Host, int Port, int Consumed) ReadIp(ReadOnlySpan<byte> source, int byteCount)
    {
        if (source.Length < 1 + byteCount + 2)
        {
            throw new InvalidDataException("SOCKS5 IP target is incomplete.");
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(1 + byteCount, 2));
        return (new IPAddress(source.Slice(1, byteCount)).ToString(), port, 1 + byteCount + 2);
    }

    private static (string Host, int Port, int Consumed) ReadDomain(ReadOnlySpan<byte> source)
    {
        if (source.Length < 2)
        {
            throw new InvalidDataException("SOCKS5 domain target is incomplete.");
        }

        var length = source[1];
        if (source.Length < 2 + length + 2)
        {
            throw new InvalidDataException("SOCKS5 domain target is incomplete.");
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(source.Slice(2 + length, 2));
        return (Encoding.ASCII.GetString(source.Slice(2, length)), port, 4 + length);
    }
}

internal sealed record Socks5UdpPacket
{
    public required string Host { get; init; }

    public required int Port { get; init; }

    public byte[] Payload { get; init; } = Array.Empty<byte>();
}

internal static class Socks5UdpPacketCodec
{
    public static Socks5UdpPacket Decode(ReadOnlySpan<byte> source)
    {
        if (source.Length < 4)
        {
            throw new InvalidDataException("SOCKS5 UDP packet is incomplete.");
        }

        if (source[2] != 0x00)
        {
            throw new InvalidDataException("SOCKS5 fragmented UDP payload is not supported.");
        }

        var target = Socks5AddressCodec.ReadAddressPort(source[3..]);
        return new Socks5UdpPacket
        {
            Host = target.Host,
            Port = target.Port,
            Payload = source[(3 + target.Consumed)..].ToArray()
        };
    }

    public static byte[] Encode(string host, int port, ReadOnlySpan<byte> payload)
    {
        var addressLength = Socks5AddressCodec.GetSerializedLength(host);
        var buffer = new byte[3 + addressLength + payload.Length];
        buffer[0] = 0x00;
        buffer[1] = 0x00;
        buffer[2] = 0x00;
        var offset = 3 + Socks5AddressCodec.WriteAddressPort(buffer.AsSpan(3), host, port);
        payload.CopyTo(buffer.AsSpan(offset));
        return buffer;
    }
}

internal static class Socks5ReplyWriter
{
    public static Task WriteAsync(
        Stream stream,
        byte reply,
        EndPoint? bindEndPoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var (host, port) = bindEndPoint switch
        {
            IPEndPoint ipEndPoint => (ipEndPoint.Address.ToString(), ipEndPoint.Port),
            null => ("0.0.0.0", 0),
            _ => throw new NotSupportedException("SOCKS5 reply only supports IP endpoints.")
        };

        var addressLength = Socks5AddressCodec.GetSerializedLength(host);
        var buffer = new byte[3 + addressLength];
        buffer[0] = Socks5ProtocolConstants.Version;
        buffer[1] = reply;
        buffer[2] = 0x00;
        Socks5AddressCodec.WriteAddressPort(buffer.AsSpan(3), host, port);
        return stream.WriteAsync(buffer, cancellationToken).AsTask();
    }
}

internal static class Socks4ReplyWriter
{
    public static Task WriteAsync(
        Stream stream,
        byte reply,
        EndPoint? bindEndPoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var port = 0;
        var addressBytes = new byte[4];

        if (bindEndPoint is IPEndPoint ipEndPoint &&
            ipEndPoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            port = ipEndPoint.Port;
            ipEndPoint.Address.GetAddressBytes().CopyTo(addressBytes, 0);
        }

        var buffer = new byte[8];
        buffer[0] = 0x00;
        buffer[1] = reply;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), (ushort)port);
        addressBytes.CopyTo(buffer.AsSpan(4, 4));
        return stream.WriteAsync(buffer, cancellationToken).AsTask();
    }
}

using System.Buffers.Binary;

namespace NodePanel.Core.Runtime;

internal static class UdpOverTcpProtocol
{
    public const int LegacyVersion = 1;
    public const int Version = 2;
    public const string MagicAddress = "sp.v2.udp-over-tcp.arpa";
    public const string LegacyMagicAddress = "sp.udp-over-tcp.arpa";
    public const int MagicPort = 443;

    public static DispatchDestination CreateRequestDestination(int version)
        => new()
        {
            Host = IsLegacyVersion(version) ? LegacyMagicAddress : MagicAddress,
            Port = MagicPort,
            Network = DispatchNetwork.Tcp
        };

    public static async ValueTask WriteRequestAsync(
        Stream stream,
        int version,
        bool isConnect,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(destination);

        if (destination.Network != DispatchNetwork.Udp)
        {
            throw new NotSupportedException($"UDP over TCP request does not support '{destination.Network}'.");
        }

        var addressLength = Socks5AddressCodec.GetSerializedLength(destination.Host);
        var buffer = IsLegacyVersion(version)
            ? new byte[addressLength]
            : new byte[1 + addressLength];

        var offset = 0;
        if (!IsLegacyVersion(version))
        {
            buffer[offset++] = isConnect ? (byte)0x01 : (byte)0x00;
        }

        Socks5AddressCodec.WriteAddressPort(buffer.AsSpan(offset), destination.Host, destination.Port);
        await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<UdpOverTcpRequest> ReadRequestAsync(
        Stream stream,
        int version,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var isConnect = false;
        if (!IsLegacyVersion(version))
        {
            var flags = new byte[1];
            await ReadExactAsync(stream, flags, cancellationToken).ConfigureAwait(false);
            isConnect = (flags[0] & 0x01) != 0;
        }

        var address = await ReadAddressPortAsync(stream, cancellationToken).ConfigureAwait(false);
        return new UdpOverTcpRequest
        {
            IsConnect = isConnect,
            Destination = new DispatchDestination
            {
                Host = address.Host,
                Port = address.Port,
                Network = DispatchNetwork.Udp
            }
        };
    }

    public static async ValueTask WritePacketAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (payload.Length > ushort.MaxValue)
        {
            throw new InvalidDataException("UDP over TCP payload must not exceed 65535 bytes.");
        }

        var header = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(header, (ushort)payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        }
    }

    public static async ValueTask<byte[]?> ReadPacketAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var header = new byte[2];
        if (!await TryReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(header);
        if (length == 0)
        {
            return Array.Empty<byte>();
        }

        var payload = new byte[length];
        await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    private static bool IsLegacyVersion(int version)
        => version == LegacyVersion;

    private static async ValueTask<SocksAddress> ReadAddressPortAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var addressType = new byte[1];
        await ReadExactAsync(stream, addressType, cancellationToken).ConfigureAwait(false);

        switch (addressType[0])
        {
            case 0x01:
                return await ReadSizedAddressPortAsync(
                    stream,
                    addressType[0],
                    6,
                    cancellationToken).ConfigureAwait(false);
            case 0x04:
                return await ReadSizedAddressPortAsync(
                    stream,
                    addressType[0],
                    18,
                    cancellationToken).ConfigureAwait(false);
            case 0x03:
            {
                var domainLength = new byte[1];
                await ReadExactAsync(stream, domainLength, cancellationToken).ConfigureAwait(false);
                var payload = new byte[1 + domainLength[0] + 2];
                payload[0] = domainLength[0];
                await ReadExactAsync(stream, payload.AsMemory(1), cancellationToken).ConfigureAwait(false);
                return DecodeAddress(addressType[0], payload);
            }
            default:
                throw new InvalidDataException($"UDP over TCP returned an unsupported address type: {addressType[0]}.");
        }
    }

    private static async ValueTask<SocksAddress> ReadSizedAddressPortAsync(
        Stream stream,
        byte addressType,
        int payloadLength,
        CancellationToken cancellationToken)
    {
        var payload = new byte[payloadLength];
        await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return DecodeAddress(addressType, payload);
    }

    private static SocksAddress DecodeAddress(byte addressType, byte[] payload)
    {
        var buffer = new byte[1 + payload.Length];
        buffer[0] = addressType;
        payload.CopyTo(buffer.AsSpan(1));
        var address = Socks5AddressCodec.ReadAddressPort(buffer);
        return new SocksAddress
        {
            Host = address.Host,
            Port = address.Port
        };
    }

    private static async ValueTask ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        if (!await TryReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false))
        {
            throw new IOException("UDP over TCP stream closed unexpectedly.");
        }
    }

    private static async ValueTask<bool> TryReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (offset == 0)
                {
                    return false;
                }

                throw new IOException("UDP over TCP stream closed unexpectedly.");
            }

            offset += read;
        }

        return true;
    }
}

internal sealed record UdpOverTcpRequest
{
    public bool IsConnect { get; init; }

    public required DispatchDestination Destination { get; init; }
}

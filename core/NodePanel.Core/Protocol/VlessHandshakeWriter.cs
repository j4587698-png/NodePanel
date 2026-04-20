using System.Buffers.Binary;
using System.Net;

namespace NodePanel.Core.Protocol;

public sealed class VlessHandshakeWriter
{
    public byte[] Build(
        string userUuid,
        VlessCommand command,
        string targetHost,
        int targetPort,
        byte version = 0,
        VlessHeaderAddons? addons = null)
    {
        if (!ProtocolUuid.TryNormalize(userUuid, out var normalizedUserUuid))
        {
            throw new ArgumentException("VLESS user UUID is invalid.", nameof(userUuid));
        }

        if (command is not (VlessCommand.Connect or VlessCommand.Udp or VlessCommand.Mux or VlessCommand.Rvs))
        {
            throw new NotSupportedException($"Unsupported VLESS command: {command}.");
        }

        if (command is not (VlessCommand.Mux or VlessCommand.Rvs))
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);
            if (targetPort is <= 0 or > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(targetPort), targetPort, "Target port must be between 1 and 65535.");
            }
        }

        var addonBytes = VlessHeaderAddonsCodec.Encode(addons);
        var buffer = new byte[1 + 16 + 1 + addonBytes.Length + 1 + TrojanProtocolCodec.MaxAddressPortLength];
        var offset = 0;
        buffer[offset++] = version;

        if (!ProtocolUuid.TryWriteBytes(normalizedUserUuid, buffer.AsSpan(offset, 16)))
        {
            throw new InvalidDataException("VLESS user UUID could not be serialized.");
        }

        offset += 16;
        buffer[offset++] = checked((byte)addonBytes.Length);
        addonBytes.CopyTo(buffer.AsSpan(offset));
        offset += addonBytes.Length;
        buffer[offset++] = (byte)command;

        if (command is not (VlessCommand.Mux or VlessCommand.Rvs))
        {
            offset += WritePortAddress(buffer.AsSpan(offset), targetHost, targetPort);
        }

        return buffer.AsSpan(0, offset).ToArray();
    }

    public async ValueTask WriteAsync(
        Stream stream,
        string userUuid,
        VlessCommand command,
        string targetHost,
        int targetPort,
        byte version,
        CancellationToken cancellationToken,
        VlessHeaderAddons? addons = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = Build(userUuid, command, targetHost, targetPort, version, addons);
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken).ConfigureAwait(false);
    }

    private static int WritePortAddress(Span<byte> destination, string host, int port)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)port);
        return 2 + WriteAddress(destination[2..], host);
    }

    private static int WriteAddress(Span<byte> destination, string host)
    {
        if (IPAddress.TryParse(host, out var ipAddress))
        {
            var addressBytes = ipAddress.GetAddressBytes();
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                destination[0] = 0x01;
                addressBytes.CopyTo(destination[1..]);
                return 5;
            }

            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                destination[0] = 0x04;
                addressBytes.CopyTo(destination[1..]);
                return 17;
            }
        }

        var domainBytes = System.Text.Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("VLESS domain address must be between 1 and 255 ASCII bytes.");
        }

        destination[0] = 0x03;
        destination[1] = (byte)domainBytes.Length;
        domainBytes.CopyTo(destination[2..]);
        return 2 + domainBytes.Length;
    }
}

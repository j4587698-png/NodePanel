using System.Text;

namespace NodePanel.Core.Protocol;

public sealed record VlessHeaderAddons
{
    public static VlessHeaderAddons Empty { get; } = new();

    public string Flow { get; init; } = string.Empty;

    public byte[] Seed { get; init; } = Array.Empty<byte>();

    public bool IsEmpty
        => string.IsNullOrWhiteSpace(Flow) &&
           (Seed is null || Seed.Length == 0);
}

public enum VlessCommand : byte
{
    Connect = 0x01,
    Udp = 0x02,
    Mux = 0x03,
    Rvs = 0x04
}

public sealed record VlessRequest
{
    public byte Version { get; init; }

    public string UserUuid { get; init; } = string.Empty;

    public int VlessRoutePort { get; init; }

    public VlessCommand Command { get; init; }

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; }

    public VlessHeaderAddons Addons { get; init; } = VlessHeaderAddons.Empty;
}

public sealed class VlessHandshakeReader
{
    public async ValueTask<VlessRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var version = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);

        var userBytes = new byte[16];
        await TrojanProtocolCodec.ReadExactAsync(stream, userBytes, cancellationToken).ConfigureAwait(false);

        var addonLength = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        var addons = VlessHeaderAddons.Empty;
        if (addonLength > 0)
        {
            var addonBytes = new byte[addonLength];
            await TrojanProtocolCodec.ReadExactAsync(stream, addonBytes, cancellationToken).ConfigureAwait(false);
            addons = VlessHeaderAddonsCodec.Decode(addonBytes);
        }

        var command = (VlessCommand)await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (command is VlessCommand.Mux or VlessCommand.Rvs)
        {
            return new VlessRequest
            {
                Version = version,
                UserUuid = ProtocolUuid.Format(userBytes),
                VlessRoutePort = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(userBytes.AsSpan(6, 2)),
                Command = command,
                TargetHost = command == VlessCommand.Mux ? "v1.mux.cool" : "v1.rvs.cool",
                TargetPort = 0,
                Addons = addons
            };
        }

        return new VlessRequest
        {
            Version = version,
            UserUuid = ProtocolUuid.Format(userBytes),
            VlessRoutePort = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(userBytes.AsSpan(6, 2)),
            Command = command,
            TargetPort = await TrojanProtocolCodec.ReadUInt16Async(stream, cancellationToken).ConfigureAwait(false),
            TargetHost = await TrojanProtocolCodec.ReadAddressAsync(stream, cancellationToken).ConfigureAwait(false),
            Addons = addons
        };
    }

    public static ValueTask WriteResponseAsync(Stream stream, byte version, CancellationToken cancellationToken)
        => WriteResponseAsync(stream, version, VlessHeaderAddons.Empty, cancellationToken);

    public static async ValueTask WriteResponseAsync(
        Stream stream,
        byte version,
        VlessHeaderAddons? addons,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var addonBytes = VlessHeaderAddonsCodec.Encode(addons);
        var payload = new byte[2 + addonBytes.Length];
        payload[0] = version;
        payload[1] = checked((byte)addonBytes.Length);
        addonBytes.CopyTo(payload.AsSpan(2));
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask<VlessHeaderAddons> ReadResponseAsync(
        Stream stream,
        byte expectedVersion,
        CancellationToken cancellationToken)
    {
        var version = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (version != expectedVersion)
        {
            throw new InvalidDataException($"Unexpected VLESS response version. Expected {expectedVersion} but received {version}.");
        }

        var addonLength = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (addonLength == 0)
        {
            return VlessHeaderAddons.Empty;
        }

        var addonBytes = new byte[addonLength];
        await TrojanProtocolCodec.ReadExactAsync(stream, addonBytes, cancellationToken).ConfigureAwait(false);
        return VlessHeaderAddonsCodec.Decode(addonBytes);
    }
}

internal static class VlessHeaderAddonsCodec
{
    public static byte[] Encode(VlessHeaderAddons? addons)
    {
        if (addons is null || addons.IsEmpty)
        {
            return Array.Empty<byte>();
        }

        using var buffer = new MemoryStream();

        if (!string.IsNullOrWhiteSpace(addons.Flow))
        {
            buffer.WriteByte(0x0A);
            WriteVarint(buffer, checked((ulong)Encoding.UTF8.GetByteCount(addons.Flow)));
            var flowBytes = Encoding.UTF8.GetBytes(addons.Flow);
            buffer.Write(flowBytes, 0, flowBytes.Length);
        }

        if (addons.Seed is { Length: > 0 })
        {
            buffer.WriteByte(0x12);
            WriteVarint(buffer, checked((ulong)addons.Seed.Length));
            buffer.Write(addons.Seed, 0, addons.Seed.Length);
        }

        if (buffer.Length > byte.MaxValue)
        {
            throw new InvalidDataException("VLESS header addons exceed the 255-byte protocol limit.");
        }

        return buffer.ToArray();
    }

    public static VlessHeaderAddons Decode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0)
        {
            return VlessHeaderAddons.Empty;
        }

        var flow = string.Empty;
        byte[] seed = Array.Empty<byte>();
        var offset = 0;
        while (offset < payload.Length)
        {
            var tag = ReadVarint(payload, ref offset);
            var fieldNumber = tag >> 3;
            var wireType = (int)(tag & 0x07);

            switch (fieldNumber)
            {
                case 1 when wireType == 2:
                    flow = ReadLengthDelimitedString(payload, ref offset);
                    break;

                case 2 when wireType == 2:
                    seed = ReadLengthDelimitedBytes(payload, ref offset);
                    break;

                default:
                    SkipField(payload, ref offset, wireType);
                    break;
            }
        }

        if (string.IsNullOrWhiteSpace(flow) && seed.Length == 0)
        {
            return VlessHeaderAddons.Empty;
        }

        return new VlessHeaderAddons
        {
            Flow = flow,
            Seed = seed
        };
    }

    private static string ReadLengthDelimitedString(ReadOnlySpan<byte> payload, ref int offset)
        => Encoding.UTF8.GetString(ReadLengthDelimitedBytes(payload, ref offset));

    private static byte[] ReadLengthDelimitedBytes(ReadOnlySpan<byte> payload, ref int offset)
    {
        var length = checked((int)ReadVarint(payload, ref offset));
        if (length < 0 || payload.Length - offset < length)
        {
            throw new InvalidDataException("VLESS header addons contain a truncated length-delimited field.");
        }

        var value = payload.Slice(offset, length).ToArray();
        offset += length;
        return value;
    }

    private static void SkipField(ReadOnlySpan<byte> payload, ref int offset, int wireType)
    {
        switch (wireType)
        {
            case 0:
                _ = ReadVarint(payload, ref offset);
                return;

            case 1:
                RequireRemaining(payload, offset, 8);
                offset += 8;
                return;

            case 2:
                var length = checked((int)ReadVarint(payload, ref offset));
                RequireRemaining(payload, offset, length);
                offset += length;
                return;

            case 5:
                RequireRemaining(payload, offset, 4);
                offset += 4;
                return;

            default:
                throw new InvalidDataException($"Unsupported protobuf wire type in VLESS header addons: {wireType}.");
        }
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> payload, ref int offset)
    {
        ulong value = 0;
        var shift = 0;
        while (true)
        {
            if (offset >= payload.Length)
            {
                throw new InvalidDataException("VLESS header addons contain a truncated protobuf varint.");
            }

            var current = payload[offset++];
            value |= (ulong)(current & 0x7F) << shift;
            if ((current & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
            if (shift > 63)
            {
                throw new InvalidDataException("VLESS header addons contain an oversized protobuf varint.");
            }
        }
    }

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80)
        {
            stream.WriteByte((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        stream.WriteByte((byte)value);
    }

    private static void RequireRemaining(ReadOnlySpan<byte> payload, int offset, int length)
    {
        if (length < 0 || payload.Length - offset < length)
        {
            throw new InvalidDataException("VLESS header addons contain a truncated protobuf field.");
        }
    }
}

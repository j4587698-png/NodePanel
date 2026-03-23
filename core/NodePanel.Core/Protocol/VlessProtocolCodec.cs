namespace NodePanel.Core.Protocol;

public enum VlessCommand : byte
{
    Connect = 0x01,
    Udp = 0x02,
    Mux = 0x03
}

public sealed record VlessRequest
{
    public byte Version { get; init; }

    public string UserUuid { get; init; } = string.Empty;

    public VlessCommand Command { get; init; }

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; }
}

public sealed class VlessHandshakeReader
{
    public async ValueTask<VlessRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var version = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);

        var userBytes = new byte[16];
        await TrojanProtocolCodec.ReadExactAsync(stream, userBytes, cancellationToken).ConfigureAwait(false);

        var addonLength = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (addonLength > 0)
        {
            var addonBytes = new byte[addonLength];
            await TrojanProtocolCodec.ReadExactAsync(stream, addonBytes, cancellationToken).ConfigureAwait(false);
        }

        var command = (VlessCommand)await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (command is VlessCommand.Mux)
        {
            return new VlessRequest
            {
                Version = version,
                UserUuid = ProtocolUuid.Format(userBytes),
                Command = command,
                TargetHost = "v1.mux.cool",
                TargetPort = 0
            };
        }

        return new VlessRequest
        {
            Version = version,
            UserUuid = ProtocolUuid.Format(userBytes),
            Command = command,
            TargetHost = await TrojanProtocolCodec.ReadAddressAsync(stream, cancellationToken).ConfigureAwait(false),
            TargetPort = await TrojanProtocolCodec.ReadUInt16Async(stream, cancellationToken).ConfigureAwait(false)
        };
    }

    public static ValueTask WriteResponseAsync(Stream stream, byte version, CancellationToken cancellationToken)
    {
        return stream.WriteAsync(new byte[] { version, 0 }, cancellationToken);
    }
}

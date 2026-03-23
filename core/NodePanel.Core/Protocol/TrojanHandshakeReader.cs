using System.Net;
using System.Text;

namespace NodePanel.Core.Protocol;

public sealed class TrojanHandshakeReader
{
    public async ValueTask<TrojanRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var hashBytes = new byte[TrojanProtocolCodec.UserHashLength];
        await TrojanProtocolCodec.ReadExactAsync(stream, hashBytes, cancellationToken).ConfigureAwait(false);
        await TrojanProtocolCodec.ReadCrlfAsync(stream, cancellationToken).ConfigureAwait(false);

        var commandValue = await TrojanProtocolCodec.ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (commandValue is not (byte)TrojanCommand.Connect and not (byte)TrojanCommand.Associate)
        {
            throw new InvalidDataException($"Unsupported trojan command: {commandValue}");
        }

        var targetHost = await TrojanProtocolCodec.ReadAddressAsync(stream, cancellationToken).ConfigureAwait(false);
        var portBuffer = new byte[2];
        await TrojanProtocolCodec.ReadExactAsync(stream, portBuffer, cancellationToken).ConfigureAwait(false);
        var targetPort = (portBuffer[0] << 8) | portBuffer[1];

        await TrojanProtocolCodec.ReadCrlfAsync(stream, cancellationToken).ConfigureAwait(false);

        return new TrojanRequest
        {
            UserHash = Encoding.ASCII.GetString(hashBytes),
            Command = (TrojanCommand)commandValue,
            TargetHost = targetHost,
            TargetPort = targetPort
        };
    }
}

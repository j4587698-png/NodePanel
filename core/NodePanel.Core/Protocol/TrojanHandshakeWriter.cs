using System.Text;
using NodePanel.Core.Cryptography;

namespace NodePanel.Core.Protocol;

public sealed class TrojanHandshakeWriter
{
    public byte[] Build(
        string password,
        TrojanCommand command,
        string targetHost,
        int targetPort)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);

        if (command is not (TrojanCommand.Connect or TrojanCommand.Associate))
        {
            throw new NotSupportedException($"Unsupported trojan command: {command}.");
        }

        var userHash = TrojanPassword.ComputeHash(password);
        var buffer = new byte[TrojanProtocolCodec.UserHashLength + 2 + 1 + TrojanProtocolCodec.MaxAddressPortLength + 2];
        var offset = Encoding.ASCII.GetBytes(userHash, buffer);
        TrojanProtocolCodec.WriteCrlf(buffer.AsSpan(offset, 2));
        offset += 2;
        buffer[offset++] = (byte)command;
        offset += TrojanProtocolCodec.WriteAddressPort(buffer.AsSpan(offset), targetHost, targetPort);
        TrojanProtocolCodec.WriteCrlf(buffer.AsSpan(offset, 2));
        offset += 2;

        return buffer.AsSpan(0, offset).ToArray();
    }

    public async ValueTask WriteAsync(
        Stream stream,
        string password,
        TrojanCommand command,
        string targetHost,
        int targetPort,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var payload = Build(password, command, targetHost, targetPort);
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken).ConfigureAwait(false);
    }
}

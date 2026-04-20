using System.Security.Cryptography;
using System.Text;

namespace NodePanel.Core.Protocol;

public static class VmessAccountCodec
{
    private static readonly byte[] CmdKeySalt = Encoding.ASCII.GetBytes("c48619fe-8f02-49e0-b9e9-edf763e17e21");

    public static bool TryCreateCommandKey(string? uuid, out byte[] commandKey)
    {
        if (!ProtocolUuid.TryNormalize(uuid, out var normalizedUuid))
        {
            commandKey = Array.Empty<byte>();
            return false;
        }

        commandKey = CreateCommandKey(normalizedUuid);
        return commandKey.Length == 16;
    }

    public static byte[] CreateCommandKey(string normalizedUuid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(normalizedUuid);

        Span<byte> uuidBytes = stackalloc byte[16];
        if (!ProtocolUuid.TryWriteBytes(normalizedUuid, uuidBytes))
        {
            throw new ArgumentException("VMess UUID is invalid.", nameof(normalizedUuid));
        }

        var buffer = new byte[uuidBytes.Length + CmdKeySalt.Length];
        uuidBytes.CopyTo(buffer);
        CmdKeySalt.CopyTo(buffer.AsSpan(uuidBytes.Length));
        return MD5.HashData(buffer);
    }
}

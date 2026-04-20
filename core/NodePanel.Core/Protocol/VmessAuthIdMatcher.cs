using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NodePanel.Core.Protocol;

internal enum VmessAuthIdMatchOutcome
{
    InvalidChecksum = 0,
    NegativeTime = 1,
    InvalidTime = 2,
    Replay = 3,
    Valid = 4
}

internal static class VmessAuthIdMatcher
{
    private const int AuthIdToleranceSeconds = 120;
    private static readonly byte[] SaltAuthIdEncryptionKey = Encoding.ASCII.GetBytes("AES Auth ID Encryption");

    public static byte[] DeriveAuthIdKey(ReadOnlySpan<byte> cmdKey)
        => VmessAeadKdf.Kdf16(cmdKey, SaltAuthIdEncryptionKey);

    public static VmessAuthIdMatchOutcome Match(
        ReadOnlySpan<byte> authId,
        ReadOnlySpan<byte> authIdKey,
        VmessAuthIdHistory authIdHistory)
    {
        ArgumentNullException.ThrowIfNull(authIdHistory);

        var decryptedAuthId = DecryptAuthId(authId, authIdKey);
        var outcome = ValidateAuthId(decryptedAuthId);
        if (outcome is not VmessAuthIdMatchOutcome.Valid)
        {
            return outcome;
        }

        return authIdHistory.TryRegister(authId)
            ? VmessAuthIdMatchOutcome.Valid
            : VmessAuthIdMatchOutcome.Replay;
    }

    public static Exception CreateException(VmessAuthIdMatchOutcome outcome)
        => outcome switch
        {
            VmessAuthIdMatchOutcome.NegativeTime => new InvalidDataException("timestamp is negative"),
            VmessAuthIdMatchOutcome.InvalidTime => new InvalidDataException("invalid timestamp, perhaps unsynchronized time"),
            VmessAuthIdMatchOutcome.Replay => new InvalidDataException("replayed request"),
            _ => new InvalidDataException("user do not exist")
        };

    private static byte[] DecryptAuthId(ReadOnlySpan<byte> authId, ReadOnlySpan<byte> authIdKey)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = authIdKey.ToArray();
        using var decryptor = aes.CreateDecryptor();

        var decrypted = new byte[16];
        var input = authId.ToArray();
        var written = decryptor.TransformBlock(input, 0, input.Length, decrypted, 0);
        if (written != decrypted.Length)
        {
            throw new InvalidDataException("VMess auth id decryption failed.");
        }

        return decrypted;
    }

    private static VmessAuthIdMatchOutcome ValidateAuthId(ReadOnlySpan<byte> decryptedAuthId)
    {
        if (decryptedAuthId.Length != 16)
        {
            return VmessAuthIdMatchOutcome.InvalidChecksum;
        }

        var timestamp = BinaryPrimitives.ReadInt64BigEndian(decryptedAuthId[..8]);
        if (timestamp < 0)
        {
            return VmessAuthIdMatchOutcome.NegativeTime;
        }

        var checksum = BinaryPrimitives.ReadUInt32BigEndian(decryptedAuthId.Slice(12, 4));
        if (checksum != ComputeCrc32(decryptedAuthId[..12]))
        {
            return VmessAuthIdMatchOutcome.InvalidChecksum;
        }

        var delta = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp);
        return delta <= AuthIdToleranceSeconds
            ? VmessAuthIdMatchOutcome.Valid
            : VmessAuthIdMatchOutcome.InvalidTime;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0
                    ? (crc >> 1) ^ 0xEDB88320u
                    : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }
}

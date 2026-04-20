using System.Security.Cryptography;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeTls13KeyScheduleTests
{
    [Fact]
    public void Create_uses_hash_length_zero_secret_for_absent_inputs()
    {
        var cipherSuite = RuntimeTls13CipherSuite.Resolve(0x1301);
        var handshakeSharedSecret = Enumerable
            .Range(1, cipherSuite.HashLength)
            .Select(static value => (byte)value)
            .ToArray();
        var transcriptHash = Enumerable
            .Range(65, cipherSuite.HashLength)
            .Select(static value => (byte)value)
            .ToArray();

        var schedule = RuntimeTls13KeySchedule.Create(
            cipherSuite,
            handshakeSharedSecret,
            transcriptHash);

        var expected = CreateExpectedSchedule(
            cipherSuite,
            handshakeSharedSecret,
            transcriptHash,
            useHashLengthZeroSecret: true);
        var legacy = CreateExpectedSchedule(
            cipherSuite,
            handshakeSharedSecret,
            transcriptHash,
            useHashLengthZeroSecret: false);

        Assert.Equal(expected.ClientHandshakeTrafficSecret, schedule.ClientHandshakeTrafficSecret);
        Assert.Equal(expected.ServerHandshakeTrafficSecret, schedule.ServerHandshakeTrafficSecret);
        Assert.Equal(expected.MasterSecret, schedule.MasterSecret);

        Assert.NotEqual(
            Convert.ToHexString(legacy.ClientHandshakeTrafficSecret),
            Convert.ToHexString(schedule.ClientHandshakeTrafficSecret));
        Assert.NotEqual(
            Convert.ToHexString(legacy.ServerHandshakeTrafficSecret),
            Convert.ToHexString(schedule.ServerHandshakeTrafficSecret));
        Assert.NotEqual(
            Convert.ToHexString(legacy.MasterSecret),
            Convert.ToHexString(schedule.MasterSecret));
    }

    private static ExpectedKeySchedule CreateExpectedSchedule(
        RuntimeTls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> handshakeSharedSecret,
        ReadOnlySpan<byte> transcriptHash,
        bool useHashLengthZeroSecret)
    {
        Assert.Equal(nameof(HashAlgorithmName.SHA256), cipherSuite.HashAlgorithm.Name);

        var absentSecret = useHashLengthZeroSecret
            ? new byte[cipherSuite.HashLength]
            : Array.Empty<byte>();
        var emptyHash = SHA256.HashData(Array.Empty<byte>());

        var earlySecret = HMACSHA256.HashData(
            new byte[cipherSuite.HashLength],
            absentSecret);
        var derivedEarly = RuntimeHkdf.ExpandLabelSha256(
            earlySecret,
            "derived",
            emptyHash,
            cipherSuite.HashLength);
        var handshakeSecret = HMACSHA256.HashData(
            derivedEarly,
            handshakeSharedSecret.ToArray());
        var clientHandshakeTrafficSecret = RuntimeHkdf.ExpandLabelSha256(
            handshakeSecret,
            "c hs traffic",
            transcriptHash,
            cipherSuite.HashLength);
        var serverHandshakeTrafficSecret = RuntimeHkdf.ExpandLabelSha256(
            handshakeSecret,
            "s hs traffic",
            transcriptHash,
            cipherSuite.HashLength);
        var derivedHandshake = RuntimeHkdf.ExpandLabelSha256(
            handshakeSecret,
            "derived",
            emptyHash,
            cipherSuite.HashLength);
        var masterSecret = HMACSHA256.HashData(
            derivedHandshake,
            absentSecret);

        return new ExpectedKeySchedule(
            clientHandshakeTrafficSecret,
            serverHandshakeTrafficSecret,
            masterSecret);
    }

    private sealed record ExpectedKeySchedule(
        byte[] ClientHandshakeTrafficSecret,
        byte[] ServerHandshakeTrafficSecret,
        byte[] MasterSecret);
}

using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VmessHandshakeDrainer
{
    private const int DrainFoundationBytes = 16 + 38;
    private const int MaxBaseDrainBytes = 3266;
    private const int MaxRandomDrainBytes = 64;

    private static readonly byte[] BehaviorSeedKey = Encoding.ASCII.GetBytes("VMESSBSKDF");

    private int _remainingBytes;

    private VmessHandshakeDrainer(int remainingBytes)
    {
        _remainingBytes = remainingBytes;
    }

    public static VmessHandshakeDrainer Create(ulong behaviorSeed)
        => Create(behaviorSeed, static randomDrainMax => GoMathRandom.PackageLevelRoll(randomDrainMax));

    internal static VmessHandshakeDrainer Create(ulong behaviorSeed, Func<int, int> packageLevelRoll)
    {
        ArgumentNullException.ThrowIfNull(packageLevelRoll);

        var (baseDrainBytes, randomDrainMax) = DeriveDeterministicDrainParameters(behaviorSeed);
        var randomDrainBytes = packageLevelRoll(randomDrainMax);
        return new VmessHandshakeDrainer(DrainFoundationBytes + baseDrainBytes + randomDrainBytes);
    }

    public void AcknowledgeReceive(int bytesRead)
    {
        if (bytesRead <= 0)
        {
            return;
        }

        _remainingBytes = Math.Max(0, _remainingBytes - bytesRead);
    }

    public async ValueTask<bool> DrainAsync(Stream stream, CancellationToken cancellationToken)
    {
        if (_remainingBytes <= 0)
        {
            return true;
        }

        var buffer = new byte[Math.Min(4096, _remainingBytes)];
        while (_remainingBytes > 0)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, _remainingBytes)),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            _remainingBytes -= read;
        }

        return true;
    }

    internal static (int BaseDrainBytes, int RandomDrainMax) DeriveDeterministicDrainParameters(ulong behaviorSeed)
    {
        var deterministicRandom = new GoMathRandom(unchecked((long)behaviorSeed));
        var baseDrainBytes = deterministicRandom.NextInt(MaxBaseDrainBytes);
        var randomDrainMax = deterministicRandom.NextInt(MaxRandomDrainBytes) + 1;
        return (baseDrainBytes, randomDrainMax);
    }

    internal static ulong ComputeBehaviorSeed(IReadOnlyList<VmessUser> users, ulong fallbackSeed)
        => TryComputeBehaviorSeed(users, out var behaviorSeed)
            ? behaviorSeed
            : fallbackSeed;

    internal static bool TryComputeBehaviorSeed(IReadOnlyList<VmessUser> users, out ulong behaviorSeed)
    {
        behaviorSeed = 0;
        var hasSeedInput = false;
        Span<byte> userBytes = stackalloc byte[16];

        for (var index = 0; index < users.Count; index++)
        {
            if (!ProtocolUuid.TryWriteBytes(users[index].Uuid, userBytes))
            {
                continue;
            }

            hasSeedInput = true;
            var hash = HMACSHA256.HashData(BehaviorSeedKey, userBytes);
            behaviorSeed = Crc64Ecma.Update(behaviorSeed, hash);
        }

        return hasSeedInput && behaviorSeed != 0;
    }

    private static class Crc64Ecma
    {
        private const ulong Polynomial = 0x42F0E1EBA9EA3693;
        private static readonly ulong[] Table = BuildTable();

        public static ulong Update(ulong current, ReadOnlySpan<byte> data)
        {
            var crc = current;
            foreach (var value in data)
            {
                var tableIndex = ((crc >> 56) ^ value) & 0xFF;
                crc = Table[tableIndex] ^ (crc << 8);
            }

            return crc;
        }

        private static ulong[] BuildTable()
        {
            var table = new ulong[256];
            for (var index = 0; index < table.Length; index++)
            {
                var crc = (ulong)index << 56;
                for (var bit = 0; bit < 8; bit++)
                {
                    crc = (crc & 0x8000000000000000UL) != 0
                        ? (crc << 1) ^ Polynomial
                        : crc << 1;
                }

                table[index] = crc;
            }

            return table;
        }
    }
}

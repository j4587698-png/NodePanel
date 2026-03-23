using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VmessBehaviorSeedRegistry
{
    private readonly Lock _sync = new();
    private readonly Dictionary<string, ulong> _entries = new(StringComparer.Ordinal);
    private readonly Func<ulong> _fallbackSeedFactory;

    public VmessBehaviorSeedRegistry()
        : this(static () => GoMathRandom.PackageLevelNextUInt64())
    {
    }

    internal VmessBehaviorSeedRegistry(Func<ulong> fallbackSeedFactory)
    {
        _fallbackSeedFactory = fallbackSeedFactory ?? throw new ArgumentNullException(nameof(fallbackSeedFactory));
    }

    public ulong GetOrCreate(string? key, IReadOnlyList<VmessUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        if (string.IsNullOrWhiteSpace(key))
        {
            return VmessHandshakeDrainer.TryComputeBehaviorSeed(users, out var deterministicSeed)
                ? deterministicSeed
                : _fallbackSeedFactory();
        }

        lock (_sync)
        {
            if (_entries.TryGetValue(key, out var behaviorSeed))
            {
                return behaviorSeed;
            }

            behaviorSeed = VmessHandshakeDrainer.TryComputeBehaviorSeed(users, out var deterministicSeed)
                ? deterministicSeed
                : _fallbackSeedFactory();
            _entries[key] = behaviorSeed;
            return behaviorSeed;
        }
    }
}

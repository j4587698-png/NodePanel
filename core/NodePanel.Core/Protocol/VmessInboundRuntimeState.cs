using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VmessInboundRuntimeState
{
    private readonly Lock _sync = new();
    private readonly Func<ulong> _fallbackBehaviorSeedFactory;
    private readonly IReadOnlyList<VmessUser> _users;

    private ulong _behaviorSeed;
    private bool _behaviorSeedFrozen;

    public VmessInboundRuntimeState(IReadOnlyList<VmessUser> users)
        : this(
            users,
            static () => GoMathRandom.PackageLevelNextUInt64(),
            new VmessSessionHistory(),
            new VmessAuthIdHistory())
    {
    }

    internal VmessInboundRuntimeState(
        IReadOnlyList<VmessUser> users,
        Func<ulong> fallbackBehaviorSeedFactory,
        VmessSessionHistory sessionHistory,
        VmessAuthIdHistory authIdHistory)
    {
        ArgumentNullException.ThrowIfNull(users);

        _users = users.ToArray();
        _fallbackBehaviorSeedFactory = fallbackBehaviorSeedFactory ?? throw new ArgumentNullException(nameof(fallbackBehaviorSeedFactory));
        SessionHistory = sessionHistory ?? throw new ArgumentNullException(nameof(sessionHistory));
        AuthIdHistory = authIdHistory ?? throw new ArgumentNullException(nameof(authIdHistory));
    }

    public VmessSessionHistory SessionHistory { get; }

    public VmessAuthIdHistory AuthIdHistory { get; }

    public ulong BehaviorSeed
    {
        get
        {
            lock (_sync)
            {
                if (_behaviorSeedFrozen)
                {
                    return _behaviorSeed;
                }

                _behaviorSeed = VmessHandshakeDrainer.TryComputeBehaviorSeed(_users, out var deterministicSeed)
                    ? deterministicSeed
                    : _fallbackBehaviorSeedFactory();
                _behaviorSeedFrozen = true;
                return _behaviorSeed;
            }
        }
    }
}

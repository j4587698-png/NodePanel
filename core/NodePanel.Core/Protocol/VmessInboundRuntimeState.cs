using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VmessInboundRuntimeState
{
    private readonly Lock _sync = new();
    private VmessTimedUserValidator _userValidator;

    public VmessInboundRuntimeState(IReadOnlyList<VmessUser> users)
        : this(
            users,
            static () => GoMathRandom.PackageLevelNextUInt64(),
            new VmessSessionHistory())
    {
    }

    internal VmessInboundRuntimeState(
        IReadOnlyList<VmessUser> users,
        Func<ulong> fallbackBehaviorSeedFactory,
        VmessSessionHistory sessionHistory)
    {
        ArgumentNullException.ThrowIfNull(users);

        _userValidator = new VmessTimedUserValidator(
            users,
            new VmessAuthIdHistory(),
            fallbackBehaviorSeedFactory ?? throw new ArgumentNullException(nameof(fallbackBehaviorSeedFactory)));
        SessionHistory = sessionHistory ?? throw new ArgumentNullException(nameof(sessionHistory));
    }

    public VmessSessionHistory SessionHistory { get; }

    internal void BindUserValidator(VmessTimedUserValidator userValidator)
    {
        ArgumentNullException.ThrowIfNull(userValidator);

        lock (_sync)
        {
            _userValidator = userValidator;
        }
    }

    internal bool TryResolveUser(
        ReadOnlySpan<byte> authId,
        out VmessUser? user,
        out Exception? error)
    {
        _ = Volatile.Read(ref _userValidator).TryMatchUser(authId, out user, out error);
        return true;
    }

    public ulong BehaviorSeed => Volatile.Read(ref _userValidator).BehaviorSeed;
}

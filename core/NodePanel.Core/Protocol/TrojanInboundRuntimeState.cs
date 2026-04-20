using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class TrojanInboundRuntimeState
{
    private readonly Lock _sync = new();
    private TrojanUserValidator _userValidator;

    public TrojanInboundRuntimeState(IReadOnlyList<TrojanUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        _userValidator = new TrojanUserValidator(users);
    }

    internal void BindUserValidator(TrojanUserValidator userValidator)
    {
        ArgumentNullException.ThrowIfNull(userValidator);

        lock (_sync)
        {
            _userValidator = userValidator;
        }
    }

    internal bool TryAuthenticate(string passwordHash, out TrojanUser? user)
        => Volatile.Read(ref _userValidator).TryAuthenticate(passwordHash, out user);
}

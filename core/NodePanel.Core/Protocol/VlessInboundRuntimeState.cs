using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VlessInboundRuntimeState
{
    private readonly Lock _sync = new();
    private VlessUserValidator _userValidator;

    public VlessInboundRuntimeState(IReadOnlyList<VlessUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        _userValidator = new VlessUserValidator(users);
    }

    internal void BindUserValidator(VlessUserValidator userValidator)
    {
        ArgumentNullException.ThrowIfNull(userValidator);

        lock (_sync)
        {
            _userValidator = userValidator;
        }
    }

    internal bool TryResolveUser(string uuid, out VlessUser? user)
        => Volatile.Read(ref _userValidator).TryResolveUser(uuid, out user);
}

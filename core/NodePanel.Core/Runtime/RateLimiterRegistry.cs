using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public sealed class RateLimiterRegistry
{
    private readonly ConcurrentDictionary<string, ByteRateGate> _userGates = new(StringComparer.Ordinal);

    public RateLimiterRegistry()
    {
        GlobalGate = new ByteRateGate(0);
    }

    public ByteRateGate GlobalGate { get; }

    public void Apply(ITrojanInboundLimits limits, IReadOnlyList<IRuntimeUserDefinition> users)
        => Apply(limits.GlobalBytesPerSecond, users);

    public void Apply(long globalBytesPerSecond, IReadOnlyList<IRuntimeUserDefinition> users)
    {
        GlobalGate.UpdateRate(Math.Max(0, globalBytesPerSecond));

        var activeIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var user in users)
        {
            if (string.IsNullOrWhiteSpace(user.UserId))
            {
                continue;
            }

            activeIds.Add(user.UserId);
            var gate = _userGates.GetOrAdd(user.UserId, _ => new ByteRateGate(Math.Max(0, user.BytesPerSecond)));
            gate.UpdateRate(Math.Max(0, user.BytesPerSecond));
        }

        foreach (var key in _userGates.Keys)
        {
            if (!activeIds.Contains(key))
            {
                _userGates.TryRemove(key, out _);
            }
        }
    }

    public ByteRateGate GetUserGate(IRuntimeUserDefinition user)
        => _userGates.GetOrAdd(user.UserId, _ => new ByteRateGate(user.BytesPerSecond));
}

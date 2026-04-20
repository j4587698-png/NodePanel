using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public interface IRuntimeRateLimiterRegistry
{
    ByteRateGate GlobalGate { get; }

    void Apply(IRuntimeInboundLimits limits, IReadOnlyList<IRuntimeUserDefinition> users);

    void Apply(long globalBytesPerSecond, IReadOnlyList<IRuntimeUserDefinition> users);

    ByteRateGate GetUserGate(IRuntimeUserDefinition user);

    ByteRateGate GetUserGate(string scopedUserId);
}

public sealed class RateLimiterRegistry : IRuntimeRateLimiterRegistry
{
    private readonly ConcurrentDictionary<string, ByteRateGate> _userGates = new(StringComparer.Ordinal);

    public RateLimiterRegistry()
    {
        GlobalGate = new ByteRateGate(0);
    }

    public ByteRateGate GlobalGate { get; }

    public void Apply(IRuntimeInboundLimits limits, IReadOnlyList<IRuntimeUserDefinition> users)
        => Apply(limits.GlobalBytesPerSecond, users);

    public void Apply(long globalBytesPerSecond, IReadOnlyList<IRuntimeUserDefinition> users)
    {
        GlobalGate.UpdateRate(Math.Max(0, globalBytesPerSecond));

        var activeIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var user in users)
        {
            var runtimeKey = RuntimeUserKeys.Get(user);
            if (runtimeKey.Length == 0)
            {
                continue;
            }

            activeIds.Add(runtimeKey);
            var gate = _userGates.GetOrAdd(runtimeKey, _ => new ByteRateGate(Math.Max(0, user.BytesPerSecond)));
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
    {
        ArgumentNullException.ThrowIfNull(user);

        var runtimeKey = RuntimeUserKeys.Get(user);
        var gate = _userGates.GetOrAdd(runtimeKey, _ => new ByteRateGate(Math.Max(0, user.BytesPerSecond)));
        gate.UpdateRate(Math.Max(0, user.BytesPerSecond));
        return gate;
    }

    public ByteRateGate GetUserGate(string scopedUserId)
    {
        var runtimeKey = NormalizeRuntimeKey(scopedUserId);
        if (runtimeKey.Length == 0)
        {
            return new ByteRateGate(0);
        }

        return _userGates.GetOrAdd(runtimeKey, _ => new ByteRateGate(0));
    }

    private static string NormalizeRuntimeKey(string? scopedUserId)
        => string.IsNullOrWhiteSpace(scopedUserId)
            ? string.Empty
            : scopedUserId.Trim();
}

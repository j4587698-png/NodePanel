namespace NodePanel.Core.Runtime;

public sealed record RuntimeSessionPolicyTimeouts
{
    public int HandshakeSeconds { get; init; } = 60;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public sealed record RuntimeSessionPolicy
{
    public RuntimeSessionPolicyTimeouts Timeout { get; init; } = new();
}

public sealed record RuntimeSessionPolicyCatalog
{
    public static RuntimeSessionPolicyCatalog Default { get; } = new();

    public RuntimeSessionPolicy DefaultPolicy { get; init; } = new();

    public IReadOnlyDictionary<int, RuntimeSessionPolicy> Levels { get; init; }
        = new Dictionary<int, RuntimeSessionPolicy>();

    public RuntimeSessionPolicy ForLevel(int level)
    {
        var normalizedLevel = Math.Max(0, level);
        return Levels.TryGetValue(normalizedLevel, out var policy)
            ? policy
            : DefaultPolicy;
    }
}

internal readonly record struct RuntimeInboundSessionLimits(
    int HandshakeTimeoutSeconds,
    int ConnectTimeoutSeconds,
    int ConnectionIdleSeconds,
    int UplinkOnlySeconds,
    int DownlinkOnlySeconds);

internal static class RuntimeInboundSessionLimitResolver
{
    public static RuntimeInboundSessionLimits Resolve(
        IRuntimeInboundLimits inboundLimits,
        RuntimeSessionPolicyCatalog sessionPolicies,
        int userLevel)
    {
        ArgumentNullException.ThrowIfNull(inboundLimits);
        ArgumentNullException.ThrowIfNull(sessionPolicies);

        var timeouts = sessionPolicies.ForLevel(userLevel).Timeout;
        return new RuntimeInboundSessionLimits(
            HandshakeTimeoutSeconds: Math.Max(1, timeouts.HandshakeSeconds),
            ConnectTimeoutSeconds: Math.Max(1, inboundLimits.ConnectTimeoutSeconds),
            ConnectionIdleSeconds: Math.Max(1, timeouts.ConnectionIdleSeconds),
            UplinkOnlySeconds: Math.Max(1, timeouts.UplinkOnlySeconds),
            DownlinkOnlySeconds: Math.Max(1, timeouts.DownlinkOnlySeconds));
    }

    public static RuntimeInboundSessionLimits Resolve(
        IRuntimeInboundConnectionOptions options,
        RuntimeSessionPolicyCatalog sessionPolicies,
        int userLevel)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(sessionPolicies);

        var timeouts = sessionPolicies.ForLevel(userLevel).Timeout;
        return new RuntimeInboundSessionLimits(
            HandshakeTimeoutSeconds: Math.Max(1, timeouts.HandshakeSeconds),
            ConnectTimeoutSeconds: Math.Max(1, options.ConnectTimeoutSeconds),
            ConnectionIdleSeconds: Math.Max(1, timeouts.ConnectionIdleSeconds),
            UplinkOnlySeconds: Math.Max(1, timeouts.UplinkOnlySeconds),
            DownlinkOnlySeconds: Math.Max(1, timeouts.DownlinkOnlySeconds));
    }
}

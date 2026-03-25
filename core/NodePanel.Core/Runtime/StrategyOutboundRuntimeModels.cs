namespace NodePanel.Core.Runtime;

public interface IStrategyOutboundDefinition
{
    IReadOnlyList<string> CandidateTags { get; }

    string SelectedTag { get; }

    string ProbeUrl { get; }

    int ProbeIntervalSeconds { get; }

    int ProbeTimeoutSeconds { get; }

    int ToleranceMilliseconds { get; }
}

public sealed record StrategyOutboundSettings
{
    public required string Tag { get; init; }

    public required string Protocol { get; init; }

    public IReadOnlyList<string> CandidateTags { get; init; } = Array.Empty<string>();

    public string SelectedTag { get; init; } = string.Empty;

    public string ProbeUrl { get; init; } = StrategyOutboundDefaults.ProbeUrl;

    public int ProbeIntervalSeconds { get; init; } = StrategyOutboundDefaults.ProbeIntervalSeconds;

    public int ProbeTimeoutSeconds { get; init; } = StrategyOutboundDefaults.ProbeTimeoutSeconds;

    public int ToleranceMilliseconds { get; init; } = StrategyOutboundDefaults.ToleranceMilliseconds;
}

public interface IStrategyOutboundSettingsProvider
{
    bool TryResolve(DispatchContext context, out StrategyOutboundSettings settings);
}

public sealed record StrategyCandidateProbeResult
{
    public required string Tag { get; init; }

    public bool Success { get; init; }

    public long LatencyMilliseconds { get; init; } = long.MaxValue;

    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.UtcNow;
}

public interface IStrategyOutboundProbeService
{
    ValueTask<IReadOnlyList<StrategyCandidateProbeResult>> ProbeAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken);
}

public static class StrategyOutboundDefaults
{
    public const string ProbeUrl = "http://cp.cloudflare.com/generate_204";

    public const int ProbeIntervalSeconds = 300;

    public const int ProbeTimeoutSeconds = 5;

    public const int ToleranceMilliseconds = 150;
}

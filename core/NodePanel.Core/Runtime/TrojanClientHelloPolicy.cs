namespace NodePanel.Core.Runtime;

public interface ITrojanClientHelloPolicyDefinition
{
    bool Enabled { get; }

    IReadOnlyList<string> AllowedServerNames { get; }

    IReadOnlyList<string> BlockedServerNames { get; }

    IReadOnlyList<string> AllowedApplicationProtocols { get; }

    IReadOnlyList<string> BlockedApplicationProtocols { get; }

    IReadOnlyList<string> AllowedJa3 { get; }

    IReadOnlyList<string> BlockedJa3 { get; }
}

public sealed record TrojanClientHelloPolicyRuntime : ITrojanClientHelloPolicyDefinition
{
    public static TrojanClientHelloPolicyRuntime Disabled { get; } = new();

    public bool Enabled { get; init; }

    public IReadOnlyList<string> AllowedServerNames { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> BlockedServerNames { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> AllowedApplicationProtocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> BlockedApplicationProtocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> AllowedJa3 { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> BlockedJa3 { get; init; } = Array.Empty<string>();
}

public sealed record TrojanClientHelloPolicyDecision
{
    public bool Rejected { get; init; }

    public string Reason { get; init; } = string.Empty;
}

public static class TrojanClientHelloPolicyEvaluator
{
    public static bool ShouldReject(
        ITrojanClientHelloPolicyDefinition policy,
        TrojanTlsClientHelloMetadata? metadata,
        out TrojanClientHelloPolicyDecision decision)
    {
        ArgumentNullException.ThrowIfNull(policy);

        if (!policy.Enabled)
        {
            decision = new TrojanClientHelloPolicyDecision();
            return false;
        }

        if (ContainsJa3(policy.BlockedJa3, metadata))
        {
            decision = new TrojanClientHelloPolicyDecision
            {
                Rejected = true,
                Reason = "ja3-blocked"
            };
            return true;
        }

        if (policy.AllowedJa3.Count > 0 && !ContainsJa3(policy.AllowedJa3, metadata))
        {
            decision = new TrojanClientHelloPolicyDecision
            {
                Rejected = true,
                Reason = "ja3-allow-list-miss"
            };
            return true;
        }

        if (ContainsServerName(policy.BlockedServerNames, metadata?.ServerName))
        {
            decision = new TrojanClientHelloPolicyDecision
            {
                Rejected = true,
                Reason = "server-name-blocked"
            };
            return true;
        }

        if (policy.AllowedServerNames.Count > 0 && !ContainsServerName(policy.AllowedServerNames, metadata?.ServerName))
        {
            decision = new TrojanClientHelloPolicyDecision
            {
                Rejected = true,
                Reason = "server-name-allow-list-miss"
            };
            return true;
        }

        if (ContainsApplicationProtocol(policy.BlockedApplicationProtocols, metadata?.ApplicationProtocols))
        {
            decision = new TrojanClientHelloPolicyDecision
            {
                Rejected = true,
                Reason = "alpn-blocked"
            };
            return true;
        }

        if (policy.AllowedApplicationProtocols.Count > 0 &&
            !ContainsApplicationProtocol(policy.AllowedApplicationProtocols, metadata?.ApplicationProtocols))
        {
            decision = new TrojanClientHelloPolicyDecision
            {
                Rejected = true,
                Reason = "alpn-allow-list-miss"
            };
            return true;
        }

        decision = new TrojanClientHelloPolicyDecision();
        return false;
    }

    private static bool ContainsJa3(IReadOnlyList<string> configuredValues, TrojanTlsClientHelloMetadata? metadata)
    {
        if (configuredValues.Count == 0 || metadata is null)
        {
            return false;
        }

        foreach (var configuredValue in configuredValues)
        {
            var normalized = NormalizeToken(configuredValue);
            if (normalized.Length == 0)
            {
                continue;
            }

            if (string.Equals(normalized, metadata.Ja3Hash, StringComparison.Ordinal) ||
                string.Equals(normalized, metadata.Ja3Text, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsServerName(IReadOnlyList<string> configuredValues, string? serverName)
    {
        var normalizedServerName = NormalizeServerName(serverName);
        if (configuredValues.Count == 0 || normalizedServerName.Length == 0)
        {
            return false;
        }

        foreach (var configuredValue in configuredValues)
        {
            var normalized = NormalizeServerName(configuredValue);
            if (normalized.Length == 0)
            {
                continue;
            }

            if (IsServerNameMatch(normalizedServerName, normalized))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsApplicationProtocol(
        IReadOnlyList<string> configuredValues,
        IReadOnlyList<string>? applicationProtocols)
    {
        if (configuredValues.Count == 0 || applicationProtocols is null || applicationProtocols.Count == 0)
        {
            return false;
        }

        var configured = configuredValues
            .Select(NormalizeToken)
            .Where(static value => value.Length > 0)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var applicationProtocol in applicationProtocols)
        {
            if (configured.Contains(NormalizeToken(applicationProtocol)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsServerNameMatch(string requestedServerName, string configuredServerName)
    {
        if (string.Equals(requestedServerName, configuredServerName, StringComparison.Ordinal))
        {
            return true;
        }

        if (!configuredServerName.StartsWith("*.", StringComparison.Ordinal) || configuredServerName.Length <= 2)
        {
            return false;
        }

        var suffix = configuredServerName[1..];
        if (!requestedServerName.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        var label = requestedServerName[..^suffix.Length];
        return label.Length > 0 && !label.Contains('.', StringComparison.Ordinal);
    }

    private static string NormalizeServerName(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().TrimEnd('.').ToLowerInvariant();

    private static string NormalizeToken(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();
}

namespace NodePanel.Panel.Models;

public static class SubscriptionFormats
{
    public const string Clash = "clash";
    public const string General = "general";
    public const string QuantumultX = "quantumultx";
    public const string RawTrojan = "trojan";
    public const string Shadowrocket = "shadowrocket";
    public const string Stash = "stash";
    public const string Surge = "surge";

    public static bool IsStructured(string format)
        => string.Equals(format, Clash, StringComparison.Ordinal) ||
           string.Equals(format, Stash, StringComparison.Ordinal) ||
           string.Equals(format, Surge, StringComparison.Ordinal) ||
           string.Equals(format, QuantumultX, StringComparison.Ordinal);
}

public static class SubscriptionProfileNames
{
    public const string Minimal = "minimal";
    public const string Region = "region";
    public const string Full = "full";
    public const string NoReject = "no-reject";

    public static string Normalize(string? value)
    {
        var normalized = value?.Trim().ToLowerInvariant();
        return normalized switch
        {
            Minimal => Minimal,
            Region => Region,
            NoReject => NoReject,
            _ => Full
        };
    }
}

public static class SubscriptionSettingKeys
{
    public const string DefaultProfile = "subscription_profile_default";
    public const string TestUrl = "subscription_test_url";
    public const string TestIntervalSeconds = "subscription_test_interval_seconds";
    public const string EnableRejectInGlobalGroup = "subscription_enable_reject_groups";
    public const string CustomGroupsJson = "subscription_custom_groups_json";
    public const string CustomRulesText = "subscription_custom_rules_text";
}

public sealed record SubscriptionRenderSettings
{
    public string DefaultProfile { get; init; } = SubscriptionProfileNames.Full;

    public string TestUrl { get; init; } = "http://www.gstatic.com/generate_204";

    public int TestIntervalSeconds { get; init; } = 300;

    public bool EnableRejectInGlobalGroup { get; init; }

    public IReadOnlyList<SubscriptionCustomGroupDefinition> CustomGroups { get; init; } = Array.Empty<SubscriptionCustomGroupDefinition>();

    public IReadOnlyList<string> CustomRules { get; init; } = Array.Empty<string>();

    public static SubscriptionRenderSettings FromSettings(IReadOnlyDictionary<string, string>? settings)
    {
        var source = settings ?? new Dictionary<string, string>(StringComparer.Ordinal);
        var defaultProfile = SubscriptionProfileNames.Normalize(
            source.GetValueOrDefault(SubscriptionSettingKeys.DefaultProfile));
        var testUrl = NormalizeTestUrl(source.GetValueOrDefault(SubscriptionSettingKeys.TestUrl));
        var interval = int.TryParse(
                source.GetValueOrDefault(SubscriptionSettingKeys.TestIntervalSeconds),
                out var parsedInterval) &&
            parsedInterval is >= 60 and <= 86400
                ? parsedInterval
                : 300;
        var enableReject = bool.TryParse(
                source.GetValueOrDefault(SubscriptionSettingKeys.EnableRejectInGlobalGroup),
                out var parsedReject) &&
            parsedReject;
        var customGroups = SubscriptionCustomGroupDefinition.ParseList(
            source.GetValueOrDefault(SubscriptionSettingKeys.CustomGroupsJson));
        var customRules = ParseRuleLines(source.GetValueOrDefault(SubscriptionSettingKeys.CustomRulesText));

        return new SubscriptionRenderSettings
        {
            DefaultProfile = defaultProfile,
            TestUrl = testUrl,
            TestIntervalSeconds = interval,
            EnableRejectInGlobalGroup = enableReject,
            CustomGroups = customGroups,
            CustomRules = customRules
        };
    }

    private static string NormalizeTestUrl(string? value)
    {
        var candidate = value?.Trim();
        if (!string.IsNullOrWhiteSpace(candidate) &&
            Uri.TryCreate(candidate, UriKind.Absolute, out var parsed) &&
            (string.Equals(parsed.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
             string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            return parsed.ToString();
        }

        return "http://www.gstatic.com/generate_204";
    }

    private static IReadOnlyList<string> ParseRuleLines(string? value)
        => (value ?? string.Empty)
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static line => line.Trim())
            .Where(static line =>
                !string.IsNullOrWhiteSpace(line) &&
                !line.StartsWith('#') &&
                !line.StartsWith("//", StringComparison.Ordinal))
            .ToArray();
}

public sealed record SubscriptionRequestContext
{
    public required string Format { get; init; }

    public required string ProfileName { get; init; }

    public required SubscriptionRenderSettings Settings { get; init; }
}

public sealed record SubscriptionRenderProxy
{
    public required SubscriptionEndpoint Endpoint { get; init; }

    public required string Name { get; init; }

    public required string Protocol { get; init; }

    public string Region { get; init; } = string.Empty;

    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
}

public sealed record SubscriptionProxyGroup
{
    public required string Name { get; init; }

    public required string Type { get; init; }

    public IReadOnlyList<string> Proxies { get; init; } = Array.Empty<string>();

    public string Url { get; init; } = string.Empty;

    public int IntervalSeconds { get; init; }

    public string Strategy { get; init; } = string.Empty;
}

public sealed record SubscriptionRenderPlan
{
    public required SubscriptionRequestContext Request { get; init; }

    public IReadOnlyList<SubscriptionRenderProxy> Proxies { get; init; } = Array.Empty<SubscriptionRenderProxy>();

    public IReadOnlyList<SubscriptionProxyGroup> Groups { get; init; } = Array.Empty<SubscriptionProxyGroup>();

    public IReadOnlyList<string> Rules { get; init; } = Array.Empty<string>();

    public string FinalGroupName { get; init; } = "Proxy";
}

public sealed record SubscriptionCustomGroupDefinition
{
    public string Name { get; init; } = string.Empty;

    public string Type { get; init; } = "select";

    public IReadOnlyList<string> MatchTags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> MatchRegions { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> MatchKeywords { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> IncludeGroups { get; init; } = Array.Empty<string>();

    public bool IncludeAllNodes { get; init; }

    public bool IncludeInProxySelector { get; init; } = true;

    public string Url { get; init; } = string.Empty;

    public int IntervalSeconds { get; init; }

    public string Strategy { get; init; } = string.Empty;

    public static IReadOnlyList<SubscriptionCustomGroupDefinition> ParseList(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<SubscriptionCustomGroupDefinition>();
        }

        try
        {
            var items = System.Text.Json.JsonSerializer.Deserialize<SubscriptionCustomGroupDefinition[]>(
                json,
                new System.Text.Json.JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

            return (items ?? Array.Empty<SubscriptionCustomGroupDefinition>())
                .Select(static item => item.Normalize())
                .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
                .ToArray();
        }
        catch (System.Text.Json.JsonException)
        {
            return Array.Empty<SubscriptionCustomGroupDefinition>();
        }
    }

    public SubscriptionCustomGroupDefinition Normalize()
        => this with
        {
            Name = Name.Trim(),
            Type = NormalizeType(Type),
            MatchTags = NormalizeItems(MatchTags),
            MatchRegions = NormalizeItems(MatchRegions),
            MatchKeywords = NormalizeItems(MatchKeywords),
            IncludeGroups = NormalizeItems(IncludeGroups),
            Url = Url?.Trim() ?? string.Empty,
            IntervalSeconds = IntervalSeconds is >= 60 and <= 86400 ? IntervalSeconds : 300,
            Strategy = string.IsNullOrWhiteSpace(Strategy) ? "round-robin" : Strategy.Trim()
        };

    private static IReadOnlyList<string> NormalizeItems(IReadOnlyList<string>? values)
        => (values ?? Array.Empty<string>())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string NormalizeType(string? value)
    {
        var normalized = value?.Trim().ToLowerInvariant();
        return normalized switch
        {
            "url-test" => "url-test",
            "fallback" => "fallback",
            "load-balance" => "load-balance",
            _ => "select"
        };
    }
}

using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace NodePanel.Core.Runtime;

public static class RoutingProtocols
{
    public const string FakeDns = "fakedns";
    public const string FakeDnsThenOthers = "fakedns+others";
    public const string Http = "http";
    public const string Tls = "tls";
    public const string Quic = "quic";
    public const string BitTorrent = "bittorrent";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();
}

public sealed record OutboundRuntime
{
    public required string Tag { get; init; }

    public required string Protocol { get; init; }

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string TargetStrategy { get; init; } = OutboundTargetStrategies.AsIs;

    public string ProxyOutboundTag { get; init; } = string.Empty;

    public OutboundMultiplexRuntime MultiplexSettings { get; init; } = OutboundMultiplexRuntime.Disabled;

    public IReadOnlyList<string> CandidateTags { get; init; } = Array.Empty<string>();

    public string SelectedTag { get; init; } = string.Empty;

    public string ProbeUrl { get; init; } = StrategyOutboundDefaults.ProbeUrl;

    public int ProbeIntervalSeconds { get; init; } = StrategyOutboundDefaults.ProbeIntervalSeconds;

    public int ProbeTimeoutSeconds { get; init; } = StrategyOutboundDefaults.ProbeTimeoutSeconds;

    public int ToleranceMilliseconds { get; init; } = StrategyOutboundDefaults.ToleranceMilliseconds;
}

public sealed record RoutingRuleRuntime : IRoutingRuleDefinition
{
    private static readonly IReadOnlyDictionary<string, string> EmptyAttributes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static readonly IReadOnlyDictionary<string, Regex> EmptyAttributeRegexes =
        new Dictionary<string, Regex>(StringComparer.OrdinalIgnoreCase);
    private static readonly IReadOnlyList<Regex> EmptyUserRegexes = Array.Empty<Regex>();

    public bool Enabled => true;

    public string RuleTag { get; init; } = string.Empty;

    public IReadOnlyList<string> InboundTags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Protocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Networks { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> UserIds { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Processes { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> SourceCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DestinationCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DestinationPorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> SourcePorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> LocalCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> LocalPorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> VlessRoutes { get; init; } = Array.Empty<string>();

    public IReadOnlyDictionary<string, string> Attributes { get; init; } = EmptyAttributes;

    public IReadOnlyList<RoutingHostMatcher> DomainMatchers { get; init; } = Array.Empty<RoutingHostMatcher>();

    public IReadOnlyList<RoutingCidrMatcher> SourceCidrMatchers { get; init; } = Array.Empty<RoutingCidrMatcher>();

    public IReadOnlyList<RoutingCidrMatcher> DestinationCidrMatchers { get; init; } = Array.Empty<RoutingCidrMatcher>();

    public IReadOnlyList<RoutingPortMatcher> DestinationPortMatchers { get; init; } = Array.Empty<RoutingPortMatcher>();

    public IReadOnlyList<RoutingPortMatcher> SourcePortMatchers { get; init; } = Array.Empty<RoutingPortMatcher>();

    public IReadOnlyList<RoutingCidrMatcher> LocalCidrMatchers { get; init; } = Array.Empty<RoutingCidrMatcher>();

    public IReadOnlyList<RoutingPortMatcher> LocalPortMatchers { get; init; } = Array.Empty<RoutingPortMatcher>();

    public IReadOnlyList<RoutingPortMatcher> VlessRouteMatchers { get; init; } = Array.Empty<RoutingPortMatcher>();

    internal IReadOnlyDictionary<string, Regex> AttributeRegexes { get; init; } = EmptyAttributeRegexes;

    internal IReadOnlyList<Regex> UserRegexes { get; init; } = EmptyUserRegexes;

    internal IReadOnlyList<RoutingProcessMatcher> ProcessMatchers { get; init; } = Array.Empty<RoutingProcessMatcher>();

    public required string OutboundTag { get; init; }

    public bool IsMatch(DispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Matches(InboundTags, context.InboundTag) &&
               MatchesProtocols(Protocols, context) &&
               Matches(Networks, context.Network) &&
               MatchesDestinationAddress(context) &&
               MatchesDestinationPort(context) &&
               MatchesSourceAddress(context) &&
                MatchesSourcePort(context) &&
                MatchesLocalAddress(context) &&
                MatchesLocalPort(context) &&
                MatchesVlessRoute(context) &&
                MatchesUsers(context) &&
                MatchesProcesses(context) &&
                MatchesAttributes(context) &&
                MatchesHost(context);
    }

    private static bool Matches(IReadOnlyList<string> candidates, string value)
    {
        if (candidates.Count == 0)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        for (var index = 0; index < candidates.Count; index++)
        {
            if (string.Equals(candidates[index], value, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesProtocols(IReadOnlyList<string> candidates, DispatchContext context)
    {
        if (candidates.Count == 0)
        {
            return true;
        }

        var detectedProtocol = context.DetectedProtocol;
        var contentProtocol = context.Content.Protocol;
        if (string.IsNullOrWhiteSpace(detectedProtocol) && string.IsNullOrWhiteSpace(contentProtocol))
        {
            return false;
        }

        for (var index = 0; index < candidates.Count; index++)
        {
            var candidate = candidates[index];
            if (candidate.Length == 0)
            {
                continue;
            }

            if ((!string.IsNullOrWhiteSpace(detectedProtocol) &&
                 detectedProtocol.StartsWith(candidate, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrWhiteSpace(contentProtocol) &&
                 contentProtocol.StartsWith(candidate, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesUsers(DispatchContext context)
    {
        if (UserIds.Count == 0 && UserRegexes.Count == 0)
        {
            return true;
        }

        var userIds = GetUserIds(context);
        if (userIds.Count == 0)
        {
            return false;
        }

        for (var index = 0; index < UserIds.Count; index++)
        {
            var candidate = UserIds[index];
            if (IsUserRegexPattern(candidate))
            {
                continue;
            }

            for (var userIndex = 0; userIndex < userIds.Count; userIndex++)
            {
                if (string.Equals(candidate, userIds[userIndex], StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        for (var index = 0; index < UserRegexes.Count; index++)
        {
            for (var userIndex = 0; userIndex < userIds.Count; userIndex++)
            {
                if (UserRegexes[index].IsMatch(userIds[userIndex]))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static IReadOnlyList<string> GetUserIds(DispatchContext context)
    {
        var identities = new List<string>(2);
        if (!string.IsNullOrWhiteSpace(context.UserId))
        {
            identities.Add(context.UserId);
        }

        if (!string.IsNullOrWhiteSpace(context.ScopedUserId) &&
            !identities.Contains(context.ScopedUserId, StringComparer.Ordinal))
        {
            identities.Add(context.ScopedUserId);
        }

        return identities;
    }

    private bool MatchesProcesses(DispatchContext context)
    {
        if (Processes.Count == 0 && ProcessMatchers.Count == 0)
        {
            return true;
        }

        if (ProcessMatchers.Count > 0)
        {
            return ProcessMatchers.Any(matcher => matcher.IsMatch(context));
        }

        foreach (var value in Processes)
        {
            if (RoutingProcessMatcher.TryCreate(value, out var matcher) &&
                matcher.IsMatch(context))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesAttributes(DispatchContext context)
    {
        if (AttributeRegexes.Count == 0)
        {
            return true;
        }

        var attributes = context.Content.Attributes;
        if (attributes.Count == 0)
        {
            return false;
        }

        foreach (var (key, pattern) in AttributeRegexes)
        {
            if (!attributes.TryGetValue(key, out var value) ||
                !pattern.IsMatch(value))
            {
                return false;
            }
        }

        return true;
    }

    private bool MatchesHost(DispatchContext context)
    {
        if (Domains.Count == 0 && DomainMatchers.Count == 0)
        {
            return true;
        }

        var effectiveHost = GetEffectiveHost(context);
        if (string.IsNullOrWhiteSpace(effectiveHost))
        {
            return false;
        }

        if (DomainMatchers.Count > 0)
        {
            return DomainMatchers.Any(matcher => matcher.IsMatch(effectiveHost));
        }

        foreach (var value in Domains)
        {
            if (RoutingHostMatcher.TryCreate(value, out var matcher) &&
                matcher.IsMatch(effectiveHost))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesDestinationAddress(DispatchContext context)
    {
        if (DestinationCidrs.Count == 0 && DestinationCidrMatchers.Count == 0)
        {
            return true;
        }

        return MatchesAddresses(
            GetDestinationAddresses(context),
            DestinationCidrMatchers,
            DestinationCidrs);
    }

    private bool MatchesSourceAddress(DispatchContext context)
    {
        if (SourceCidrs.Count == 0 && SourceCidrMatchers.Count == 0)
        {
            return true;
        }

        return MatchesAddresses(
            GetSourceAddresses(context),
            SourceCidrMatchers,
            SourceCidrs);
    }

    private bool MatchesLocalAddress(DispatchContext context)
    {
        if (LocalCidrs.Count == 0 && LocalCidrMatchers.Count == 0)
        {
            return true;
        }

        return MatchesAddresses(
            GetLocalAddresses(context),
            LocalCidrMatchers,
            LocalCidrs);
    }

    private bool MatchesDestinationPort(DispatchContext context)
    {
        if (DestinationPorts.Count == 0 && DestinationPortMatchers.Count == 0)
        {
            return true;
        }

        var port = GetDestinationPort(context);
        if (port <= 0)
        {
            return false;
        }

        if (DestinationPortMatchers.Count > 0)
        {
            return DestinationPortMatchers.Any(matcher => matcher.IsMatch(port));
        }

        foreach (var value in DestinationPorts)
        {
            if (RoutingPortMatcher.TryCreate(value, out var matcher, out _) &&
                matcher.IsMatch(port))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesSourcePort(DispatchContext context)
    {
        if (SourcePorts.Count == 0 && SourcePortMatchers.Count == 0)
        {
            return true;
        }

        var port = GetSourcePort(context);
        if (port <= 0)
        {
            return false;
        }

        if (SourcePortMatchers.Count > 0)
        {
            return SourcePortMatchers.Any(matcher => matcher.IsMatch(port));
        }

        foreach (var value in SourcePorts)
        {
            if (RoutingPortMatcher.TryCreate(value, out var matcher, out _) &&
                matcher.IsMatch(port))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesLocalPort(DispatchContext context)
    {
        if (LocalPorts.Count == 0 && LocalPortMatchers.Count == 0)
        {
            return true;
        }

        var port = GetLocalPort(context);
        if (port <= 0)
        {
            return false;
        }

        if (LocalPortMatchers.Count > 0)
        {
            return LocalPortMatchers.Any(matcher => matcher.IsMatch(port));
        }

        foreach (var value in LocalPorts)
        {
            if (RoutingPortMatcher.TryCreate(value, out var matcher, out _) &&
                matcher.IsMatch(port))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesVlessRoute(DispatchContext context)
    {
        if (VlessRoutes.Count == 0 && VlessRouteMatchers.Count == 0)
        {
            return true;
        }

        var port = GetVlessRoutePort(context);
        if (port <= 0)
        {
            return false;
        }

        if (VlessRouteMatchers.Count > 0)
        {
            return VlessRouteMatchers.Any(matcher => matcher.IsMatch(port));
        }

        foreach (var value in VlessRoutes)
        {
            if (RoutingPortMatcher.TryCreate(value, out var matcher, out _) &&
                matcher.IsMatch(port))
            {
                return true;
            }
        }

        return false;
    }

    private static string GetEffectiveHost(DispatchContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.RouteTargetHost))
        {
            return NormalizeHostToken(context.RouteTargetHost);
        }

        if (!string.IsNullOrWhiteSpace(context.TargetHost))
        {
            return NormalizeHostToken(context.TargetHost);
        }

        if (!string.IsNullOrWhiteSpace(context.DetectedDomain))
        {
            return NormalizeHostToken(context.DetectedDomain);
        }

        if (!string.IsNullOrWhiteSpace(context.OriginalDestinationHost))
        {
            return NormalizeHostToken(context.OriginalDestinationHost);
        }

        if (!string.IsNullOrWhiteSpace(context.InboundOriginalDestinationHost))
        {
            return NormalizeHostToken(context.InboundOriginalDestinationHost);
        }

        return string.Empty;
    }

    private static bool MatchesAddresses(
        IReadOnlyList<IPAddress> addresses,
        IReadOnlyList<RoutingCidrMatcher> matchers,
        IReadOnlyList<string> values)
    {
        if (addresses.Count == 0)
        {
            return false;
        }

        if (matchers.Count > 0)
        {
            for (var matcherIndex = 0; matcherIndex < matchers.Count; matcherIndex++)
            {
                for (var addressIndex = 0; addressIndex < addresses.Count; addressIndex++)
                {
                    if (matchers[matcherIndex].IsMatch(addresses[addressIndex]))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        foreach (var value in values)
        {
            if (!RoutingCidrMatcher.TryCreate(value, out var matcher, out _))
            {
                continue;
            }

            for (var addressIndex = 0; addressIndex < addresses.Count; addressIndex++)
            {
                if (matcher.IsMatch(addresses[addressIndex]))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static IReadOnlyList<IPAddress> GetSourceAddresses(DispatchContext context)
        => MergeAddresses(
            context.SourceAddresses,
            context.SourceEndPoint is IPEndPoint ipEndPoint ? ipEndPoint.Address : null);

    private static IReadOnlyList<IPAddress> GetDestinationAddresses(DispatchContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.RouteTargetHost))
        {
            return TryParseAddress(context.RouteTargetHost, out var routeTargetAddress)
                ? [routeTargetAddress]
                : Array.Empty<IPAddress>();
        }

        if (!string.IsNullOrWhiteSpace(context.TargetHost))
        {
            return TryParseAddress(context.TargetHost, out var targetAddress)
                ? [targetAddress]
                : Array.Empty<IPAddress>();
        }

        IPAddress? originalDestinationAddress = null;
        IPAddress? inboundOriginalDestinationAddress = null;
        if (TryParseAddress(context.OriginalDestinationHost, out var address))
        {
            originalDestinationAddress = address;
        }

        if (TryParseAddress(context.InboundOriginalDestinationHost, out address))
        {
            inboundOriginalDestinationAddress = address;
        }

        return MergeAddresses(
            context.TargetAddresses,
            originalDestinationAddress,
            inboundOriginalDestinationAddress);
    }

    private static IReadOnlyList<IPAddress> GetLocalAddresses(DispatchContext context)
        => MergeAddresses(
            context.LocalAddresses,
            context.LocalEndPoint is IPEndPoint ipEndPoint ? ipEndPoint.Address : null);

    private static IReadOnlyList<IPAddress> MergeAddresses(
        IReadOnlyList<IPAddress> addresses,
        IPAddress? primaryAddress = null,
        IPAddress? secondaryAddress = null)
    {
        if (addresses.Count == 0 &&
            primaryAddress is null &&
            secondaryAddress is null)
        {
            return Array.Empty<IPAddress>();
        }

        var normalized = new List<IPAddress>(
            addresses.Count +
            (primaryAddress is null ? 0 : 1) +
            (secondaryAddress is null ? 0 : 1));

        for (var index = 0; index < addresses.Count; index++)
        {
            AddNormalizedAddress(normalized, addresses[index]);
        }

        AddNormalizedAddress(normalized, primaryAddress);
        AddNormalizedAddress(normalized, secondaryAddress);
        return normalized.Count == 0 ? Array.Empty<IPAddress>() : normalized;
    }

    private static void AddNormalizedAddress(List<IPAddress> addresses, IPAddress? address)
    {
        if (address is null)
        {
            return;
        }

        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (!addresses.Contains(normalized))
        {
            addresses.Add(normalized);
        }
    }

    private static int GetSourcePort(DispatchContext context)
        => context.SourceEndPoint is IPEndPoint ipEndPoint ? ipEndPoint.Port : 0;

    private static int GetLocalPort(DispatchContext context)
        => context.LocalEndPoint is IPEndPoint ipEndPoint ? ipEndPoint.Port : 0;

    private static int GetVlessRoutePort(DispatchContext context)
        => context.VlessRoutePort;

    private static int GetDestinationPort(DispatchContext context)
    {
        if (context.RouteTargetPort > 0)
        {
            return context.RouteTargetPort;
        }

        if (context.TargetPort > 0)
        {
            return context.TargetPort;
        }

        return context.OriginalDestinationPort > 0
            ? context.OriginalDestinationPort
            : context.InboundOriginalDestinationPort;
    }

    private static bool TryParseAddress(string? value, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim();
        if (normalized.Length > 1 &&
            normalized[0] == '[' &&
            normalized[^1] == ']')
        {
            normalized = normalized[1..^1];
        }

        if (!IPAddress.TryParse(normalized, out var parsed))
        {
            return false;
        }

        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    private static bool IsUserRegexPattern(string value)
        => value.StartsWith("regexp:", StringComparison.Ordinal);

    private static string NormalizeHostToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(normalized, out var address))
        {
            return address.IsIPv4MappedToIPv6
                ? address.MapToIPv4().ToString()
                : address.ToString();
        }

        return normalized;
    }
}

public enum RoutingHostMatchKind
{
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3
}

public enum RoutingProcessMatchKind
{
    Name = 0,
    AbsolutePath = 1,
    Folder = 2,
    CurrentExecutable = 3
}

public sealed record RoutingProcessMatcher
{
    private const string SelfToken = "self/";
    private const string XrayToken = "xray/";

    public required RoutingProcessMatchKind Kind { get; init; }

    public required string Pattern { get; init; }

    public required string NormalizedRule { get; init; }

    public bool IsMatch(DispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Kind switch
        {
            RoutingProcessMatchKind.Name => string.Equals(
                GetEffectiveProcessName(context),
                Pattern,
                StringComparison.Ordinal),
            RoutingProcessMatchKind.AbsolutePath => string.Equals(
                NormalizeProcessPath(context.ProcessPath),
                Pattern,
                StringComparison.Ordinal),
            RoutingProcessMatchKind.Folder => NormalizeProcessPath(context.ProcessPath)
                .StartsWith(Pattern, StringComparison.Ordinal),
            RoutingProcessMatchKind.CurrentExecutable => context.ProcessIsCurrentExecutable,
            _ => false
        };
    }

    public static bool TryCreate(string value, out RoutingProcessMatcher matcher)
    {
        matcher = default!;
        var normalized = NormalizeRuleToken(value);
        if (normalized.Length == 0)
        {
            return false;
        }

        if (string.Equals(normalized, SelfToken, StringComparison.Ordinal) ||
            string.Equals(normalized, XrayToken, StringComparison.Ordinal))
        {
            matcher = new RoutingProcessMatcher
            {
                Kind = RoutingProcessMatchKind.CurrentExecutable,
                Pattern = normalized,
                NormalizedRule = normalized
            };
            return true;
        }

        if (normalized.EndsWith("/", StringComparison.Ordinal))
        {
            matcher = new RoutingProcessMatcher
            {
                Kind = RoutingProcessMatchKind.Folder,
                Pattern = normalized,
                NormalizedRule = normalized
            };
            return true;
        }

        if (normalized.Contains('/', StringComparison.Ordinal))
        {
            matcher = new RoutingProcessMatcher
            {
                Kind = RoutingProcessMatchKind.AbsolutePath,
                Pattern = normalized,
                NormalizedRule = normalized
            };
            return true;
        }

        var processName = NormalizeProcessName(normalized);
        if (processName.Length == 0)
        {
            return false;
        }

        matcher = new RoutingProcessMatcher
        {
            Kind = RoutingProcessMatchKind.Name,
            Pattern = processName,
            NormalizedRule = normalized
        };
        return true;
    }

    public static bool TryNormalizeRule(string value, out string normalizedRule)
    {
        if (TryCreate(value, out var matcher))
        {
            normalizedRule = matcher.NormalizedRule;
            return true;
        }

        normalizedRule = string.Empty;
        return false;
    }

    private static string GetEffectiveProcessName(DispatchContext context)
    {
        var processName = NormalizeProcessName(context.ProcessName);
        if (processName.Length > 0)
        {
            return processName;
        }

        var processPath = NormalizeProcessPath(context.ProcessPath);
        if (processPath.Length == 0)
        {
            return string.Empty;
        }

        var separator = processPath.LastIndexOf('/');
        var fileName = separator >= 0 ? processPath[(separator + 1)..] : processPath;
        return NormalizeProcessName(fileName);
    }

    private static string NormalizeProcessName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        return normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? normalized[..^4]
            : normalized;
    }

    private static string NormalizeProcessPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return value.Trim().Replace('\\', '/');
    }

    private static string NormalizeRuleToken(string? value)
        => NormalizeProcessPath(value);
}

public sealed record RoutingHostMatcher
{
    private const string RegexpPrefix = "regexp:";
    private const string DomainPrefix = "domain:";
    private const string FullPrefix = "full:";
    private const string KeywordPrefix = "keyword:";
    private const string DotlessPrefix = "dotless:";

    public required RoutingHostMatchKind Kind { get; init; }

    public required string Pattern { get; init; }

    private Regex? CompiledRegex { get; init; }

    private string Prefix { get; init; } = string.Empty;

    private string SourcePattern { get; init; } = string.Empty;

    internal string NormalizedRule
        => Prefix.Length == 0 ? SourcePattern : Prefix + SourcePattern;

    public bool IsMatch(string value)
    {
        var normalizedValue = NormalizeHostToken(value);
        if (normalizedValue.Length == 0)
        {
            return false;
        }

        return Kind switch
        {
            RoutingHostMatchKind.Plain => normalizedValue.Contains(Pattern, StringComparison.Ordinal),
            RoutingHostMatchKind.Regex => CompiledRegex is not null && CompiledRegex.IsMatch(normalizedValue),
            RoutingHostMatchKind.Domain => IsDomainMatch(normalizedValue, Pattern),
            RoutingHostMatchKind.Full => string.Equals(Pattern, normalizedValue, StringComparison.Ordinal),
            _ => false
        };
    }

    public static bool TryCreate(string value, out RoutingHostMatcher matcher)
    {
        matcher = default!;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim();
        if (normalized.Length == 0)
        {
            return false;
        }

        if (TryStripPrefix(normalized, RegexpPrefix, out var regexPattern))
        {
            return TryCreateRegex(regexPattern, RegexpPrefix, out matcher);
        }

        if (TryStripPrefix(normalized, DomainPrefix, out var domainPattern))
        {
            return TryCreateLiteral(domainPattern, RoutingHostMatchKind.Domain, DomainPrefix, out matcher);
        }

        if (TryStripPrefix(normalized, FullPrefix, out var fullPattern))
        {
            return TryCreateLiteral(fullPattern, RoutingHostMatchKind.Full, FullPrefix, out matcher);
        }

        if (TryStripPrefix(normalized, KeywordPrefix, out var keywordPattern))
        {
            return TryCreateLiteral(keywordPattern, RoutingHostMatchKind.Plain, KeywordPrefix, out matcher);
        }

        if (TryStripPrefix(normalized, DotlessPrefix, out var dotlessPattern))
        {
            return TryCreateDotless(dotlessPattern, out matcher);
        }

        return TryCreateLiteral(normalized, RoutingHostMatchKind.Plain, string.Empty, out matcher);
    }

    public static bool TryNormalizeRule(string value, out string normalizedRule)
    {
        if (TryCreate(value, out var matcher))
        {
            normalizedRule = matcher.NormalizedRule;
            return true;
        }

        normalizedRule = string.Empty;
        return false;
    }

    private static bool TryCreateLiteral(
        string value,
        RoutingHostMatchKind kind,
        string prefix,
        out RoutingHostMatcher matcher)
    {
        var pattern = NormalizeHostToken(value);
        if (pattern.Length == 0)
        {
            matcher = default!;
            return false;
        }

        matcher = new RoutingHostMatcher
        {
            Kind = kind,
            Pattern = pattern,
            Prefix = prefix,
            SourcePattern = pattern
        };
        return true;
    }

    private static bool TryCreateRegex(string value, string prefix, out RoutingHostMatcher matcher)
    {
        var pattern = value.Trim();
        if (pattern.Length == 0)
        {
            matcher = default!;
            return false;
        }

        try
        {
            matcher = new RoutingHostMatcher
            {
                Kind = RoutingHostMatchKind.Regex,
                Pattern = pattern,
                Prefix = prefix,
                SourcePattern = pattern,
                CompiledRegex = new Regex(pattern, RegexOptions.CultureInvariant)
            };
            return true;
        }
        catch (ArgumentException)
        {
            matcher = default!;
            return false;
        }
    }

    private static bool TryCreateDotless(string value, out RoutingHostMatcher matcher)
    {
        var pattern = value.Trim();
        if (pattern.Contains('.', StringComparison.Ordinal))
        {
            matcher = default!;
            return false;
        }

        var regexPattern = pattern.Length == 0
            ? "^[^.]*$"
            : "^[^.]*" + pattern + "[^.]*$";
        if (!TryCreateRegex(regexPattern, DotlessPrefix, out matcher))
        {
            return false;
        }

        matcher = matcher with
        {
            SourcePattern = pattern
        };
        return true;
    }

    private static bool TryStripPrefix(string value, string prefix, out string pattern)
    {
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            pattern = value[prefix.Length..];
            return true;
        }

        pattern = string.Empty;
        return false;
    }

    private static bool IsDomainMatch(string value, string pattern)
    {
        if (!value.EndsWith(pattern, StringComparison.Ordinal))
        {
            return false;
        }

        return value.Length == pattern.Length ||
               value[value.Length - pattern.Length - 1] == '.';
    }

    private static string NormalizeHostToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(normalized, out var address))
        {
            return address.IsIPv4MappedToIPv6
                ? address.MapToIPv4().ToString()
                : address.ToString();
        }

        return normalized;
    }
}

public sealed record RoutingPortMatcher
{
    public required int Start { get; init; }

    public required int End { get; init; }

    public bool IsMatch(int port)
        => port >= Start && port <= End;

    public static bool TryCreate(string value, out RoutingPortMatcher matcher, out string? error)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
        if (normalized.Length == 0)
        {
            matcher = default!;
            error = "Routing port matcher cannot be empty.";
            return false;
        }

        var separator = normalized.IndexOf('-');
        if (separator < 0)
        {
            if (!TryParsePort(normalized, out var port))
            {
                matcher = default!;
                error = $"Routing port matcher is invalid: {value}.";
                return false;
            }

            matcher = new RoutingPortMatcher
            {
                Start = port,
                End = port
            };
            error = null;
            return true;
        }

        var startText = normalized[..separator].Trim();
        var endText = normalized[(separator + 1)..].Trim();
        if (!TryParsePort(startText, out var start) ||
            !TryParsePort(endText, out var end) ||
            start > end)
        {
            matcher = default!;
            error = $"Routing port matcher is invalid: {value}.";
            return false;
        }

        matcher = new RoutingPortMatcher
        {
            Start = start,
            End = end
        };
        error = null;
        return true;
    }

    private static bool TryParsePort(string value, out int port)
        => int.TryParse(value, out port) && port is > 0 and <= 65535;
}

public sealed record RoutingCidrMatcher
{
    public required IPAddress NetworkAddress { get; init; }

    public required int PrefixLength { get; init; }

    public bool ReverseMatch { get; init; }

    public bool IsMatch(IPAddress address)
    {
        var normalizedAddress = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (normalizedAddress.AddressFamily != NetworkAddress.AddressFamily)
        {
            return false;
        }

        var candidateBytes = normalizedAddress.GetAddressBytes();
        var networkBytes = NetworkAddress.GetAddressBytes();
        var fullBytes = PrefixLength / 8;
        var remainingBits = PrefixLength % 8;
        var isMatch = true;

        for (var index = 0; index < fullBytes; index++)
        {
            if (candidateBytes[index] != networkBytes[index])
            {
                isMatch = false;
                break;
            }
        }

        if (isMatch && remainingBits > 0)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            isMatch = (candidateBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }

        return isMatch != ReverseMatch;
    }

    public static bool TryCreate(string value, out RoutingCidrMatcher matcher, out string? error)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
        if (normalized.Length == 0)
        {
            matcher = default!;
            error = "Routing source CIDR matcher cannot be empty.";
            return false;
        }

        var reverseMatch = false;
        if (normalized.StartsWith("!", StringComparison.Ordinal))
        {
            reverseMatch = true;
            normalized = normalized[1..].Trim();
        }

        if (normalized.Length == 0)
        {
            matcher = default!;
            error = "Routing source CIDR matcher cannot be empty.";
            return false;
        }

        var slashIndex = normalized.IndexOf('/');
        if (slashIndex < 0)
        {
            if (!IPAddress.TryParse(normalized, out var exactAddress))
            {
                matcher = default!;
                error = $"Routing source CIDR matcher is invalid: {value}.";
                return false;
            }

            exactAddress = exactAddress.IsIPv4MappedToIPv6 ? exactAddress.MapToIPv4() : exactAddress;
            matcher = new RoutingCidrMatcher
            {
                NetworkAddress = exactAddress,
                PrefixLength = exactAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128,
                ReverseMatch = reverseMatch
            };
            error = null;
            return true;
        }

        var addressText = normalized[..slashIndex].Trim();
        var prefixText = normalized[(slashIndex + 1)..].Trim();
        if (!IPAddress.TryParse(addressText, out var address) ||
            !int.TryParse(prefixText, out var prefixLength))
        {
            matcher = default!;
            error = $"Routing source CIDR matcher is invalid: {value}.";
            return false;
        }

        address = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            matcher = default!;
            error = $"Routing source CIDR matcher is invalid: {value}.";
            return false;
        }

        matcher = new RoutingCidrMatcher
        {
            NetworkAddress = ApplyNetworkMask(address, prefixLength),
            PrefixLength = prefixLength,
            ReverseMatch = reverseMatch
        };
        error = null;
        return true;
    }

    private static IPAddress ApplyNetworkMask(IPAddress address, int prefixLength)
    {
        var bytes = address.GetAddressBytes();
        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var index = fullBytes + (remainingBits > 0 ? 1 : 0); index < bytes.Length; index++)
        {
            bytes[index] = 0;
        }

        if (remainingBits > 0)
        {
            var mask = (byte)(0xFF << (8 - remainingBits));
            bytes[fullBytes] &= mask;
        }

        return new IPAddress(bytes);
    }
}

public sealed record OutboundRuntimePlan
{
    public static OutboundRuntimePlan Empty { get; } = new();

    public IReadOnlyList<OutboundRuntime> Outbounds { get; init; } = Array.Empty<OutboundRuntime>();

    public IReadOnlyList<RoutingRuleRuntime> RoutingRules { get; init; } = Array.Empty<RoutingRuleRuntime>();

    public string DefaultOutboundTag { get; init; } = string.Empty;

    public OutboundRuntime? GetDefaultOutbound()
        => TryGetOutbound(DefaultOutboundTag, out var outbound) ? outbound : null;

    public bool TryGetOutbound(string? tag, out OutboundRuntime outbound)
    {
        if (!string.IsNullOrWhiteSpace(tag))
        {
            for (var index = 0; index < Outbounds.Count; index++)
            {
                if (string.Equals(Outbounds[index].Tag, tag.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    outbound = Outbounds[index];
                    return true;
                }
            }
        }

        outbound = default!;
        return false;
    }

    public bool TryResolveOutboundTag(DispatchContext context, out string outboundTag)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (TryPickRoute(context, out var route))
        {
            outboundTag = route.OutboundTag;
            return true;
        }

        outboundTag = DefaultOutboundTag;
        return !string.IsNullOrWhiteSpace(outboundTag);
    }

    public bool TryPickRoute(DispatchContext context, out OutboundRouteDecision route)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!string.IsNullOrWhiteSpace(context.OutboundTag))
        {
            route = new OutboundRouteDecision
            {
                OutboundTag = context.OutboundTag.Trim()
            };
            return true;
        }

        var normalizedContext = NormalizeContext(context);
        for (var index = 0; index < RoutingRules.Count; index++)
        {
            if (RoutingRules[index].IsMatch(normalizedContext))
            {
                route = new OutboundRouteDecision
                {
                    OutboundTag = RoutingRules[index].OutboundTag,
                    RuleTag = RoutingRules[index].RuleTag
                };
                return true;
            }
        }

        route = default!;
        return false;
    }

    private static DispatchContext NormalizeContext(DispatchContext context)
        => context with
        {
            InboundTag = NormalizeTag(context.InboundTag),
            DetectedProtocol = RoutingProtocols.Normalize(context.DetectedProtocol),
            Network = RoutingNetworks.Normalize(context.Network),
            UserId = NormalizeTag(context.UserId),
            ScopedUserId = NormalizeTag(context.ScopedUserId),
            DetectedDomain = NormalizeHostToken(context.DetectedDomain),
            OriginalDestinationHost = NormalizeHostToken(context.OriginalDestinationHost),
            TargetHost = NormalizeHostToken(context.TargetHost),
            RouteTargetHost = NormalizeHostToken(context.RouteTargetHost),
            InboundOriginalDestinationHost = NormalizeHostToken(context.InboundOriginalDestinationHost),
            Content = NormalizeContent(context.Content)
        };

    private static string NormalizeTag(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static string NormalizeHostToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(normalized, out var address))
        {
            return address.IsIPv4MappedToIPv6
                ? address.MapToIPv4().ToString()
                : address.ToString();
        }

        return normalized;
    }

    private static DispatchContent NormalizeContent(DispatchContent content)
    {
        if (string.IsNullOrWhiteSpace(content.Protocol) &&
            content.Attributes.Count == 0 &&
            !content.SkipDnsResolve)
        {
            return DispatchContent.Empty;
        }

        var normalizedAttributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in content.Attributes)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            normalizedAttributes[key.Trim()] = value ?? string.Empty;
        }

        return new DispatchContent
        {
            Protocol = string.IsNullOrWhiteSpace(content.Protocol)
                ? string.Empty
                : content.Protocol.Trim().ToLowerInvariant(),
            Attributes = normalizedAttributes,
            SkipDnsResolve = content.SkipDnsResolve
        };
    }
}

public sealed record NodeRuntimePlan
{
    public static NodeRuntimePlan Empty { get; } = new();

    public InboundRuntimePlanCollection Inbounds { get; init; } = InboundRuntimePlanCollection.Empty;

    public OutboundRuntimePlan Outbound { get; init; } = OutboundRuntimePlan.Empty;

    public TrojanInboundRuntimePlan Trojan => Inbounds.GetOrDefault(InboundProtocols.Trojan, TrojanInboundRuntimePlan.Empty);

    public bool TryGetInboundPlan<TPlan>(string protocol, out TPlan plan)
        where TPlan : class, IInboundProtocolRuntimePlan
        => Inbounds.TryGet(protocol, out plan);
}

public interface IOutboundRuntimePlanProvider
{
    OutboundRuntimePlan GetCurrentOutboundPlan();
}

public static class NodeRuntimePlanner
{
    public static NodeRuntimePlan Create(
        IEnumerable<IInboundProtocolRuntimePlan> inboundPlans,
        OutboundRuntimePlan outboundPlan)
    {
        ArgumentNullException.ThrowIfNull(inboundPlans);
        ArgumentNullException.ThrowIfNull(outboundPlan);

        return new NodeRuntimePlan
        {
            Inbounds = InboundRuntimePlanCollection.Create(inboundPlans),
            Outbound = outboundPlan
        };
    }
}

public static class OutboundRuntimePlanner
{
    public static bool TryBuild(
        IReadOnlyList<IOutboundDefinition> outbounds,
        IReadOnlyList<IRoutingRuleDefinition> routingRules,
        IReadOnlyList<string> supportedOutboundProtocols,
        out OutboundRuntimePlan plan,
        out string? error,
        IReadOnlyList<string>? additionalKnownOutboundTags = null)
    {
        ArgumentNullException.ThrowIfNull(outbounds);
        ArgumentNullException.ThrowIfNull(routingRules);
        ArgumentNullException.ThrowIfNull(supportedOutboundProtocols);

        var normalizedOutbounds = NormalizeOutbounds(outbounds, supportedOutboundProtocols, out error);
        if (normalizedOutbounds is null)
        {
            plan = OutboundRuntimePlan.Empty;
            return false;
        }

        if (!TryNormalizeRules(
                routingRules,
                normalizedOutbounds,
                additionalKnownOutboundTags,
                out var normalizedRules,
                out error))
        {
            plan = OutboundRuntimePlan.Empty;
            return false;
        }

        plan = new OutboundRuntimePlan
        {
            Outbounds = normalizedOutbounds,
            RoutingRules = normalizedRules,
            DefaultOutboundTag = normalizedOutbounds[0].Tag
        };
        error = null;
        return true;
    }

    internal static bool TryNormalizeRules(
        IReadOnlyList<IRoutingRuleDefinition> routingRules,
        IReadOnlyList<OutboundRuntime> outbounds,
        out IReadOnlyList<RoutingRuleRuntime> normalizedRules,
        out string? error)
    {
        return TryNormalizeRules(routingRules, outbounds, additionalKnownOutboundTags: null, out normalizedRules, out error);
    }

    internal static bool TryNormalizeRules(
        IReadOnlyList<IRoutingRuleDefinition> routingRules,
        IReadOnlyList<OutboundRuntime> outbounds,
        IReadOnlyList<string>? additionalKnownOutboundTags,
        out IReadOnlyList<RoutingRuleRuntime> normalizedRules,
        out string? error)
    {
        var normalized = NormalizeRules(routingRules, outbounds, additionalKnownOutboundTags, out error);
        if (normalized is null)
        {
            normalizedRules = Array.Empty<RoutingRuleRuntime>();
            return false;
        }

        normalizedRules = normalized;
        return true;
    }

    private static IReadOnlyList<OutboundRuntime>? NormalizeOutbounds(
        IReadOnlyList<IOutboundDefinition> outbounds,
        IReadOnlyList<string> supportedOutboundProtocols,
        out string? error)
    {
        var supported = new HashSet<string>(
            supportedOutboundProtocols
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(OutboundProtocols.Normalize),
            StringComparer.OrdinalIgnoreCase);
        var seenTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalized = new List<OutboundRuntime>(outbounds.Count);

        for (var index = 0; index < outbounds.Count; index++)
        {
            var outbound = outbounds[index];
            if (!outbound.Enabled)
            {
                continue;
            }

            var tag = NormalizeTag(outbound.Tag);
            if (string.IsNullOrWhiteSpace(tag))
            {
                error = "Outbound tag cannot be empty.";
                return null;
            }

            if (!seenTags.Add(tag))
            {
                error = $"Duplicate outbound tag: {tag}.";
                return null;
            }

            var protocol = OutboundProtocols.Normalize(outbound.Protocol);
            if (!supported.Contains(protocol))
            {
                error = $"Unsupported outbound protocol: {protocol}.";
                return null;
            }

            var sender = outbound as IOutboundSenderDefinition;
            var strategy = outbound as IStrategyOutboundDefinition;
            var via = NormalizeTag(sender?.Via);
            var viaCidr = NormalizeCidr(sender?.ViaCidr);
            var targetStrategy = sender is null
                ? OutboundTargetStrategies.AsIs
                : OutboundTargetStrategies.Normalize(sender.TargetStrategy);
            var proxyOutboundTag = NormalizeTag(sender?.ProxyOutboundTag);
            var multiplexSettings = sender is null
                ? OutboundMultiplexRuntime.Disabled
                : NormalizeMultiplexSettings(sender.GetMultiplexSettings());
            var candidateTags = strategy is null
                ? Array.Empty<string>()
                : NormalizeValues(strategy.CandidateTags, NormalizeTag);
            var selectedTag = NormalizeTag(strategy?.SelectedTag);
            var probeUrl = NormalizeProbeUrl(strategy?.ProbeUrl);
            var probeIntervalSeconds = NormalizeProbeIntervalSeconds(strategy?.ProbeIntervalSeconds ?? 0);
            var probeTimeoutSeconds = NormalizeProbeTimeoutSeconds(strategy?.ProbeTimeoutSeconds ?? 0);
            var toleranceMilliseconds = NormalizeToleranceMilliseconds(strategy?.ToleranceMilliseconds ?? 0);

            if (!IsValidVia(via))
            {
                error = $"Unsupported outbound via setting: {via}.";
                return null;
            }

            if (!IsValidViaCidr(viaCidr))
            {
                error = $"Invalid outbound via CIDR prefix: {viaCidr}.";
                return null;
            }

            if (sender is not null && !IsValidTargetStrategy(sender.TargetStrategy))
            {
                error = $"Unsupported outbound target strategy: {sender.TargetStrategy}.";
                return null;
            }

            if (IsStrategyProtocol(protocol) && candidateTags.Count == 0)
            {
                error = $"Strategy outbound '{tag}' requires at least one candidate tag.";
                return null;
            }

            if (selectedTag.Length > 0 && !candidateTags.Contains(selectedTag, StringComparer.OrdinalIgnoreCase))
            {
                error = $"Strategy outbound '{tag}' selected tag '{selectedTag}' is not present in candidate tags.";
                return null;
            }

            normalized.Add(new OutboundRuntime
            {
                Tag = tag,
                Protocol = protocol,
                Via = via,
                ViaCidr = viaCidr,
                TargetStrategy = targetStrategy,
                ProxyOutboundTag = proxyOutboundTag,
                MultiplexSettings = multiplexSettings,
                CandidateTags = candidateTags,
                SelectedTag = selectedTag,
                ProbeUrl = probeUrl,
                ProbeIntervalSeconds = probeIntervalSeconds,
                ProbeTimeoutSeconds = probeTimeoutSeconds,
                ToleranceMilliseconds = toleranceMilliseconds
            });
        }

        if (normalized.Count == 0)
        {
            error = "At least one enabled outbound is required.";
            return null;
        }

        if (!ValidateOutboundDependencyGraph(normalized, out error))
        {
            return null;
        }

        error = null;
        return normalized;
    }

    private static IReadOnlyList<RoutingRuleRuntime>? NormalizeRules(
        IReadOnlyList<IRoutingRuleDefinition> routingRules,
        IReadOnlyList<OutboundRuntime> outbounds,
        IReadOnlyList<string>? additionalKnownOutboundTags,
        out string? error)
    {
        var knownOutboundTags = new HashSet<string>(
            outbounds.Select(static outbound => outbound.Tag),
            StringComparer.OrdinalIgnoreCase);
        if (additionalKnownOutboundTags is not null)
        {
            foreach (var dynamicTag in additionalKnownOutboundTags)
            {
                var normalizedTag = NormalizeTag(dynamicTag);
                if (!string.IsNullOrWhiteSpace(normalizedTag))
                {
                    knownOutboundTags.Add(normalizedTag);
                }
            }
        }

        var normalized = new List<RoutingRuleRuntime>(routingRules.Count);

        for (var index = 0; index < routingRules.Count; index++)
        {
            var rule = routingRules[index];
            if (!rule.Enabled)
            {
                continue;
            }

            var outboundTag = NormalizeTag(rule.OutboundTag);
            if (string.IsNullOrWhiteSpace(outboundTag))
            {
                error = "Routing rule outbound tag cannot be empty.";
                return null;
            }

            if (!knownOutboundTags.Contains(outboundTag))
            {
                error = $"Routing rule references unknown outbound tag: {outboundTag}.";
                return null;
            }

            var userIds = NormalizeUserValues(rule.UserIds);
            var userRegexes = BuildUserRegexes(userIds);
            var processes = NormalizeProcessValues(rule.Processes);
            var processMatchers = BuildProcessMatchers(processes);

            var domainMatchers = BuildHostMatchers(rule.Domains, out error);
            if (error is not null)
            {
                return null;
            }

            var sourceCidrMatchers = BuildCidrMatchers(rule.SourceCidrs, "source", out error);
            if (error is not null)
            {
                return null;
            }

            var destinationCidrMatchers = BuildCidrMatchers(rule.DestinationCidrs, "destination", out error);
            if (error is not null)
            {
                return null;
            }

            var destinationPortMatchers = BuildPortMatchers(rule.DestinationPorts, out error);
            if (error is not null)
            {
                return null;
            }

            var sourcePortMatchers = BuildPortMatchers(rule.SourcePorts, out error);
            if (error is not null)
            {
                return null;
            }

            var localCidrMatchers = BuildCidrMatchers(rule.LocalCidrs, "local", out error);
            if (error is not null)
            {
                return null;
            }

            var localPortMatchers = BuildPortMatchers(rule.LocalPorts, out error);
            if (error is not null)
            {
                return null;
            }

            var vlessRouteMatchers = BuildPortMatchers(rule.VlessRoutes, out error);
            if (error is not null)
            {
                return null;
            }

            var normalizedAttributes = NormalizeAttributeValues(rule.Attributes);
            var attributeRegexes = BuildAttributeRegexes(normalizedAttributes, out error);
            if (error is not null)
            {
                return null;
            }

            var normalizedRule = new RoutingRuleRuntime
            {
                RuleTag = NormalizeRuleTag(rule.RuleTag),
                InboundTags = NormalizeValues(rule.InboundTags, NormalizeTag),
                Protocols = NormalizeValues(rule.Protocols, RoutingProtocols.Normalize),
                Networks = NormalizeValues(rule.Networks, RoutingNetworks.Normalize),
                UserIds = userIds,
                Processes = processes,
                Domains = NormalizeValues(rule.Domains, NormalizeDomainPattern),
                SourceCidrs = NormalizeValues(rule.SourceCidrs, NormalizeTag),
                DestinationCidrs = NormalizeValues(rule.DestinationCidrs, NormalizeTag),
                DestinationPorts = NormalizeValues(rule.DestinationPorts, NormalizeTag),
                SourcePorts = NormalizeValues(rule.SourcePorts, NormalizeTag),
                LocalCidrs = NormalizeValues(rule.LocalCidrs, NormalizeTag),
                LocalPorts = NormalizeValues(rule.LocalPorts, NormalizeTag),
                VlessRoutes = NormalizeValues(rule.VlessRoutes, NormalizeTag),
                Attributes = normalizedAttributes,
                DomainMatchers = domainMatchers,
                SourceCidrMatchers = sourceCidrMatchers,
                DestinationCidrMatchers = destinationCidrMatchers,
                DestinationPortMatchers = destinationPortMatchers,
                SourcePortMatchers = sourcePortMatchers,
                LocalCidrMatchers = localCidrMatchers,
                LocalPortMatchers = localPortMatchers,
                VlessRouteMatchers = vlessRouteMatchers,
                AttributeRegexes = attributeRegexes,
                UserRegexes = userRegexes,
                ProcessMatchers = processMatchers,
                OutboundTag = outboundTag
            };

            if (!HasEffectiveFields(normalizedRule))
            {
                error = $"Routing rule '{outboundTag}' has no effective fields.";
                return null;
            }

            normalized.Add(normalizedRule);
        }

        error = null;
        return normalized;
    }

    private static bool HasEffectiveFields(RoutingRuleRuntime rule)
        => rule.InboundTags.Count > 0 ||
           rule.Protocols.Count > 0 ||
           rule.Networks.Count > 0 ||
           rule.UserIds.Count > 0 ||
           rule.UserRegexes.Count > 0 ||
           rule.Processes.Count > 0 ||
           rule.ProcessMatchers.Count > 0 ||
           rule.Domains.Count > 0 ||
           rule.DomainMatchers.Count > 0 ||
           rule.SourceCidrs.Count > 0 ||
           rule.SourceCidrMatchers.Count > 0 ||
           rule.DestinationCidrs.Count > 0 ||
           rule.DestinationCidrMatchers.Count > 0 ||
           rule.DestinationPorts.Count > 0 ||
           rule.DestinationPortMatchers.Count > 0 ||
           rule.SourcePorts.Count > 0 ||
           rule.SourcePortMatchers.Count > 0 ||
           rule.LocalCidrs.Count > 0 ||
           rule.LocalCidrMatchers.Count > 0 ||
           rule.LocalPorts.Count > 0 ||
           rule.LocalPortMatchers.Count > 0 ||
           rule.VlessRoutes.Count > 0 ||
           rule.VlessRouteMatchers.Count > 0 ||
           rule.AttributeRegexes.Count > 0;

    private static IReadOnlyDictionary<string, string> NormalizeAttributeValues(
        IReadOnlyDictionary<string, string> values)
    {
        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in values)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            normalized[key.Trim()] = value?.Trim() ?? string.Empty;
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeValues(
        IReadOnlyList<string> values,
        Func<string, string> normalize)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalized = new List<string>(values.Count);

        for (var index = 0; index < values.Count; index++)
        {
            var value = normalize(values[index]);
            if (string.IsNullOrWhiteSpace(value) || !seen.Add(value))
            {
                continue;
            }

            normalized.Add(value);
        }

        return normalized;
    }

    private static string NormalizeTag(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static string NormalizeRuleTag(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static IReadOnlyList<string> NormalizeUserValues(IReadOnlyList<string> values)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var normalized = new List<string>(values.Count);

        for (var index = 0; index < values.Count; index++)
        {
            var value = NormalizeTag(values[index]);
            if (value.Length == 0 || !seen.Add(value))
            {
                continue;
            }

            normalized.Add(value);
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeProcessValues(IReadOnlyList<string> values)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var normalized = new List<string>(values.Count);

        for (var index = 0; index < values.Count; index++)
        {
            if (!RoutingProcessMatcher.TryNormalizeRule(values[index], out var value) ||
                value.Length == 0 ||
                !seen.Add(value))
            {
                continue;
            }

            normalized.Add(value);
        }

        return normalized;
    }

    private static string NormalizeDomainPattern(string value)
    {
        if (RoutingHostMatcher.TryNormalizeRule(value, out var normalized))
        {
            return normalized;
        }

        return string.Empty;
    }

    private static string NormalizeCidr(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().TrimStart('/');

    private static string NormalizeHostToken(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (IPAddress.TryParse(normalized, out var address))
        {
            return address.IsIPv4MappedToIPv6
                ? address.MapToIPv4().ToString()
                : address.ToString();
        }

        return normalized;
    }

    private static IReadOnlyList<RoutingHostMatcher> BuildHostMatchers(
        IReadOnlyList<string> values,
        out string? error)
    {
        var matchers = new List<RoutingHostMatcher>(values.Count);
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (!RoutingHostMatcher.TryCreate(value, out var matcher))
            {
                error = $"Routing domain matcher is invalid: {value}.";
                return Array.Empty<RoutingHostMatcher>();
            }

            matchers.Add(matcher);
        }

        error = null;
        return matchers;
    }

    private static IReadOnlyList<Regex> BuildUserRegexes(IReadOnlyList<string> values)
    {
        var matchers = new List<Regex>();
        foreach (var value in values)
        {
            if (!value.StartsWith("regexp:", StringComparison.Ordinal))
            {
                continue;
            }

            var pattern = value["regexp:".Length..];
            try
            {
                matchers.Add(new Regex(pattern, RegexOptions.CultureInvariant));
            }
            catch (ArgumentException)
            {
                // xray-core ignores invalid regexp user items instead of failing the rule.
            }
        }

        return matchers;
    }

    private static IReadOnlyList<RoutingProcessMatcher> BuildProcessMatchers(IReadOnlyList<string> values)
    {
        var matchers = new List<RoutingProcessMatcher>(values.Count);
        foreach (var value in values)
        {
            if (RoutingProcessMatcher.TryCreate(value, out var matcher))
            {
                matchers.Add(matcher);
            }
        }

        return matchers;
    }

    private static IReadOnlyList<RoutingCidrMatcher> BuildCidrMatchers(
        IReadOnlyList<string> values,
        string matcherScope,
        out string? error)
    {
        var matchers = new List<RoutingCidrMatcher>(values.Count);
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (!RoutingCidrMatcher.TryCreate(value, out var matcher, out error))
            {
                error = $"Routing {matcherScope} CIDR matcher is invalid: {value}.";
                return Array.Empty<RoutingCidrMatcher>();
            }

            matchers.Add(matcher);
        }

        error = null;
        return matchers;
    }

    private static IReadOnlyList<RoutingPortMatcher> BuildPortMatchers(
        IReadOnlyList<string> values,
        out string? error)
    {
        var matchers = new List<RoutingPortMatcher>(values.Count);
        foreach (var value in values)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (!RoutingPortMatcher.TryCreate(value, out var matcher, out error))
            {
                return Array.Empty<RoutingPortMatcher>();
            }

            matchers.Add(matcher);
        }

        error = null;
        return matchers;
    }

    private static IReadOnlyDictionary<string, Regex> BuildAttributeRegexes(
        IReadOnlyDictionary<string, string> values,
        out string? error)
    {
        var matchers = new Dictionary<string, Regex>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in values)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var normalizedKey = key.Trim();
            var pattern = value?.Trim() ?? string.Empty;
            try
            {
                matchers[normalizedKey] = new Regex(pattern, RegexOptions.CultureInvariant);
            }
            catch (ArgumentException)
            {
                error = $"Routing attribute matcher is invalid for key '{normalizedKey}'.";
                return new Dictionary<string, Regex>(StringComparer.OrdinalIgnoreCase);
            }
        }

        error = null;
        return matchers;
    }

    private static bool ValidateOutboundDependencyGraph(
        IReadOnlyList<OutboundRuntime> outbounds,
        out string? error)
    {
        var knownTags = outbounds
            .Select(static outbound => outbound.Tag)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var byTag = outbounds.ToDictionary(
            static outbound => outbound.Tag,
            StringComparer.OrdinalIgnoreCase);

        foreach (var outbound in outbounds)
        {
            if (!string.IsNullOrWhiteSpace(outbound.ProxyOutboundTag) &&
                !knownTags.Contains(outbound.ProxyOutboundTag))
            {
                error = $"Outbound '{outbound.Tag}' references unknown proxy outbound tag: {outbound.ProxyOutboundTag}.";
                return false;
            }

            foreach (var candidateTag in outbound.CandidateTags)
            {
                if (!knownTags.Contains(candidateTag))
                {
                    error = $"Outbound '{outbound.Tag}' references unknown candidate outbound tag: {candidateTag}.";
                    return false;
                }
            }
        }

        foreach (var outbound in outbounds)
        {
            if (!HasDependencyCycle(outbound.Tag, byTag, new HashSet<string>(StringComparer.OrdinalIgnoreCase)))
            {
                continue;
            }

            error = $"Outbound dependency graph contains a cycle at tag '{outbound.Tag}'.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool HasDependencyCycle(
        string tag,
        IReadOnlyDictionary<string, OutboundRuntime> byTag,
        ISet<string> stack)
    {
        if (!byTag.TryGetValue(tag, out var outbound))
        {
            return false;
        }

        if (!stack.Add(tag))
        {
            return true;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(outbound.ProxyOutboundTag) &&
                HasDependencyCycle(outbound.ProxyOutboundTag, byTag, stack))
            {
                return true;
            }

            foreach (var candidateTag in outbound.CandidateTags)
            {
                if (HasDependencyCycle(candidateTag, byTag, stack))
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            stack.Remove(tag);
        }
    }

    private static OutboundMultiplexRuntime NormalizeMultiplexSettings(IOutboundMultiplexDefinition definition)
        => new()
        {
            Enabled = definition.Enabled,
            Concurrency = definition.Concurrency,
            XudpConcurrency = definition.XudpConcurrency,
            XudpProxyUdp443 = OutboundXudpProxyModes.Normalize(definition.XudpProxyUdp443)
        };

    private static bool IsValidTargetStrategy(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var normalized = value
            .Trim()
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();

        return normalized is
            "asis" or
            "useip" or
            "useipv4" or
            "useip4" or
            "useipv6" or
            "useip6" or
            "useipv4v6" or
            "useip46" or
            "useipv6v4" or
            "useip64" or
            "forceip" or
            "forceipv4" or
            "forceip4" or
            "forceipv6" or
            "forceip6" or
            "forceipv4v6" or
            "forceip46" or
            "forceipv6v4" or
            "forceip64";
    }

    private static bool IsValidVia(string value)
        => string.IsNullOrWhiteSpace(value) ||
           string.Equals(value, "origin", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(value, "srcip", StringComparison.OrdinalIgnoreCase) ||
           IPAddress.TryParse(value, out _);

    private static bool IsValidViaCidr(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        return int.TryParse(value, out var prefixLength) && prefixLength is >= 0 and <= 128;
    }

    private static bool IsStrategyProtocol(string protocol)
        => protocol is
            OutboundProtocols.Selector or
            OutboundProtocols.UrlTest or
            OutboundProtocols.Fallback or
            OutboundProtocols.LoadBalance;

    private static string NormalizeProbeUrl(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? StrategyOutboundDefaults.ProbeUrl
            : value.Trim();

    private static int NormalizeProbeIntervalSeconds(int value)
        => value > 0 ? value : StrategyOutboundDefaults.ProbeIntervalSeconds;

    private static int NormalizeProbeTimeoutSeconds(int value)
        => value > 0 ? value : StrategyOutboundDefaults.ProbeTimeoutSeconds;

    private static int NormalizeToleranceMilliseconds(int value)
        => value >= 0 ? value : StrategyOutboundDefaults.ToleranceMilliseconds;
}

using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public static class RoutingProtocols
{
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

public sealed record RoutingRuleRuntime
{
    public IReadOnlyList<string> InboundTags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Protocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Networks { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> UserIds { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> SourceCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DestinationPorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<RoutingHostMatcher> DomainMatchers { get; init; } = Array.Empty<RoutingHostMatcher>();

    public IReadOnlyList<RoutingCidrMatcher> SourceCidrMatchers { get; init; } = Array.Empty<RoutingCidrMatcher>();

    public IReadOnlyList<RoutingPortMatcher> DestinationPortMatchers { get; init; } = Array.Empty<RoutingPortMatcher>();

    public required string OutboundTag { get; init; }

    public bool IsMatch(DispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return Matches(InboundTags, context.InboundTag) &&
               Matches(Protocols, context.DetectedProtocol) &&
               Matches(Networks, context.Network) &&
               Matches(UserIds, context.UserId) &&
               MatchesHost(context) &&
               MatchesSource(context) &&
               MatchesDestinationPort(context);
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
            if (string.Equals(candidates[index], value, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
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

    private bool MatchesSource(DispatchContext context)
    {
        if (SourceCidrs.Count == 0 && SourceCidrMatchers.Count == 0)
        {
            return true;
        }

        var sourceAddress = GetSourceAddress(context);
        if (sourceAddress is null)
        {
            return false;
        }

        if (SourceCidrMatchers.Count > 0)
        {
            return SourceCidrMatchers.Any(matcher => matcher.IsMatch(sourceAddress));
        }

        foreach (var value in SourceCidrs)
        {
            if (RoutingCidrMatcher.TryCreate(value, out var matcher, out _) &&
                matcher.IsMatch(sourceAddress))
            {
                return true;
            }
        }

        return false;
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

    private static string GetEffectiveHost(DispatchContext context)
    {
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

    private static IPAddress? GetSourceAddress(DispatchContext context)
    {
        if (context.SourceEndPoint is not IPEndPoint ipEndPoint)
        {
            return null;
        }

        var address = ipEndPoint.Address;
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    private static int GetDestinationPort(DispatchContext context)
        => context.OriginalDestinationPort > 0
            ? context.OriginalDestinationPort
            : context.InboundOriginalDestinationPort;

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

public sealed record RoutingHostMatcher
{
    public required string Pattern { get; init; }

    public bool WildcardSubdomain { get; init; }

    public bool IsMatch(string value)
    {
        var normalizedValue = NormalizeHostToken(value);
        if (normalizedValue.Length == 0)
        {
            return false;
        }

        if (!WildcardSubdomain)
        {
            return string.Equals(Pattern, normalizedValue, StringComparison.Ordinal);
        }

        return normalizedValue.Length > Pattern.Length &&
               normalizedValue.EndsWith("." + Pattern, StringComparison.Ordinal);
    }

    public static bool TryCreate(string value, out RoutingHostMatcher matcher)
    {
        var normalized = NormalizeHostToken(value);
        if (normalized.Length == 0)
        {
            matcher = default!;
            return false;
        }

        if (normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = normalized[2..];
            if (suffix.Length == 0 || suffix.Contains('*', StringComparison.Ordinal))
            {
                matcher = default!;
                return false;
            }

            matcher = new RoutingHostMatcher
            {
                Pattern = suffix,
                WildcardSubdomain = true
            };
            return true;
        }

        if (normalized.Contains('*', StringComparison.Ordinal))
        {
            matcher = default!;
            return false;
        }

        matcher = new RoutingHostMatcher
        {
            Pattern = normalized,
            WildcardSubdomain = false
        };
        return true;
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

        for (var index = 0; index < fullBytes; index++)
        {
            if (candidateBytes[index] != networkBytes[index])
            {
                return false;
            }
        }

        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (candidateBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
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
                PrefixLength = exactAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128
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
            PrefixLength = prefixLength
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

        if (!string.IsNullOrWhiteSpace(context.OutboundTag))
        {
            outboundTag = context.OutboundTag.Trim();
            return true;
        }

        var normalizedContext = NormalizeContext(context);
        for (var index = 0; index < RoutingRules.Count; index++)
        {
            if (RoutingRules[index].IsMatch(normalizedContext))
            {
                outboundTag = RoutingRules[index].OutboundTag;
                return true;
            }
        }

        outboundTag = DefaultOutboundTag;
        return !string.IsNullOrWhiteSpace(outboundTag);
    }

    private static DispatchContext NormalizeContext(DispatchContext context)
        => context with
        {
            InboundTag = NormalizeTag(context.InboundTag),
            DetectedProtocol = RoutingProtocols.Normalize(context.DetectedProtocol),
            Network = RoutingNetworks.Normalize(context.Network),
            UserId = NormalizeTag(context.UserId),
            DetectedDomain = NormalizeHostToken(context.DetectedDomain),
            OriginalDestinationHost = NormalizeHostToken(context.OriginalDestinationHost),
            InboundOriginalDestinationHost = NormalizeHostToken(context.InboundOriginalDestinationHost)
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
        out string? error)
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

        var normalizedRules = NormalizeRules(routingRules, normalizedOutbounds, out error);
        if (normalizedRules is null)
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
        out string? error)
    {
        var knownOutboundTags = new HashSet<string>(
            outbounds.Select(static outbound => outbound.Tag),
            StringComparer.OrdinalIgnoreCase);
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

            var domainMatchers = BuildHostMatchers(rule.Domains, out error);
            if (error is not null)
            {
                return null;
            }

            var sourceCidrMatchers = BuildSourceCidrMatchers(rule.SourceCidrs, out error);
            if (error is not null)
            {
                return null;
            }

            var destinationPortMatchers = BuildPortMatchers(rule.DestinationPorts, out error);
            if (error is not null)
            {
                return null;
            }

            normalized.Add(new RoutingRuleRuntime
            {
                InboundTags = NormalizeValues(rule.InboundTags, NormalizeTag),
                Protocols = NormalizeValues(rule.Protocols, RoutingProtocols.Normalize),
                Networks = NormalizeValues(rule.Networks, RoutingNetworks.Normalize),
                UserIds = NormalizeValues(rule.UserIds, NormalizeTag),
                Domains = NormalizeValues(rule.Domains, NormalizeDomainPattern),
                SourceCidrs = NormalizeValues(rule.SourceCidrs, NormalizeTag),
                DestinationPorts = NormalizeValues(rule.DestinationPorts, NormalizeTag),
                DomainMatchers = domainMatchers,
                SourceCidrMatchers = sourceCidrMatchers,
                DestinationPortMatchers = destinationPortMatchers,
                OutboundTag = outboundTag
            });
        }

        error = null;
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

    private static string NormalizeDomainPattern(string value)
    {
        var normalized = NormalizeHostToken(value);
        if (normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            return "*." + NormalizeHostToken(normalized[2..]);
        }

        return normalized;
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

    private static IReadOnlyList<RoutingCidrMatcher> BuildSourceCidrMatchers(
        IReadOnlyList<string> values,
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

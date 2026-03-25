using System.Text;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public static class SubscriptionFormatRenderer
{
    private static readonly HashSet<string> BuiltinTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "DIRECT",
        "REJECT"
    };

    private static readonly HashSet<string> RuleOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "no-resolve"
    };

    public static RenderedSubscription Render(
        SubscriptionCatalog catalog,
        SubscriptionRenderPlan plan,
        string appName)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(plan);

        return plan.Request.Format switch
        {
            SubscriptionFormats.Clash => RenderClash(catalog, plan, SubscriptionFormats.Clash, appName),
            SubscriptionFormats.Stash => RenderClash(catalog, plan, SubscriptionFormats.Stash, appName),
            SubscriptionFormats.Surge => RenderSurge(catalog, plan, appName),
            SubscriptionFormats.QuantumultX => RenderQuantumultX(catalog, plan, appName),
            _ => throw new InvalidOperationException($"Unsupported structured format '{plan.Request.Format}'.")
        };
    }

    private static RenderedSubscription RenderClash(
        SubscriptionCatalog catalog,
        SubscriptionRenderPlan plan,
        string format,
        string appName)
    {
        var proxyNames = plan.Proxies
            .Select(static proxy => proxy.Name)
            .Distinct(StringComparer.Ordinal)
            .ToHashSet(StringComparer.Ordinal);
        var proxyProviders = BuildProxyProviders(plan, proxyNames);
        var ruleProviders = BuildRuleProviders(plan.Rules);

        var builder = new StringBuilder();
        builder.AppendLine("mixed-port: 7890");
        builder.AppendLine("allow-lan: false");
        builder.AppendLine("mode: rule");
        builder.AppendLine("proxies: []");

        if (proxyProviders.Count > 0)
        {
            builder.AppendLine("proxy-providers:");
            foreach (var provider in proxyProviders.Values)
            {
                AppendClashProxyProvider(builder, catalog.User, provider, plan.Request.Settings);
            }
        }

        builder.AppendLine("proxy-groups:");
        foreach (var group in plan.Groups)
        {
            AppendClashGroup(builder, group, proxyNames, proxyProviders);
        }

        if (ruleProviders.Count > 0)
        {
            builder.AppendLine("rule-providers:");
            foreach (var provider in ruleProviders)
            {
                AppendClashRuleProvider(builder, provider);
            }
        }

        builder.AppendLine("rules:");
        foreach (var rule in BuildClashRuleReferences(plan.Rules, ruleProviders))
        {
            builder.AppendLine($"  - {rule}");
        }

        return new RenderedSubscription
        {
            Format = format,
            Content = builder.ToString(),
            ContentType = "text/yaml",
            FileName = BuildFileName(appName, "yaml")
        };
    }

    private static RenderedSubscription RenderSurge(
        SubscriptionCatalog catalog,
        SubscriptionRenderPlan plan,
        string appName)
    {
        var builder = new StringBuilder();
        builder.AppendLine("[General]");
        builder.AppendLine("loglevel = notify");
        builder.AppendLine("dns-server = system");
        builder.AppendLine("skip-proxy = 127.0.0.1, localhost");
        builder.AppendLine();
        builder.AppendLine("[Proxy]");

        foreach (var proxy in plan.Proxies)
        {
            builder.AppendLine(BuildSurgeProxyLine(catalog.User, proxy));
        }

        builder.AppendLine();
        builder.AppendLine("[Proxy Group]");
        foreach (var group in plan.Groups)
        {
            builder.AppendLine(BuildSurgeGroupLine(group));
        }

        builder.AppendLine();
        builder.AppendLine("[Rule]");
        foreach (var rule in plan.Rules)
        {
            builder.AppendLine(ToSurgeRule(rule));
        }

        return new RenderedSubscription
        {
            Format = SubscriptionFormats.Surge,
            Content = builder.ToString(),
            ContentType = "text/plain",
            FileName = BuildFileName(appName, "conf")
        };
    }

    private static RenderedSubscription RenderQuantumultX(
        SubscriptionCatalog catalog,
        SubscriptionRenderPlan plan,
        string appName)
    {
        var builder = new StringBuilder();
        builder.AppendLine("[general]");
        builder.AppendLine($"server_check_url={plan.Request.Settings.TestUrl}");
        builder.AppendLine("resource_parser_url=");
        builder.AppendLine();
        builder.AppendLine("[server_local]");
        foreach (var proxy in plan.Proxies)
        {
            var line = BuildQuantumultXServerLine(catalog.User, proxy);
            if (!string.IsNullOrWhiteSpace(line))
            {
                builder.AppendLine(line);
            }
        }

        builder.AppendLine();
        builder.AppendLine("[policy]");
        foreach (var group in plan.Groups)
        {
            builder.AppendLine(BuildQuantumultXPolicyLine(group, plan.Request.Settings));
        }

        builder.AppendLine();
        builder.AppendLine("[filter_local]");
        foreach (var rule in plan.Rules)
        {
            var converted = ToQuantumultXRule(rule);
            if (!string.IsNullOrWhiteSpace(converted))
            {
                builder.AppendLine(converted);
            }
        }

        return new RenderedSubscription
        {
            Format = SubscriptionFormats.QuantumultX,
            Content = builder.ToString(),
            ContentType = "text/plain",
            FileName = BuildFileName(appName, "conf")
        };
    }

    private static Dictionary<string, ClashProxyProvider> BuildProxyProviders(
        SubscriptionRenderPlan plan,
        ISet<string> proxyNames)
    {
        var providers = new Dictionary<string, ClashProxyProvider>(StringComparer.Ordinal);
        if (plan.Proxies.Count == 0)
        {
            return providers;
        }

        var allProviderId = "all-nodes";
        providers[allProviderId] = new ClashProxyProvider
        {
            Id = allProviderId,
            Proxies = plan.Proxies
        };

        foreach (var group in plan.Groups)
        {
            var actualProxies = group.Proxies
                .Where(proxyNames.Contains)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (actualProxies.Length == 0)
            {
                continue;
            }

            var useAllNodes = actualProxies.Length == proxyNames.Count && actualProxies.All(proxyNames.Contains);
            if (useAllNodes)
            {
                continue;
            }

            var providerId = $"group-{SanitizeIdentifier(group.Name)}";
            providers[providerId] = new ClashProxyProvider
            {
                Id = providerId,
                Proxies = plan.Proxies
                    .Where(proxy => actualProxies.Contains(proxy.Name, StringComparer.Ordinal))
                    .ToArray()
            };
        }

        return providers;
    }

    private static IReadOnlyList<ClashRuleProvider> BuildRuleProviders(IReadOnlyList<string> rules)
    {
        var providersByTarget = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var rule in rules)
        {
            var parsed = ParseRule(rule);
            if (parsed.Kind is RuleKind.Final or RuleKind.Builtin || string.IsNullOrWhiteSpace(parsed.Target))
            {
                continue;
            }

            if (!providersByTarget.TryGetValue(parsed.Target, out var payload))
            {
                payload = [];
                providersByTarget[parsed.Target] = payload;
            }

            payload.Add(parsed.Payload);
        }

        return providersByTarget
            .Select(static pair => new ClashRuleProvider
            {
                Id = $"rule-{SanitizeIdentifier(pair.Key)}",
                Target = pair.Key,
                Payload = pair.Value.Distinct(StringComparer.Ordinal).ToArray()
            })
            .ToArray();
    }

    private static IReadOnlyList<string> BuildClashRuleReferences(
        IReadOnlyList<string> rules,
        IReadOnlyList<ClashRuleProvider> ruleProviders)
    {
        var references = new List<string>();
        var seenRuleSetTargets = new HashSet<string>(StringComparer.Ordinal);
        var providersByTarget = ruleProviders.ToDictionary(static provider => provider.Target, StringComparer.Ordinal);

        foreach (var rule in rules)
        {
            var parsed = ParseRule(rule);
            if (parsed.Kind == RuleKind.Final)
            {
                references.Add(rule);
                continue;
            }

            if (parsed.Kind == RuleKind.Builtin || string.IsNullOrWhiteSpace(parsed.Target))
            {
                references.Add(rule);
                continue;
            }

            if (providersByTarget.TryGetValue(parsed.Target, out var provider) &&
                seenRuleSetTargets.Add(parsed.Target))
            {
                references.Add($"RULE-SET,{provider.Id},{provider.Target}");
            }
        }

        return references;
    }

    private static void AppendClashProxyProvider(
        StringBuilder builder,
        PanelUserRecord user,
        ClashProxyProvider provider,
        SubscriptionRenderSettings settings)
    {
        builder.AppendLine($"  {provider.Id}:");
        builder.AppendLine("    type: inline");
        builder.AppendLine("    health-check:");
        builder.AppendLine("      enable: true");
        builder.AppendLine($"      url: {YamlString(settings.TestUrl)}");
        builder.AppendLine($"      interval: {Math.Max(60, settings.TestIntervalSeconds)}");
        builder.AppendLine("    payload:");
        foreach (var proxy in provider.Proxies)
        {
            AppendClashProxy(builder, user, proxy, indentLevel: 3);
        }
    }

    private static void AppendClashRuleProvider(StringBuilder builder, ClashRuleProvider provider)
    {
        builder.AppendLine($"  {provider.Id}:");
        builder.AppendLine("    type: inline");
        builder.AppendLine("    behavior: classical");
        builder.AppendLine("    payload:");
        foreach (var rule in provider.Payload)
        {
            builder.AppendLine($"      - {rule}");
        }
    }

    private static void AppendClashProxy(
        StringBuilder builder,
        PanelUserRecord user,
        SubscriptionRenderProxy proxy,
        int indentLevel)
    {
        var endpoint = proxy.Endpoint;
        var indent = new string(' ', indentLevel * 2);
        var nestedIndent = new string(' ', (indentLevel + 1) * 2);
        var headersIndent = new string(' ', (indentLevel + 2) * 2);

        builder.AppendLine($"{indent}- name: {YamlString(proxy.Name)}");
        builder.AppendLine($"{nestedIndent}type: {proxy.Protocol}");
        builder.AppendLine($"{nestedIndent}server: {YamlString(endpoint.Host)}");
        builder.AppendLine($"{nestedIndent}port: {endpoint.Port}");

        switch (proxy.Protocol)
        {
            case "trojan":
                builder.AppendLine($"{nestedIndent}password: {YamlString(user.TrojanPassword)}");
                if (!string.IsNullOrWhiteSpace(endpoint.Sni))
                {
                    builder.AppendLine($"{nestedIndent}sni: {YamlString(endpoint.Sni)}");
                }
                break;
            case "vmess":
                builder.AppendLine($"{nestedIndent}uuid: {YamlString(ResolveProtocolUuid(user))}");
                builder.AppendLine($"{nestedIndent}alterId: 0");
                builder.AppendLine($"{nestedIndent}cipher: auto");
                builder.AppendLine($"{nestedIndent}tls: true");
                if (!string.IsNullOrWhiteSpace(endpoint.Sni))
                {
                    builder.AppendLine($"{nestedIndent}servername: {YamlString(endpoint.Sni)}");
                }
                break;
            case "vless":
                builder.AppendLine($"{nestedIndent}uuid: {YamlString(ResolveProtocolUuid(user))}");
                builder.AppendLine($"{nestedIndent}tls: true");
                if (!string.IsNullOrWhiteSpace(endpoint.Sni))
                {
                    builder.AppendLine($"{nestedIndent}servername: {YamlString(endpoint.Sni)}");
                }
                break;
            case "shadowsocks":
                builder.AppendLine($"{nestedIndent}cipher: chacha20-ietf-poly1305");
                builder.AppendLine($"{nestedIndent}password: {YamlString(user.TrojanPassword)}");
                break;
        }

        builder.AppendLine($"{nestedIndent}udp: true");
        if (proxy.Protocol is "trojan" or "vmess" or "vless")
        {
            builder.AppendLine($"{nestedIndent}skip-cert-verify: {ToYamlBoolean(endpoint.SkipCertificateVerification)}");
        }

        if (string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase))
        {
            builder.AppendLine($"{nestedIndent}network: ws");
            builder.AppendLine($"{nestedIndent}ws-opts:");
            builder.AppendLine($"{headersIndent}path: {YamlString(string.IsNullOrWhiteSpace(endpoint.Path) ? "/" : endpoint.Path)}");
            builder.AppendLine($"{headersIndent}headers:");
            builder.AppendLine($"{headersIndent}  Host: {YamlString(string.IsNullOrWhiteSpace(endpoint.WsHost) ? endpoint.Host : endpoint.WsHost)}");
        }
    }

    private static void AppendClashGroup(
        StringBuilder builder,
        SubscriptionProxyGroup group,
        ISet<string> proxyNames,
        IReadOnlyDictionary<string, ClashProxyProvider> providers)
    {
        var providerId = ResolveProviderId(group, proxyNames, providers);
        var explicitMembers = group.Proxies
            .Where(proxyName => !proxyNames.Contains(proxyName))
            .ToArray();

        builder.AppendLine($"  - name: {YamlString(group.Name)}");
        builder.AppendLine($"    type: {group.Type}");

        if ((string.Equals(group.Type, "url-test", StringComparison.Ordinal) ||
             string.Equals(group.Type, "fallback", StringComparison.Ordinal)) &&
            !string.IsNullOrWhiteSpace(group.Url))
        {
            builder.AppendLine($"    url: {YamlString(group.Url)}");
            builder.AppendLine($"    interval: {Math.Max(60, group.IntervalSeconds)}");
        }

        if (string.Equals(group.Type, "load-balance", StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(group.Strategy))
        {
            builder.AppendLine($"    strategy: {group.Strategy}");
        }

        if (providerId is not null)
        {
            builder.AppendLine("    use:");
            builder.AppendLine($"      - {providerId}");
        }

        if (explicitMembers.Length > 0 || providerId is null)
        {
            builder.AppendLine("    proxies:");
            foreach (var proxyName in explicitMembers.Length > 0 ? explicitMembers : group.Proxies)
            {
                builder.AppendLine($"      - {YamlString(proxyName)}");
            }
        }
    }

    private static string? ResolveProviderId(
        SubscriptionProxyGroup group,
        ISet<string> proxyNames,
        IReadOnlyDictionary<string, ClashProxyProvider> providers)
    {
        var actualProxyNames = group.Proxies
            .Where(proxyNames.Contains)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (actualProxyNames.Length == 0)
        {
            return null;
        }

        if (actualProxyNames.Length == proxyNames.Count &&
            actualProxyNames.All(proxyNames.Contains) &&
            providers.ContainsKey("all-nodes"))
        {
            return "all-nodes";
        }

        var groupProviderId = $"group-{SanitizeIdentifier(group.Name)}";
        return providers.ContainsKey(groupProviderId) ? groupProviderId : null;
    }

    private static string BuildSurgeProxyLine(PanelUserRecord user, SubscriptionRenderProxy proxy)
    {
        var endpoint = proxy.Endpoint;
        var values = new List<string>
        {
            $"{EscapeSurge(proxy.Name)}={proxy.Protocol}",
            endpoint.Host,
            endpoint.Port.ToString()
        };

        switch (proxy.Protocol)
        {
            case "trojan":
                values.Add($"password={EscapeSurge(user.TrojanPassword)}");
                break;
            case "vmess":
            case "vless":
                values.Add($"username={EscapeSurge(ResolveProtocolUuid(user))}");
                values.Add("tls=true");
                break;
        }

        values.Add("udp-relay=true");
        values.Add("tfo=true");
        if (!string.IsNullOrWhiteSpace(endpoint.Sni))
        {
            values.Add($"sni={EscapeSurge(endpoint.Sni)}");
        }

        if (proxy.Protocol is "trojan" or "vmess" or "vless")
        {
            values.Add($"skip-cert-verify={(endpoint.SkipCertificateVerification ? "true" : "false")}");
        }

        if (string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase))
        {
            values.Add("ws=true");
            if (!string.IsNullOrWhiteSpace(endpoint.Path))
            {
                values.Add($"ws-path={EscapeSurge(endpoint.Path)}");
            }

            if (!string.IsNullOrWhiteSpace(endpoint.WsHost))
            {
                values.Add($"ws-headers=Host:{EscapeSurge(endpoint.WsHost)}");
            }
        }

        return string.Join(",", values);
    }

    private static string BuildSurgeGroupLine(SubscriptionProxyGroup group)
    {
        var values = new List<string> { $"{EscapeSurge(group.Name)} = {group.Type}" };
        values.AddRange(group.Proxies.Select(EscapeSurge));

        if ((string.Equals(group.Type, "url-test", StringComparison.Ordinal) ||
             string.Equals(group.Type, "fallback", StringComparison.Ordinal)) &&
            !string.IsNullOrWhiteSpace(group.Url))
        {
            values.Add($"url={EscapeSurge(group.Url)}");
            values.Add($"interval={Math.Max(60, group.IntervalSeconds)}");
        }

        if (string.Equals(group.Type, "load-balance", StringComparison.Ordinal))
        {
            values.Add($"policy={EscapeSurge(string.IsNullOrWhiteSpace(group.Strategy) ? "round-robin" : group.Strategy)}");
        }

        return string.Join(",", values);
    }

    private static string BuildQuantumultXServerLine(PanelUserRecord user, SubscriptionRenderProxy proxy)
    {
        var endpoint = proxy.Endpoint;
        var values = proxy.Protocol switch
        {
            "trojan" => new List<string>
            {
                $"trojan={endpoint.Host}:{endpoint.Port}",
                $"password={user.TrojanPassword}",
                "over-tls=true"
            },
            "vmess" => new List<string>
            {
                $"vmess={endpoint.Host}:{endpoint.Port}",
                $"password={ResolveProtocolUuid(user)}",
                "method=none",
                "obfs=over-tls"
            },
            "vless" => new List<string>
            {
                $"vless={endpoint.Host}:{endpoint.Port}",
                $"password={ResolveProtocolUuid(user)}",
                "method=none",
                "obfs=over-tls"
            },
            _ => []
        };

        if (values.Count == 0)
        {
            return string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(endpoint.Sni))
        {
            values.Add($"tls-host={endpoint.Sni}");
        }

        values.Add(endpoint.SkipCertificateVerification ? "tls-verification=false" : "tls-verification=true");
        if (string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase))
        {
            values.Remove("obfs=over-tls");
            values.Add("obfs=wss");
            if (!string.IsNullOrWhiteSpace(endpoint.WsHost))
            {
                values.Add($"obfs-host={endpoint.WsHost}");
            }

            if (!string.IsNullOrWhiteSpace(endpoint.Path))
            {
                values.Add($"obfs-uri={endpoint.Path}");
            }
        }

        values.Add("fast-open=true");
        values.Add("udp-relay=true");
        values.Add($"tag={EscapeQuantumultValue(proxy.Name)}");
        return string.Join(", ", values);
    }

    private static string BuildQuantumultXPolicyLine(SubscriptionProxyGroup group, SubscriptionRenderSettings settings)
    {
        var members = group.Proxies.Select(ToQuantumultXPolicyTarget).ToList();
        return group.Type switch
        {
            "url-test" => string.Join(
                ", ",
                new[]
                {
                    $"url-latency-benchmark={EscapeQuantumultValue(group.Name)}"
                }
                .Concat(members)
                .Concat(
                    [
                        $"server_check_url={settings.TestUrl}",
                        $"check-interval={Math.Max(60, group.IntervalSeconds)}",
                        "tolerance=20"
                    ])),
            "fallback" => string.Join(
                ", ",
                new[]
                {
                    $"available={EscapeQuantumultValue(group.Name)}"
                }
                .Concat(members)
                .Concat(
                    [
                        $"server_check_url={settings.TestUrl}",
                        $"check-interval={Math.Max(60, group.IntervalSeconds)}",
                        "tolerance=20"
                    ])),
            "load-balance" => string.Join(
                ", ",
                new[]
                {
                    $"round-robin={EscapeQuantumultValue(group.Name)}"
                }
                .Concat(members)),
            _ => string.Join(
                ", ",
                new[]
                {
                    $"static={EscapeQuantumultValue(group.Name)}"
                }
                .Concat(members))
        };
    }

    private static string ToQuantumultXRule(string rule)
    {
        var parts = rule
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return string.Empty;
        }

        if (string.Equals(parts[0], "MATCH", StringComparison.OrdinalIgnoreCase))
        {
            return $"final,{ToQuantumultXPolicyTarget(parts[1])}";
        }

        var targetIndex = parts.Length - 1;
        while (targetIndex > 1 && RuleOptions.Contains(parts[targetIndex]))
        {
            targetIndex--;
        }

        if (targetIndex <= 0)
        {
            return string.Empty;
        }

        var target = ToQuantumultXPolicyTarget(parts[targetIndex]);
        var head = parts[0].ToUpperInvariant() switch
        {
            "DOMAIN-SUFFIX" => "host-suffix",
            "DOMAIN-KEYWORD" => "host-keyword",
            "DOMAIN" => "host",
            "IP-CIDR" => "ip-cidr",
            "SRC-IP-CIDR" => "ip-cidr6",
            "GEOIP" => "geoip",
            _ => parts[0].ToLowerInvariant()
        };

        var valueParts = new List<string> { head };
        for (var index = 1; index < parts.Length; index++)
        {
            if (index == targetIndex)
            {
                continue;
            }

            valueParts.Add(index > targetIndex && RuleOptions.Contains(parts[index])
                ? parts[index].ToLowerInvariant()
                : parts[index]);
        }

        valueParts.Add(target);
        return string.Join(", ", valueParts);
    }

    private static ParsedRule ParseRule(string rule)
    {
        var parts = rule
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return new ParsedRule
            {
                Kind = RuleKind.Invalid,
                Original = rule
            };
        }

        if (string.Equals(parts[0], "MATCH", StringComparison.OrdinalIgnoreCase))
        {
            return new ParsedRule
            {
                Kind = RuleKind.Final,
                Original = rule,
                Target = parts[1]
            };
        }

        var targetIndex = parts.Length - 1;
        while (targetIndex > 1 && RuleOptions.Contains(parts[targetIndex]))
        {
            targetIndex--;
        }

        if (targetIndex <= 0)
        {
            return new ParsedRule
            {
                Kind = RuleKind.Invalid,
                Original = rule
            };
        }

        var target = parts[targetIndex];
        var payloadParts = parts
            .Where((_, index) => index != targetIndex)
            .ToArray();

        return new ParsedRule
        {
            Kind = BuiltinTargets.Contains(target) ? RuleKind.Builtin : RuleKind.Group,
            Original = rule,
            Target = target,
            Payload = string.Join(",", payloadParts)
        };
    }

    private static string ResolveProtocolUuid(PanelUserRecord user)
    {
        if (Guid.TryParse(user.V2rayUuid, out var configured))
        {
            return configured.ToString("D");
        }

        if (Guid.TryParse(user.UserId, out var fallback))
        {
            return fallback.ToString("D");
        }

        return string.Empty;
    }

    private static string ToSurgeRule(string rule)
    {
        var normalized = rule.Replace(",no-resolve", string.Empty, StringComparison.OrdinalIgnoreCase);
        return normalized.StartsWith("MATCH,", StringComparison.Ordinal)
            ? normalized.Replace("MATCH,", "FINAL,", StringComparison.Ordinal)
            : normalized;
    }

    private static string ToQuantumultXPolicyTarget(string target)
        => target switch
        {
            "DIRECT" => "direct",
            "REJECT" => "reject",
            _ => EscapeQuantumultValue(target)
        };

    private static string EscapeQuantumultValue(string value)
        => value.Replace(",", " ", StringComparison.Ordinal).Trim();

    private static string BuildFileName(string appName, string extension)
    {
        var normalizedAppName = string.IsNullOrWhiteSpace(appName) ? "nodepanel" : appName;
        var sanitized = string.Concat(
            normalizedAppName
                .Where(ch => !Path.GetInvalidFileNameChars().Contains(ch))
                .Select(static ch => char.IsWhiteSpace(ch) ? '-' : ch));

        return $"{(string.IsNullOrWhiteSpace(sanitized) ? "nodepanel" : sanitized)}.{extension}";
    }

    private static string SanitizeIdentifier(string value)
    {
        var sanitized = new string(
            value
                .Trim()
                .ToLowerInvariant()
                .Select(static ch => char.IsLetterOrDigit(ch) ? ch : '-')
                .ToArray());
        while (sanitized.Contains("--", StringComparison.Ordinal))
        {
            sanitized = sanitized.Replace("--", "-", StringComparison.Ordinal);
        }

        sanitized = sanitized.Trim('-');
        return string.IsNullOrWhiteSpace(sanitized) ? "default" : sanitized;
    }

    private static string YamlString(string value)
        => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

    private static string ToYamlBoolean(bool value)
        => value ? "true" : "false";

    private static string EscapeSurge(string value)
        => value.Replace(",", "\\,", StringComparison.Ordinal);

    private sealed class ClashProxyProvider
    {
        public required string Id { get; init; }

        public required IReadOnlyList<SubscriptionRenderProxy> Proxies { get; init; }
    }

    private sealed class ClashRuleProvider
    {
        public required string Id { get; init; }

        public required string Target { get; init; }

        public required IReadOnlyList<string> Payload { get; init; }
    }

    private sealed class ParsedRule
    {
        public RuleKind Kind { get; init; }

        public string Original { get; init; } = string.Empty;

        public string Target { get; init; } = string.Empty;

        public string Payload { get; init; } = string.Empty;
    }

    private enum RuleKind
    {
        Invalid,
        Builtin,
        Group,
        Final
    }
}

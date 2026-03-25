using System.Text;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public static class SubscriptionFormatRenderer
{
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
        var builder = new StringBuilder();
        builder.AppendLine("mixed-port: 7890");
        builder.AppendLine("allow-lan: false");
        builder.AppendLine("mode: rule");

        if (plan.Proxies.Count == 0)
        {
            builder.AppendLine("proxies: []");
        }
        else
        {
            builder.AppendLine("proxies:");
            foreach (var proxy in plan.Proxies)
            {
                AppendClashProxy(builder, catalog.User, proxy, indentLevel: 1);
            }
        }

        builder.AppendLine("proxy-groups:");
        foreach (var group in plan.Groups)
        {
            AppendClashGroup(builder, group);
        }

        builder.AppendLine("rules:");
        foreach (var rule in plan.Rules)
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
        SubscriptionProxyGroup group)
    {
        var members = group.Proxies
            .Distinct(StringComparer.Ordinal)
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

        if (members.Length > 0)
        {
            builder.AppendLine("    proxies:");
            foreach (var proxyName in members)
            {
                builder.AppendLine($"      - {YamlString(proxyName)}");
            }
        }
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

    private static string YamlString(string value)
        => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

    private static string ToYamlBoolean(bool value)
        => value ? "true" : "false";

    private static string EscapeSurge(string value)
        => value.Replace(",", "\\,", StringComparison.Ordinal);

}

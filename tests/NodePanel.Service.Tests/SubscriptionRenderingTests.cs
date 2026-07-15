using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class SubscriptionRenderingTests
{
    [Fact]
    public void BuildPlan_full_profile_generates_strategy_region_and_tag_groups()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.EnableRejectInGlobalGroup] = "true",
                [SubscriptionSettingKeys.TestUrl] = "https://cp.cloudflare.com/generate_204",
                [SubscriptionSettingKeys.TestIntervalSeconds] = "600"
            });

        var plan = resolver.BuildPlan(CreateCatalog(), request);
        var groupNames = plan.Groups.Select(static group => group.Name).ToArray();

        Assert.Contains("Proxy", groupNames);
        Assert.Contains("GLOBAL", groupNames);
        Assert.Contains("Auto", groupNames);
        Assert.Contains("Fallback", groupNames);
        Assert.Contains("Load Balance", groupNames);
        Assert.Contains("All Nodes", groupNames);
        Assert.Contains("香港", groupNames);
        Assert.Contains("日本", groupNames);
        Assert.Contains("美国", groupNames);
        Assert.Contains("流媒体", groupNames);
        Assert.Contains("AI", groupNames);
        Assert.Contains("游戏", groupNames);
        Assert.Contains("Netflix", groupNames);

        var proxyGroup = Assert.Single(plan.Groups, static group => group.Name == "Proxy");
        Assert.DoesNotContain("DIRECT", proxyGroup.Proxies);
        Assert.DoesNotContain("REJECT", proxyGroup.Proxies);

        var globalGroup = Assert.Single(plan.Groups, static group => group.Name == "GLOBAL");
        Assert.Contains("DIRECT", globalGroup.Proxies);
        Assert.Contains("REJECT", globalGroup.Proxies);
        Assert.Contains("DOMAIN-SUFFIX,openai.com,AI", plan.Rules);
        Assert.Contains("DOMAIN-KEYWORD,netflix,Netflix", plan.Rules);
        Assert.Contains("GEOIP,CN,DIRECT", plan.Rules);
    }

    [Fact]
    public void BuildPlan_no_reject_profile_never_injects_reject_into_global_group()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.NoReject,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.EnableRejectInGlobalGroup] = "true"
            });

        var plan = resolver.BuildPlan(CreateCatalog(), request);
        var globalGroup = Assert.Single(plan.Groups, static group => group.Name == "GLOBAL");
        Assert.DoesNotContain("REJECT", globalGroup.Proxies);
        Assert.Contains("DIRECT", globalGroup.Proxies);
    }

    [Fact]
    public void BuildPlan_default_profile_uses_site_name_as_primary_group()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            null,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.SiteName] = "内部专用"
            });

        var plan = resolver.BuildPlan(CreateCatalog(), request);
        var groupNames = plan.Groups.Select(static group => group.Name).ToArray();

        Assert.Equal(SubscriptionProfileNames.Managed, request.ProfileName);
        Assert.Contains("内部专用", groupNames);
        Assert.Contains("Auto", groupNames);
        Assert.Contains("Fallback", groupNames);
        Assert.DoesNotContain("GLOBAL", groupNames);
        Assert.DoesNotContain("All Nodes", groupNames);
        Assert.DoesNotContain("香港", groupNames);
        Assert.DoesNotContain("AI", groupNames);

        var proxyGroup = Assert.Single(plan.Groups, static group => group.Name == "内部专用");
        Assert.Contains("Auto", proxyGroup.Proxies);
        Assert.Contains("Fallback", proxyGroup.Proxies);
        Assert.Contains("HK-AI-Stream-tcp", proxyGroup.Proxies);
        Assert.Contains("US-Netflix-tcp", proxyGroup.Proxies);
        Assert.DoesNotContain("DIRECT", proxyGroup.Proxies);
        Assert.Equal("内部专用", plan.FinalGroupName);
        Assert.Contains("MATCH,内部专用", plan.Rules);
    }

    [Fact]
    public void RenderClash_outputs_protocol_specific_proxy_definitions()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");

        Assert.Equal("text/yaml", rendered.ContentType);
        Assert.Contains("proxies:", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("proxies: []", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("proxy-providers:", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("rule-providers:", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("type: inline", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("use:", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("  - name: 'HK-AI-Stream-tcp'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("  - name: 'JP-Game-wss'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("  - name: 'US-Netflix-tcp'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("type: trojan", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("type: vmess", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("type: vless", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("password: 'trojan-secret'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("uuid: '11111111-1111-1111-1111-111111111111'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("name: 'GLOBAL'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("strategy: round-robin", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("      - 'HK-AI-Stream-tcp'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("      - 'DIRECT'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("  - DOMAIN-SUFFIX,openai.com,AI", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("  - MATCH,GLOBAL", rendered.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderClash_outputs_probe_fields_for_every_probe_group()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.TestUrl] = "https://cp.cloudflare.com/generate_204",
                [SubscriptionSettingKeys.TestIntervalSeconds] = "600"
            });
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");

        foreach (var group in plan.Groups.Where(static group => IsProbeGroup(group.Type)))
        {
            var block = GetClashGroupBlock(rendered.Content, group.Name);
            Assert.Contains("    url: 'https://cp.cloudflare.com/generate_204'", block, StringComparison.Ordinal);
            Assert.Contains("    interval: 600", block, StringComparison.Ordinal);
        }

        Assert.Contains("    strategy: round-robin", GetClashGroupBlock(rendered.Content, "Load Balance"), StringComparison.Ordinal);
    }

    [Fact]
    public void RenderClash_keeps_generated_select_groups_without_probe_fields()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.TestUrl] = "https://cp.cloudflare.com/generate_204",
                [SubscriptionSettingKeys.TestIntervalSeconds] = "600"
            });
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");

        foreach (var group in plan.Groups.Where(static group => string.Equals(group.Type, "select", StringComparison.Ordinal)))
        {
            var block = GetClashGroupBlock(rendered.Content, group.Name);
            Assert.DoesNotContain("    url:", block, StringComparison.Ordinal);
            Assert.DoesNotContain("    interval:", block, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void RenderClash_custom_load_balance_group_uses_default_probe_fields()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Minimal,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.CustomGroupsJson] =
                    """
                    [
                      {
                        "name": "Node Pool",
                        "type": "load-balance",
                        "includeAllNodes": true
                      }
                    ]
                    """
            });
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");
        var block = GetClashGroupBlock(rendered.Content, "Node Pool");

        Assert.Contains("    type: load-balance", block, StringComparison.Ordinal);
        Assert.Contains("    url: 'http://www.gstatic.com/generate_204'", block, StringComparison.Ordinal);
        Assert.Contains("    interval: 300", block, StringComparison.Ordinal);
        Assert.Contains("    strategy: round-robin", block, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderClash_managed_profile_uses_site_name_primary_group()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            null,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.SiteName] = "内部专用"
            });
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "内部专用");

        Assert.Contains("  - name: '内部专用'", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("name: 'GLOBAL'", rendered.Content, StringComparison.Ordinal);
        Assert.DoesNotContain("name: 'All Nodes'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("      - 'HK-AI-Stream-tcp'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("  - MATCH,内部专用", rendered.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderSurge_keeps_direct_only_inside_global_group()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Surge,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.EnableRejectInGlobalGroup] = "false"
            });
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");
        var proxyLine = GetLine(rendered.Content, "Proxy = ");
        var globalLine = GetLine(rendered.Content, "GLOBAL = ");

        Assert.Contains("Auto", proxyLine, StringComparison.Ordinal);
        Assert.DoesNotContain("DIRECT", proxyLine, StringComparison.Ordinal);
        Assert.DoesNotContain("REJECT", proxyLine, StringComparison.Ordinal);
        Assert.Contains("DIRECT", globalLine, StringComparison.Ordinal);
        Assert.DoesNotContain("REJECT", globalLine, StringComparison.Ordinal);
        Assert.Contains("FINAL,GLOBAL", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("DOMAIN-SUFFIX,openai.com,AI", rendered.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildPlan_applies_custom_group_and_custom_rules()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.CustomGroupsJson] =
                    """
                    [
                      {
                        "name": "Streaming Mix",
                        "type": "select",
                        "matchTags": ["stream", "netflix"],
                        "includeGroups": ["Auto"]
                      }
                    ]
                    """,
                [SubscriptionSettingKeys.CustomRulesText] =
                    """
                    DOMAIN-SUFFIX,example-stream.test,Streaming Mix
                    DOMAIN-SUFFIX,invalid.example,NotExists
                    """
            });

        var plan = resolver.BuildPlan(CreateCatalog(), request);
        var customGroup = Assert.Single(plan.Groups, static group => group.Name == "Streaming Mix");

        Assert.Contains("Auto", customGroup.Proxies);
        Assert.Contains("HK-AI-Stream-tcp", customGroup.Proxies);
        Assert.Contains("US-Netflix-tcp", customGroup.Proxies);
        Assert.Contains("DOMAIN-SUFFIX,example-stream.test,Streaming Mix", plan.Rules);
        Assert.DoesNotContain("DOMAIN-SUFFIX,invalid.example,NotExists", plan.Rules);
    }

    [Fact]
    public void RenderQuantumultX_outputs_policies_and_filters()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.QuantumultX,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [SubscriptionSettingKeys.TestUrl] = "https://cp.cloudflare.com/generate_204",
                [SubscriptionSettingKeys.TestIntervalSeconds] = "600"
            });
        var catalog = CreateCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");

        Assert.Equal("text/plain", rendered.ContentType);
        Assert.Contains("[server_local]", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("[policy]", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("[filter_local]", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("url-latency-benchmark=Auto", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("available=Fallback", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("round-robin=Load Balance", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("static=GLOBAL", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("final,GLOBAL", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("host-suffix, openai.com, AI", rendered.Content, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildPlan_does_not_infer_region_group_from_endpoint_label()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));

        var catalog = new SubscriptionCatalog
        {
            User = new PanelUserRecord
            {
                UserId = "user-a",
                TrojanPassword = "trojan-secret",
                Subscription = new PanelUserSubscriptionProfile()
            },
            AssignedNodes =
            [
                new PanelNodeRecord
                {
                    NodeId = "node-a",
                    DisplayName = string.Empty,
                    Protocol = "trojan"
                }
            ],
            Endpoints =
            [
                new SubscriptionEndpoint
                {
                    NodeId = "node-a",
                    DisplayName = string.Empty,
                    Host = "node-a.example.com",
                    Port = 443,
                    Sni = "node-a.example.com",
                    Label = "-wss",
                    Protocol = "trojan",
                    Transport = "ws",
                    Path = "/ws",
                    WsHost = "node-a.example.com"
                }
            ]
        };

        var plan = resolver.BuildPlan(catalog, request);

        Assert.DoesNotContain(plan.Groups, static group => group.Name == "-wss");
    }

    [Fact]
    public void BuildPlan_does_not_infer_region_group_from_plain_display_name()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));

        var catalog = new SubscriptionCatalog
        {
            User = new PanelUserRecord
            {
                UserId = "user-a",
                TrojanPassword = "trojan-secret",
                Subscription = new PanelUserSubscriptionProfile()
            },
            AssignedNodes =
            [
                new PanelNodeRecord
                {
                    NodeId = "node-a",
                    DisplayName = "www",
                    Protocol = "trojan"
                }
            ],
            Endpoints =
            [
                new SubscriptionEndpoint
                {
                    NodeId = "node-a",
                    DisplayName = "www",
                    Host = "node-a.example.com",
                    Port = 443,
                    Sni = "node-a.example.com",
                    Label = "www-wss",
                    Protocol = "trojan",
                    Transport = "ws",
                    Path = "/ws",
                    WsHost = "node-a.example.com"
                }
            ]
        };

        var plan = resolver.BuildPlan(catalog, request);

        Assert.DoesNotContain(plan.Groups, static group => group.Name == "www");
    }

    [Fact]
    public void BuildPlan_avoids_group_name_collisions_with_proxy_names()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));

        var catalog = new SubscriptionCatalog
        {
            User = new PanelUserRecord
            {
                UserId = "user-a",
                TrojanPassword = "trojan-secret",
                Subscription = new PanelUserSubscriptionProfile()
            },
            AssignedNodes =
            [
                new PanelNodeRecord
                {
                    NodeId = "node-a",
                    DisplayName = "proxy-a",
                    Protocol = "trojan",
                    SubscriptionRegion = "HK"
                }
            ],
            Endpoints =
            [
                new SubscriptionEndpoint
                {
                    NodeId = "node-a",
                    DisplayName = "proxy-a",
                    Host = "node-a.example.com",
                    Port = 443,
                    Sni = "node-a.example.com",
                    Label = "香港",
                    Protocol = "trojan"
                }
            ]
        };

        var plan = resolver.BuildPlan(catalog, request);
        var derivedGroup = Assert.Single(
            plan.Groups,
            static group =>
                !string.Equals(group.Name, "Proxy", StringComparison.Ordinal) &&
                !string.Equals(group.Name, "GLOBAL", StringComparison.Ordinal) &&
                !string.Equals(group.Name, "All Nodes", StringComparison.Ordinal));

        Assert.NotEqual("香港", derivedGroup.Name);
        Assert.Equal(["香港"], derivedGroup.Proxies);
    }

    [Fact]
    public void BuildPlan_clash_keeps_grpc_but_filters_httpupgrade_and_splithttp_proxies()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));

        var catalog = CreateCatalogWithEndpoints(
            new PanelNodeRecord
            {
                NodeId = "node-edge",
                DisplayName = "Edge",
                Protocol = InboundProtocols.Vless
            },
            new SubscriptionEndpoint
            {
                NodeId = "node-edge",
                DisplayName = "Edge",
                Host = "edge.example.com",
                Port = 443,
                Sni = "edge.example.com",
                Label = "Edge-grpc",
                Protocol = InboundProtocols.Vless,
                Transport = InboundTransports.Grpc,
                GrpcServiceName = "/edge"
            },
            new SubscriptionEndpoint
            {
                NodeId = "node-edge",
                DisplayName = "Edge",
                Host = "edge.example.com",
                Port = 8443,
                Sni = "edge.example.com",
                Label = "Edge-httpupgrade",
                Protocol = InboundProtocols.Vless,
                Transport = InboundTransports.HttpUpgrade,
                Path = "/upgrade",
                WsHost = "cdn.example.com"
            },
            new SubscriptionEndpoint
            {
                NodeId = "node-edge",
                DisplayName = "Edge",
                Host = "edge.example.com",
                Port = 443,
                Sni = "edge.example.com",
                Label = "Edge-splithttp",
                Protocol = InboundProtocols.Vless,
                Transport = InboundTransports.SplitHttp,
                Path = "/xhttp",
                WsHost = "cdn.example.com"
            });

        var plan = resolver.BuildPlan(catalog, request);

        Assert.Equal(["Edge-grpc"], plan.Proxies.Select(static proxy => proxy.Name).ToArray());
    }

    [Fact]
    public void BuildUri_vless_reality_outputs_reality_query_fields()
    {
        var catalog = CreateRealityCatalog();
        var endpoint = Assert.Single(catalog.Endpoints);
        var service = new SubscriptionCatalogService(null!);

        var uri = service.BuildUri(catalog.User, endpoint);

        Assert.StartsWith("vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?", uri, StringComparison.Ordinal);
        Assert.Contains("security=reality", uri, StringComparison.Ordinal);
        Assert.Contains("sni=dl.google.com", uri, StringComparison.Ordinal);
        Assert.Contains("fp=chrome", uri, StringComparison.Ordinal);
        Assert.Contains("pbk=reality-public-key", uri, StringComparison.Ordinal);
        Assert.Contains("sid=0123456789abcdef", uri, StringComparison.Ordinal);
        Assert.Contains("spx=%2F", uri, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderClash_outputs_vless_reality_options()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Clash,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var catalog = CreateRealityCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");

        Assert.Contains("  - name: 'Edge-reality'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("type: vless", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("servername: 'dl.google.com'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("client-fingerprint: 'chrome'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("reality-opts:", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("public-key: 'reality-public-key'", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("short-id: '0123456789abcdef'", rendered.Content, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SubscriptionFormats.Surge)]
    [InlineData(SubscriptionFormats.QuantumultX)]
    public void BuildPlan_filters_reality_for_legacy_structured_formats(string format)
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            format,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var catalog = CreateRealityCatalog();

        var plan = resolver.BuildPlan(catalog, request);

        Assert.Empty(plan.Proxies);
    }

    [Fact]
    public void RenderSurge_includes_shadowsocks_proxy_definitions()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.Surge,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var catalog = CreateShadowsocksCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");
        var proxyLine = GetLine(rendered.Content, "SS-Node-ss=shadowsocks");

        Assert.Contains("encrypt-method=chacha20-ietf-poly1305", proxyLine, StringComparison.Ordinal);
        Assert.Contains("password=ss-secret", proxyLine, StringComparison.Ordinal);
        Assert.Contains("udp-relay=true", proxyLine, StringComparison.Ordinal);
    }

    [Fact]
    public void RenderQuantumultX_includes_shadowsocks_proxy_definitions()
    {
        var resolver = new SubscriptionProfileResolver();
        var request = resolver.ResolveRequest(
            SubscriptionFormats.QuantumultX,
            SubscriptionProfileNames.Full,
            null,
            new Dictionary<string, string>(StringComparer.Ordinal));
        var catalog = CreateShadowsocksCatalog();
        var plan = resolver.BuildPlan(catalog, request);

        var rendered = SubscriptionFormatRenderer.Render(catalog, plan, "NodePanel");

        Assert.Contains("shadowsocks=ss.example.com:8388", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("method=chacha20-ietf-poly1305", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("password=ss-secret", rendered.Content, StringComparison.Ordinal);
        Assert.Contains("tag=SS-Node-ss", rendered.Content, StringComparison.Ordinal);
    }

    private static string GetLine(string content, string prefix)
        => content
            .Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries)
            .First(line => line.StartsWith(prefix, StringComparison.Ordinal));

    private static string GetClashGroupBlock(string content, string groupName)
    {
        var marker = $"  - name: '{groupName.Replace("'", "''", StringComparison.Ordinal)}'";
        var start = content.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Clash group '{groupName}' was not rendered.");

        var next = content.IndexOf("\n  - name:", start + marker.Length, StringComparison.Ordinal);
        if (next < 0)
        {
            next = content.IndexOf("\nrules:", start + marker.Length, StringComparison.Ordinal);
        }

        return next < 0
            ? content[start..]
            : content[start..next];
    }

    private static bool IsProbeGroup(string groupType)
        => string.Equals(groupType, "url-test", StringComparison.Ordinal) ||
           string.Equals(groupType, "fallback", StringComparison.Ordinal) ||
           string.Equals(groupType, "load-balance", StringComparison.Ordinal);

    private static SubscriptionCatalog CreateCatalogWithEndpoints(
        PanelNodeRecord node,
        params SubscriptionEndpoint[] endpoints)
        => new()
        {
            User = CreateCatalog().User,
            AssignedNodes = [node],
            Endpoints = endpoints
        };

    private static SubscriptionCatalog CreateRealityCatalog()
        => CreateCatalogWithEndpoints(
            new PanelNodeRecord
            {
                NodeId = "node-reality",
                DisplayName = "Edge",
                Protocol = InboundProtocols.Vless
            },
            new SubscriptionEndpoint
            {
                NodeId = "node-reality",
                DisplayName = "Edge",
                Host = "edge.example.com",
                Port = 443,
                Sni = "dl.google.com",
                Label = "Edge-reality",
                Protocol = InboundProtocols.Vless,
                Security = RuntimeInternetSecurityTypes.Reality,
                Transport = InboundTransports.Tcp,
                RealityPublicKey = "reality-public-key",
                RealityShortId = "0123456789abcdef",
                RealityFingerprint = "chrome",
                RealitySpiderX = "/"
            });

    private static SubscriptionCatalog CreateShadowsocksCatalog()
        => CreateCatalogWithEndpoints(
            new PanelNodeRecord
            {
                NodeId = "node-ss",
                DisplayName = "SS-Node",
                Protocol = InboundProtocols.Shadowsocks
            },
            new SubscriptionEndpoint
            {
                NodeId = "node-ss",
                DisplayName = "SS-Node",
                Host = "ss.example.com",
                Port = 8388,
                Sni = string.Empty,
                Label = "SS-Node-ss",
                Protocol = InboundProtocols.Shadowsocks,
                Transport = InboundTransports.Tcp
            }) with
        {
            User = CreateCatalog().User with
            {
                ShadowsocksCipher = ShadowsocksCipherTypes.ChaCha20Poly1305,
                ShadowsocksPassword = "ss-secret"
            }
        };

    private static SubscriptionCatalog CreateCatalog()
        => new()
        {
            User = new PanelUserRecord
            {
                UserId = "11111111-1111-1111-1111-111111111111",
                DisplayName = "demo-user",
                TrojanPassword = "trojan-secret",
                V2rayUuid = "11111111-1111-1111-1111-111111111111",
                SubscriptionToken = "token-demo",
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "Demo",
                    TransferEnableBytes = 1024L * 1024L * 1024L
                }
            },
            AssignedNodes =
            [
                new PanelNodeRecord
                {
                    NodeId = "node-hk",
                    DisplayName = "HK-AI-Stream",
                    Protocol = "trojan",
                    SubscriptionRegion = "香港",
                    SubscriptionTags = ["stream", "ai"]
                },
                new PanelNodeRecord
                {
                    NodeId = "node-jp",
                    DisplayName = "JP-Game",
                    Protocol = "vmess",
                    SubscriptionRegion = "日本",
                    SubscriptionTags = ["game"]
                },
                new PanelNodeRecord
                {
                    NodeId = "node-us",
                    DisplayName = "US-Netflix",
                    Protocol = "vless",
                    SubscriptionRegion = "美国",
                    SubscriptionTags = ["netflix"]
                }
            ],
            Endpoints =
            [
                new SubscriptionEndpoint
                {
                    NodeId = "node-hk",
                    DisplayName = "HK-AI-Stream",
                    Host = "hk.example.com",
                    Port = 443,
                    Sni = "hk.example.com",
                    Label = "HK-AI-Stream-tcp",
                    Protocol = "trojan"
                },
                new SubscriptionEndpoint
                {
                    NodeId = "node-jp",
                    DisplayName = "JP-Game",
                    Host = "jp.example.com",
                    Port = 443,
                    Sni = "jp.example.com",
                    Label = "JP-Game-wss",
                    Protocol = "vmess",
                    Transport = "ws",
                    Path = "/ws",
                    WsHost = "jp.example.com"
                },
                new SubscriptionEndpoint
                {
                    NodeId = "node-us",
                    DisplayName = "US-Netflix",
                    Host = "us.example.com",
                    Port = 443,
                    Sni = "us.example.com",
                    Label = "US-Netflix-tcp",
                    Protocol = "vless"
                }
            ]
        };
}

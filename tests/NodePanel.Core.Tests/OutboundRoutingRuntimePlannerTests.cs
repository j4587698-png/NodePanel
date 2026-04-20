using System.Net;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class OutboundRoutingRuntimePlannerTests
{
    [Fact]
    public void TryBuild_uses_first_outbound_as_default_and_first_matching_rule_wins()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("proxy", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    ["edge"],
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct"),
                new TestRoutingRuleDefinition(
                    true,
                    ["edge"],
                    Array.Empty<string>(),
                    [RoutingNetworks.Tcp],
                    "proxy")
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);
        Assert.Equal("proxy", plan.DefaultOutboundTag);
        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                InboundTag = "edge",
                Network = RoutingNetworks.Tcp
            },
            out var matchedTag));
        Assert.Equal("direct", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                Network = RoutingNetworks.Tcp
            },
            out var defaultTag));
        Assert.Equal("proxy", defaultTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_inbound_tag_case_sensitively()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("case-sensitive", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    ["Edge"],
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "case-sensitive")
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                InboundTag = "Edge"
            },
            out var matchedTag));
        Assert.Equal("case-sensitive", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                InboundTag = "edge"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryPickRoute_returns_matching_rule_tag_without_default_fallback()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("proxy", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    ["edge"],
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "proxy",
                    ruleTag: "edge-route")
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);
        Assert.True(plan.TryPickRoute(
            new DispatchContext
            {
                InboundTag = "edge"
            },
            out var route));
        Assert.Equal("proxy", route.OutboundTag);
        Assert.Equal("edge-route", route.RuleTag);
        Assert.False(plan.TryPickRoute(new DispatchContext(), out _));
    }

    [Fact]
    public void TryResolveOutboundTag_matches_detected_protocol_instead_of_inbound_protocol()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("sniffed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    [RoutingProtocols.Http],
                    Array.Empty<string>(),
                    "sniffed")
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                InboundProtocol = RoutingProtocols.Http,
                DetectedProtocol = string.Empty
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Trojan,
                DetectedProtocol = RoutingProtocols.Http
            },
            out var matchedTag));
        Assert.Equal("sniffed", matchedTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_content_protocol_prefix_and_attribute_regexes()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("http-api", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    [RoutingProtocols.Http],
                    Array.Empty<string>(),
                    "http-api",
                    attributes: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [":path"] = "/test",
                        ["Custom"] = "p([a-z]+)ch"
                    })
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                Content = new DispatchContent
                {
                    Protocol = "http/1.1",
                    Attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [":path"] = "/test/1",
                        ["custom"] = "peach"
                    }
                }
            },
            out var matchedTag));
        Assert.Equal("http-api", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                Content = new DispatchContent
                {
                    Protocol = "http/1.1",
                    Attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [":path"] = "/other",
                        ["custom"] = "peach"
                    }
                }
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_xray_domain_rule_kinds()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("plain", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("domain", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("full", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("regexp", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("dotless", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "full",
                    domains: ["full:api.full-match.test"]),
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "regexp",
                    domains: ["regexp:^facebook\\.com$"]),
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "domain",
                    domains: ["domain:google.com"]),
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "dotless",
                    domains: ["dotless:local"]),
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "plain",
                    domains: ["example.com"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "www.example.com.www"
            },
            out var plainTag));
        Assert.Equal("plain", plainTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "www.google.com"
            },
            out var domainTag));
        Assert.Equal("domain", domainTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "api.full-match.test"
            },
            out var fullTag));
        Assert.Equal("full", fullTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "facebook.com"
            },
            out var regexpTag));
        Assert.Equal("regexp", regexpTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "mylocal"
            },
            out var dotlessTag));
        Assert.Equal("dotless", dotlessTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "www.facebook.com"
            },
            out var regexFallbackTag));
        Assert.Equal("direct", regexFallbackTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "my.local"
            },
            out var dotlessFallbackTag));
        Assert.Equal("direct", dotlessFallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_explicit_route_target_for_domain_and_port()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("routed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "routed",
                    domains: ["full:route.example.com"],
                    destinationPorts: ["443"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);
        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                RouteTargetHost = "route.example.com",
                RouteTargetPort = 443,
                TargetHost = "198.51.100.10",
                TargetPort = 80,
                OriginalDestinationHost = "198.51.100.10",
                OriginalDestinationPort = 80
            },
            out var matchedTag));
        Assert.Equal("routed", matchedTag);
    }

    [Fact]
    public void TryResolveOutboundTag_uses_current_routing_target_instead_of_original_destination_for_cidr()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("routed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "routed",
                    destinationCidrs: ["203.0.113.0/24"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                RouteTargetHost = "203.0.113.7",
                OriginalDestinationHost = "198.51.100.7",
                OriginalDestinationPort = 443,
                TargetHost = "198.51.100.7",
                TargetPort = 443,
                TargetAddresses = [IPAddress.Parse("198.51.100.7")]
            },
            out var routeTargetTag));
        Assert.Equal("routed", routeTargetTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                TargetHost = "route.example.com",
                TargetPort = 443,
                OriginalDestinationHost = "203.0.113.7",
                OriginalDestinationPort = 443,
                TargetAddresses = [IPAddress.Parse("203.0.113.7")]
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void Resolve_selects_handler_by_protocol_of_matched_outbound()
    {
        var fallbackHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var matchedHandler = new TestOutboundHandler(OutboundProtocols.Trojan);
        var router = new DefaultOutboundRouter(
            [fallbackHandler, matchedHandler],
            new StaticOutboundRuntimePlanProvider(
                new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        },
                        new OutboundRuntime
                        {
                            Tag = "proxy",
                            Protocol = OutboundProtocols.Trojan
                        }
                    ],
                    RoutingRules =
                    [
                        new RoutingRuleRuntime
                        {
                            InboundTags = ["edge"],
                            OutboundTag = "proxy"
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }));

        var resolved = router.Resolve(
            new DispatchContext
            {
                InboundTag = "edge"
            },
            destination: null);

        Assert.Same(matchedHandler, resolved.Handler);
        Assert.Equal("proxy", resolved.OutboundTag);
        Assert.Equal("proxy", resolved.Context.OutboundTag);
    }

    [Fact]
    public void RuntimeRoutingService_adds_removes_and_lists_rules()
    {
        var service = new DefaultRuntimeRoutingService(
            new StaticOutboundRuntimePlanProvider(
                new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        },
                        new OutboundRuntime
                        {
                            Tag = "proxy",
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }));

        Assert.False(service.TryPickRoute(
            new DispatchContext
            {
                InboundTag = "edge"
            },
            out _));

        service.AddRule(
            new TestRoutingRuleDefinition(
                true,
                ["edge"],
                Array.Empty<string>(),
                Array.Empty<string>(),
                "proxy",
                ruleTag: "edge-route"));

        var listedRule = Assert.Single(service.ListRules());
        Assert.Equal("edge-route", listedRule.RuleTag);
        Assert.Equal("proxy", listedRule.OutboundTag);

        Assert.True(service.TryPickRoute(
            new DispatchContext
            {
                InboundTag = "edge"
            },
            out var route));
        Assert.Equal("proxy", route.OutboundTag);
        Assert.Equal("edge-route", route.RuleTag);

        Assert.True(service.RemoveRule("edge-route"));
        Assert.Empty(service.ListRules());
        Assert.False(service.TryPickRoute(
            new DispatchContext
            {
                InboundTag = "edge"
            },
            out _));
    }

    [Fact]
    public void RuntimeRoutingService_rejects_duplicate_non_empty_rule_tags()
    {
        var service = new DefaultRuntimeRoutingService(
            new StaticOutboundRuntimePlanProvider(
                new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }));

        service.AddRule(
            new TestRoutingRuleDefinition(
                true,
                ["edge"],
                Array.Empty<string>(),
                Array.Empty<string>(),
                "direct",
                ruleTag: "edge-route"));

        var exception = Assert.Throws<InvalidOperationException>(() => service.AddRule(
            new TestRoutingRuleDefinition(
                true,
                ["other"],
                Array.Empty<string>(),
                Array.Empty<string>(),
                "direct",
                ruleTag: "edge-route")));
        Assert.Contains("already registered", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_unknown_routing_outbound_tag()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    ["edge"],
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "missing")
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("unknown outbound tag", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_allows_routing_rule_targeting_dynamic_vless_reverse_tag()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    ["edge"],
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "reverse-edge")
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error,
            additionalKnownOutboundTags: ["reverse-edge"]);

        Assert.True(success, error);
        var rule = Assert.Single(plan.RoutingRules);
        Assert.Equal("reverse-edge", rule.OutboundTag);
    }

    [Fact]
    public void TryBuild_normalizes_outbound_sender_settings()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestSenderOutboundDefinition(
                    "proxy",
                    true,
                    OutboundProtocols.Trojan,
                    via: "srcip",
                    viaCidr: "/24",
                    targetStrategy: "force-ipv6v4",
                    proxyOutboundTag: "direct",
                    multiplexSettings: new TestMultiplexDefinition(true, 8, 16, OutboundXudpProxyModes.Skip)),
                new TestSenderOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Trojan, OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);
        Assert.True(plan.TryGetOutbound("proxy", out var outbound));
        Assert.Equal("srcip", outbound.Via);
        Assert.Equal("24", outbound.ViaCidr);
        Assert.Equal(OutboundTargetStrategies.ForceIpv6v4, outbound.TargetStrategy);
        Assert.Equal("direct", outbound.ProxyOutboundTag);
        Assert.True(outbound.MultiplexSettings.Enabled);
        Assert.Equal(8, outbound.MultiplexSettings.Concurrency);
        Assert.Equal(16, outbound.MultiplexSettings.XudpConcurrency);
        Assert.Equal(OutboundXudpProxyModes.Skip, outbound.MultiplexSettings.XudpProxyUdp443);
    }

    [Fact]
    public void TryBuild_rejects_unknown_proxy_outbound_tag()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestSenderOutboundDefinition(
                    "proxy",
                    true,
                    OutboundProtocols.Trojan,
                    proxyOutboundTag: "missing")
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Trojan],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("unknown proxy outbound tag", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_proxy_outbound_cycle()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestSenderOutboundDefinition("first", true, OutboundProtocols.Freedom, proxyOutboundTag: "second"),
                new TestSenderOutboundDefinition("second", true, OutboundProtocols.Freedom, proxyOutboundTag: "first")
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("cycle", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_user_domain_source_cidr_and_destination_port()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("routed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    [RoutingNetworks.Tcp],
                    "routed",
                    userIds: [" user-1 "],
                    domains: ["domain:example.com"],
                    sourceCidrs: ["203.0.113.0/24"],
                    destinationPorts: ["443", "8000-9000"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "user-1",
                Network = RoutingNetworks.Tcp,
                DetectedDomain = "api.example.com",
                OriginalDestinationHost = "api.example.com",
                OriginalDestinationPort = 8443,
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000)
            },
            out var matchedTag));
        Assert.Equal("routed", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "user-1",
                Network = RoutingNetworks.Tcp,
                DetectedDomain = "example.co",
                OriginalDestinationHost = "example.co",
                OriginalDestinationPort = 8443,
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000)
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_exact_and_regexp_user_ids()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("user-route", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "user-route",
                    userIds: [" admin@example.com ", "regexp:^svc-[0-9]+$", "regexp:("])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "admin@example.com"
            },
            out var exactTag));
        Assert.Equal("user-route", exactTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "svc-42"
            },
            out var regexTag));
        Assert.Equal("user-route", regexTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "Admin@example.com"
            },
            out var caseSensitiveFallbackTag));
        Assert.Equal("direct", caseSensitiveFallbackTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "regexp:("
            },
            out var invalidRegexIgnoredTag));
        Assert.Equal("direct", invalidRegexIgnoredTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_scoped_user_id_without_breaking_plain_user_id_rules()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("scoped-route", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "scoped-route",
                    userIds: ["trojan\u0000edge-in\u0000shared-user"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "shared-user",
                ScopedUserId = "trojan\u0000edge-in\u0000shared-user"
            },
            out var scopedTag));
        Assert.Equal("scoped-route", scopedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "shared-user",
                ScopedUserId = "trojan\u0000other-in\u0000shared-user"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_process_name_path_folder_and_self()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("process-route", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "process-route",
                    processes: [" curl.exe ", @" C:\Apps\svc.exe ", " /usr/bin/ ", " self/ "])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessName = "curl"
            },
            out var nameTag));
        Assert.Equal("process-route", nameTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessPath = @"C:\Apps\svc.exe"
            },
            out var pathTag));
        Assert.Equal("process-route", pathTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessPath = "/usr/bin/python3"
            },
            out var folderTag));
        Assert.Equal("process-route", folderTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessIsCurrentExecutable = true
            },
            out var selfTag));
        Assert.Equal("process-route", selfTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessName = "CURL"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_destination_source_and_local_cidrs()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("routed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "routed",
                    sourceCidrs: ["203.0.113.0/24"],
                    destinationCidrs: ["198.51.100.0/24"],
                    localCidrs: ["127.0.0.0/8"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10809),
                OriginalDestinationHost = "198.51.100.12"
            },
            out var matchedTag));
        Assert.Equal("routed", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Parse("10.0.0.5"), 10809),
                OriginalDestinationHost = "198.51.100.12"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_destination_source_and_local_ip_lists()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("routed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "routed",
                    sourceCidrs: ["203.0.113.0/24"],
                    destinationCidrs: ["198.51.100.0/24"],
                    localCidrs: ["127.0.0.0/8"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                OriginalDestinationHost = "api.example.com",
                TargetAddresses = [IPAddress.Parse("198.51.100.12")],
                SourceAddresses = [IPAddress.Parse("203.0.113.25")],
                LocalAddresses = [IPAddress.Loopback]
            },
            out var matchedTag));
        Assert.Equal("routed", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                OriginalDestinationHost = "api.example.com",
                TargetAddresses = [IPAddress.Parse("203.0.113.12")],
                SourceAddresses = [IPAddress.Parse("203.0.113.25")],
                LocalAddresses = [IPAddress.Loopback]
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_reverse_destination_cidr()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("not-us", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "not-us",
                    destinationCidrs: ["!203.0.113.0/24"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                TargetAddresses = [IPAddress.Parse("198.51.100.7")]
            },
            out var matchedTag));
        Assert.Equal("not-us", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                TargetAddresses = [IPAddress.Parse("203.0.113.7")]
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryResolveOutboundTag_matches_source_local_and_vless_route_ports()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("routed", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "routed",
                    sourcePorts: ["50000"],
                    localPorts: ["10808-10810"],
                    vlessRoutes: ["4360-4370"])
            ],
            [OutboundProtocols.Freedom],
            out var plan,
            out var error);

        Assert.True(success, error);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10809),
                VlessRoutePort = 4369
            },
            out var matchedTag));
        Assert.Equal("routed", matchedTag);

        Assert.True(plan.TryResolveOutboundTag(
            new DispatchContext
            {
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10809),
                VlessRoutePort = 5000
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryBuild_rejects_invalid_routing_source_cidr()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct",
                    sourceCidrs: ["203.0.113.0/99"])
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("source CIDR", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_invalid_routing_destination_cidr()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct",
                    destinationCidrs: ["198.51.100.0/99"])
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("destination CIDR", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_invalid_routing_domain_matcher()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct",
                    domains: ["regexp:("])
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("domain matcher", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_invalid_routing_port_matcher()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct",
                    destinationPorts: ["1000-10"])
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("port matcher", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_invalid_routing_attribute_matcher()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct",
                    attributes: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [":path"] = "["
                    })
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("attribute matcher", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_routing_rule_without_effective_fields()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom)
            ],
            [
                new TestRoutingRuleDefinition(
                    true,
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    Array.Empty<string>(),
                    "direct")
            ],
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("no effective fields", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_normalizes_strategy_outbound_settings()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestOutboundDefinition("backup", true, OutboundProtocols.Freedom),
                new TestStrategyOutboundDefinition(
                    "auto",
                    true,
                    "url-test",
                    [" direct ", "backup", "direct"],
                    selectedTag: " backup ",
                    probeUrl: " https://probe.example/test ",
                    probeIntervalSeconds: 30,
                    probeTimeoutSeconds: 7,
                    toleranceMilliseconds: 80)
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Freedom, OutboundProtocols.UrlTest],
            out var plan,
            out var error);

        Assert.True(success, error);
        Assert.True(plan.TryGetOutbound("auto", out var outbound));
        Assert.Equal(OutboundProtocols.UrlTest, outbound.Protocol);
        Assert.Equal(["direct", "backup"], outbound.CandidateTags);
        Assert.Equal("backup", outbound.SelectedTag);
        Assert.Equal("https://probe.example/test", outbound.ProbeUrl);
        Assert.Equal(30, outbound.ProbeIntervalSeconds);
        Assert.Equal(7, outbound.ProbeTimeoutSeconds);
        Assert.Equal(80, outbound.ToleranceMilliseconds);
    }

    [Fact]
    public void TryBuild_rejects_strategy_selected_tag_outside_candidates()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestStrategyOutboundDefinition(
                    "auto",
                    true,
                    OutboundProtocols.Selector,
                    ["direct"],
                    selectedTag: "backup")
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Freedom, OutboundProtocols.Selector],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("selected tag", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_unknown_strategy_candidate_tag()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("direct", true, OutboundProtocols.Freedom),
                new TestStrategyOutboundDefinition(
                    "auto",
                    true,
                    OutboundProtocols.Selector,
                    ["missing"])
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Freedom, OutboundProtocols.Selector],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("unknown candidate outbound tag", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_strategy_outbound_cycle()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestStrategyOutboundDefinition("first", true, OutboundProtocols.Selector, ["second"]),
                new TestStrategyOutboundDefinition("second", true, OutboundProtocols.Selector, ["first"])
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Selector],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("cycle", error, StringComparison.OrdinalIgnoreCase);
    }

    private sealed record TestOutboundDefinition(string Tag, bool Enabled, string Protocol) : IOutboundDefinition;

    private sealed class TestRoutingRuleDefinition : IRoutingRuleDefinition
    {
        public TestRoutingRuleDefinition(
            bool enabled,
            IReadOnlyList<string> inboundTags,
            IReadOnlyList<string> protocols,
            IReadOnlyList<string> networks,
            string outboundTag,
            IReadOnlyList<string>? userIds = null,
            IReadOnlyList<string>? processes = null,
            IReadOnlyList<string>? domains = null,
            IReadOnlyList<string>? sourceCidrs = null,
            IReadOnlyList<string>? destinationCidrs = null,
            IReadOnlyList<string>? destinationPorts = null,
            IReadOnlyList<string>? sourcePorts = null,
            IReadOnlyList<string>? localCidrs = null,
            IReadOnlyList<string>? localPorts = null,
            IReadOnlyList<string>? vlessRoutes = null,
            IReadOnlyDictionary<string, string>? attributes = null,
            string ruleTag = "")
        {
            Enabled = enabled;
            InboundTags = inboundTags;
            Protocols = protocols;
            Networks = networks;
            OutboundTag = outboundTag;
            RuleTag = ruleTag;
            UserIds = userIds ?? Array.Empty<string>();
            Processes = processes ?? Array.Empty<string>();
            Domains = domains ?? Array.Empty<string>();
            SourceCidrs = sourceCidrs ?? Array.Empty<string>();
            DestinationCidrs = destinationCidrs ?? Array.Empty<string>();
            DestinationPorts = destinationPorts ?? Array.Empty<string>();
            SourcePorts = sourcePorts ?? Array.Empty<string>();
            LocalCidrs = localCidrs ?? Array.Empty<string>();
            LocalPorts = localPorts ?? Array.Empty<string>();
            VlessRoutes = vlessRoutes ?? Array.Empty<string>();
            Attributes = attributes ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public bool Enabled { get; }

        public string RuleTag { get; }

        public IReadOnlyList<string> InboundTags { get; }

        public IReadOnlyList<string> Protocols { get; }

        public IReadOnlyList<string> Networks { get; }

        public IReadOnlyList<string> UserIds { get; }

        public IReadOnlyList<string> Processes { get; }

        public IReadOnlyList<string> Domains { get; }

        public IReadOnlyList<string> SourceCidrs { get; }

        public IReadOnlyList<string> DestinationCidrs { get; }

        public IReadOnlyList<string> DestinationPorts { get; }

        public IReadOnlyList<string> SourcePorts { get; }

        public IReadOnlyList<string> LocalCidrs { get; }

        public IReadOnlyList<string> LocalPorts { get; }

        public IReadOnlyList<string> VlessRoutes { get; }

        public IReadOnlyDictionary<string, string> Attributes { get; }

        public string OutboundTag { get; }
    }

    private sealed record TestSenderOutboundDefinition(
        string Tag,
        bool Enabled,
        string Protocol,
        string via = "",
        string viaCidr = "",
        string targetStrategy = "",
        string proxyOutboundTag = "",
        TestMultiplexDefinition? multiplexSettings = null)
        : IOutboundDefinition, IOutboundSenderDefinition
    {
        public string Via { get; } = via;

        public string ViaCidr { get; } = viaCidr;

        public string TargetStrategy { get; } = targetStrategy;

        public string ProxyOutboundTag { get; } = proxyOutboundTag;

        public IOutboundMultiplexDefinition GetMultiplexSettings() => multiplexSettings ?? TestMultiplexDefinition.Disabled;
    }

    private sealed record TestMultiplexDefinition(
        bool Enabled,
        int Concurrency,
        int XudpConcurrency,
        string XudpProxyUdp443) : IOutboundMultiplexDefinition
    {
        public static TestMultiplexDefinition Disabled { get; } =
            new(false, 0, 0, OutboundXudpProxyModes.Reject);
    }

    private sealed record TestStrategyOutboundDefinition(
        string Tag,
        bool Enabled,
        string Protocol,
        IReadOnlyList<string> candidateTags,
        string selectedTag = "",
        string probeUrl = "",
        int probeIntervalSeconds = 0,
        int probeTimeoutSeconds = 0,
        int toleranceMilliseconds = 0)
        : IOutboundDefinition, IStrategyOutboundDefinition
    {
        public IReadOnlyList<string> CandidateTags { get; } = candidateTags;

        public string SelectedTag { get; } = selectedTag;

        public string ProbeUrl { get; } = probeUrl;

        public int ProbeIntervalSeconds { get; } = probeIntervalSeconds;

        public int ProbeTimeoutSeconds { get; } = probeTimeoutSeconds;

        public int ToleranceMilliseconds { get; } = toleranceMilliseconds;
    }

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }

    private sealed class TestOutboundHandler : IOutboundHandler
    {
        public TestOutboundHandler(string protocol)
        {
            Protocol = protocol;
        }

        public string Protocol { get; }

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<Stream>(Stream.Null);

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<IOutboundUdpTransport>(new NullOutboundUdpTransport());
    }

    private sealed class NullOutboundUdpTransport : IOutboundUdpTransport
    {
        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;

        public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult<DispatchDatagram?>(null);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

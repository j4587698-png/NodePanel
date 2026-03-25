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

        Assert.Same(matchedHandler, resolved);
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
                    domains: ["*.example.com"],
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
                DetectedDomain = "example.com",
                OriginalDestinationHost = "example.com",
                OriginalDestinationPort = 8443,
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000)
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
            IReadOnlyList<string>? domains = null,
            IReadOnlyList<string>? sourceCidrs = null,
            IReadOnlyList<string>? destinationPorts = null)
        {
            Enabled = enabled;
            InboundTags = inboundTags;
            Protocols = protocols;
            Networks = networks;
            OutboundTag = outboundTag;
            UserIds = userIds ?? Array.Empty<string>();
            Domains = domains ?? Array.Empty<string>();
            SourceCidrs = sourceCidrs ?? Array.Empty<string>();
            DestinationPorts = destinationPorts ?? Array.Empty<string>();
        }

        public bool Enabled { get; }

        public IReadOnlyList<string> InboundTags { get; }

        public IReadOnlyList<string> Protocols { get; }

        public IReadOnlyList<string> Networks { get; }

        public IReadOnlyList<string> UserIds { get; }

        public IReadOnlyList<string> Domains { get; }

        public IReadOnlyList<string> SourceCidrs { get; }

        public IReadOnlyList<string> DestinationPorts { get; }

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

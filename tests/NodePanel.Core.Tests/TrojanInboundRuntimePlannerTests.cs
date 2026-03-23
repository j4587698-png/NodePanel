using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanInboundRuntimePlannerTests
{
    [Fact]
    public void TryBuild_supports_shared_tls_and_wss_binding()
    {
        var inbounds = new ITrojanInboundDefinition[]
        {
            new TestInboundDefinition
            {
                Tag = "trojan-tls",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = InboundTransports.Tls,
                ListenAddress = "0.0.0.0",
                Port = 18443,
                AcceptProxyProtocol = true
            },
            new TestInboundDefinition
            {
                Tag = "trojan-wss",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = InboundTransports.Wss,
                ListenAddress = "0.0.0.0",
                Port = 18443,
                AcceptProxyProtocol = true,
                Host = "edge.example.com",
                Path = "/ws"
            }
        };

        var result = TrojanInboundRuntimePlanner.TryBuild(inbounds, out var plan, out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.TlsListeners);
        Assert.True(listener.IsShared);
        Assert.True(plan.HasTcpTls);
        Assert.True(plan.HasWss);
        Assert.NotNull(listener.RawTlsInbound);
        Assert.NotNull(listener.WebSocketInbound);
        Assert.Equal(["http/1.1"], listener.ApplicationProtocols);
        Assert.Equal("edge.example.com", listener.WebSocketInbound!.Host);
        Assert.Equal("/ws", listener.WebSocketInbound.Path);
    }

    [Fact]
    public void TryBuild_limits_wss_application_protocols_to_http11()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-wss",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Wss,
                    ListenAddress = "0.0.0.0",
                    Port = 18443,
                    Path = "/ws",
                    ApplicationProtocols = [" h2 ", "http/1.1", "h3"]
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.TlsListeners);
        Assert.Equal(["http/1.1"], listener.ApplicationProtocols);
        Assert.Equal(["http/1.1"], listener.WebSocketInbound!.ApplicationProtocols);
    }

    [Fact]
    public void TryBuild_merges_explicit_and_fallback_application_protocols_per_listener()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Tls,
                    ListenAddress = "0.0.0.0",
                    Port = 18443,
                    ApplicationProtocols = [" h2 ", "http/1.1"],
                    Fallbacks =
                    [
                        new TestTrojanFallback
                        {
                            Alpn = "h3",
                            Dest = "127.0.0.1:7000"
                        }
                    ]
                },
                new TestInboundDefinition
                {
                    Tag = "trojan-wss",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Wss,
                    ListenAddress = "0.0.0.0",
                    Port = 18443,
                    Path = "/ws"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.TlsListeners);
        Assert.Equal(["http/1.1", "h2", "h3"], listener.ApplicationProtocols);
        Assert.Equal(["h2", "http/1.1"], listener.RawTlsInbound!.ApplicationProtocols);
    }

    [Fact]
    public void SelectInbound_prefers_wss_when_http_path_matches()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Tls,
                    ListenAddress = "0.0.0.0",
                    Port = 18443
                },
                new TestInboundDefinition
                {
                    Tag = "trojan-wss",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Wss,
                    ListenAddress = "0.0.0.0",
                    Port = 18443,
                    Path = "ws"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.TlsListeners);

        var wssInbound = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("GET /ws HTTP/1.1\r\nHost: edge.example.com\r\n\r\n"));
        var tlsInbound = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("not-http"));

        Assert.NotNull(wssInbound);
        Assert.NotNull(tlsInbound);
        Assert.Equal(InboundTransports.Wss, wssInbound!.Transport);
        Assert.Equal(InboundTransports.Tls, tlsInbound!.Transport);
    }

    private sealed record TestInboundDefinition : ITrojanInboundDefinition, ITrojanInboundScopeDefinition
    {
        public string Tag { get; init; } = string.Empty;

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Trojan;

        public string Transport { get; init; } = InboundTransports.Tls;

        public string ListenAddress { get; init; } = "0.0.0.0";

        public int Port { get; init; } = 443;

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public bool ReceiveOriginalDestination { get; init; }

        public ITrojanSniffingDefinition Sniffing { get; init; } = new TrojanSniffingRuntime();

        public IReadOnlyList<ITrojanUserDefinition> Users { get; init; } = Array.Empty<ITrojanUserDefinition>();

        public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks { get; init; } = Array.Empty<ITrojanFallbackDefinition>();

        public IReadOnlyList<ITrojanUserDefinition> GetUsers() => Users;

        public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Fallbacks;

        public ITrojanSniffingDefinition GetSniffing() => Sniffing;

        public bool GetReceiveOriginalDestination() => ReceiveOriginalDestination;
    }
}

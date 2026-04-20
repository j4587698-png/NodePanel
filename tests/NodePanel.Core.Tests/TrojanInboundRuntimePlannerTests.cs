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
    public void TryBuild_supports_explicit_transport_protocol_and_security()
    {
        var inbounds = new ITrojanInboundDefinition[]
        {
            new TestInboundDefinition
            {
                Tag = "trojan-tls",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "127.0.0.1",
                Port = 18443
            },
            new TestInboundDefinition
            {
                Tag = "trojan-wss",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Ws,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "127.0.0.1",
                Port = 18443,
                Host = "edge.example.com",
                Path = "/ws"
            }
        };

        var result = TrojanInboundRuntimePlanner.TryBuild(inbounds, out var plan, out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.Listeners);
        Assert.Equal(2, listener.Inbounds.Count);
        Assert.Equal(InboundTransports.Tls, listener.RawTlsInbound!.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, listener.RawTlsInbound.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, listener.RawTlsInbound.SecurityType);
        Assert.Equal(InboundTransports.Wss, listener.WebSocketInbound!.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Ws, listener.WebSocketInbound.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, listener.WebSocketInbound.SecurityType);
    }

    [Fact]
    public void TryBuild_supports_plain_tcp_without_tls_or_reality()
    {
        var inbounds = new ITrojanInboundDefinition[]
        {
            new TestInboundDefinition
            {
                Tag = "trojan-plain",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.None,
                ListenAddress = "127.0.0.1",
                Port = 18080
            }
        };

        var result = TrojanInboundRuntimePlanner.TryBuild(inbounds, out var plan, out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.PlainListeners);
        Assert.Single(plan.Listeners);
        Assert.Empty(plan.TlsListeners);
        Assert.Empty(plan.RealityListeners);
        Assert.NotNull(listener.RawTlsInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, listener.RawTlsInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, listener.RawTlsInbound.SecurityType);
    }

    [Fact]
    public void TryBuild_supports_plain_mkcp_without_tls_or_reality()
    {
        var inbounds = new ITrojanInboundDefinition[]
        {
            new TestInboundDefinition
            {
                Tag = "trojan-mkcp",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Mkcp,
                TransportSecurity = RuntimeInternetSecurityTypes.None,
                ListenAddress = "127.0.0.1",
                Port = 18081
            }
        };

        var result = TrojanInboundRuntimePlanner.TryBuild(inbounds, out var plan, out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.PlainListeners);
        Assert.NotNull(listener.MkcpInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.Mkcp, listener.MkcpInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, listener.MkcpInbound.SecurityType);
    }

    [Fact]
    public void TryBuild_rejects_shared_mkcp_binding_with_tcp_transport()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-mkcp",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Mkcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 18081
                },
                new TestInboundDefinition
                {
                    Tag = "trojan-tcp",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 18081
                }
            },
            out _,
            out var error);

        Assert.False(result);
        Assert.Contains("cannot share mKCP", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("ws", " edge.example.com ", "plain-ws")]
    [InlineData("httpupgrade", " edge.example.com ", "plain-upgrade")]
    public void TryBuild_supports_plain_http11_transports_without_requiring_certificate(
        string transportProtocol,
        string host,
        string path)
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-plain-http11",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = transportProtocol,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 18080,
                    Host = host,
                    Path = path
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.PlainListeners);
        Assert.Single(plan.Listeners);
        Assert.Empty(plan.TlsListeners);
        Assert.Empty(plan.RealityListeners);
        Assert.Empty(listener.ApplicationProtocols);

        var inbound = string.Equals(transportProtocol, RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal)
            ? listener.WebSocketInbound
            : listener.HttpUpgradeInbound;
        Assert.NotNull(inbound);
        Assert.Equal(transportProtocol, inbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, inbound.SecurityType);
        Assert.Equal("edge.example.com", inbound.Host);
        Assert.Equal("/" + path, inbound.Path);
        Assert.Equal(["http/1.1"], inbound.ApplicationProtocols);
    }

    [Fact]
    public void TryBuild_supports_plain_grpc_binding_without_requiring_certificate()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-plain-grpc",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 18081,
                    GrpcServiceName = "/trojan/plain/Tun|TunMulti"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.PlainListeners);
        Assert.Single(plan.Listeners);
        Assert.Empty(plan.TlsListeners);
        Assert.Empty(plan.RealityListeners);
        Assert.Empty(listener.ApplicationProtocols);
        Assert.NotNull(listener.GrpcInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.Grpc, listener.GrpcInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, listener.GrpcInbound.SecurityType);
        Assert.Equal("/trojan/plain/Tun|TunMulti", listener.GrpcInbound.Grpc.ServiceName);
        Assert.Equal(["h2"], listener.GrpcInbound.ApplicationProtocols);

        var selected = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));

        Assert.NotNull(selected);
        Assert.Equal(RuntimeInternetTransportProtocols.Grpc, selected!.TransportProtocol);
    }

    [Fact]
    public void TryBuild_supports_plain_splithttp_binding_without_requiring_certificate()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-plain-xhttp",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 18082,
                    Host = " edge.example.com ",
                    Path = "xhttp"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.PlainListeners);
        Assert.Single(plan.Listeners);
        Assert.Empty(plan.TlsListeners);
        Assert.Empty(plan.RealityListeners);
        Assert.Empty(listener.ApplicationProtocols);
        Assert.NotNull(listener.SplitHttpInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.SplitHttp, listener.SplitHttpInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, listener.SplitHttpInbound.SecurityType);
        Assert.Equal("edge.example.com", listener.SplitHttpInbound.Host);
        Assert.Equal("/xhttp/", listener.SplitHttpInbound.Path);
        Assert.Equal(["http/1.1", "h2"], listener.SplitHttpInbound.ApplicationProtocols);

        var selected = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("GET /xhttp/session-1 HTTP/1.1\r\nHost: edge.example.com\r\n\r\n"));

        Assert.NotNull(selected);
        Assert.Equal(RuntimeInternetTransportProtocols.SplitHttp, selected!.TransportProtocol);
    }

    [Fact]
    public void TryBuild_supports_grpc_tls_binding_and_selects_grpc_by_http2_preface()
    {
        var inbounds = new ITrojanInboundDefinition[]
        {
            new TestInboundDefinition
            {
                Tag = "trojan-tls",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "127.0.0.1",
                Port = 18443
            },
            new TestInboundDefinition
            {
                Tag = "trojan-grpc",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "127.0.0.1",
                Port = 18443,
                GrpcServiceName = "/trojan/service/Tun|TunMulti"
            }
        };

        var result = TrojanInboundRuntimePlanner.TryBuild(inbounds, out var plan, out var error);

        Assert.True(result, error);
        Assert.True(plan.HasTcpTls);
        Assert.True(plan.HasGrpc);

        var listener = Assert.Single(plan.Listeners);
        Assert.Equal(["h2"], listener.ApplicationProtocols);
        Assert.NotNull(listener.RawTlsInbound);
        Assert.NotNull(listener.GrpcInbound);
        Assert.Equal("/trojan/service/Tun|TunMulti", listener.GrpcInbound!.Grpc.ServiceName);
        Assert.Equal(["h2"], listener.GrpcInbound.ApplicationProtocols);

        var selected = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));

        Assert.NotNull(selected);
        Assert.Equal(InboundTransports.Grpc, selected!.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Grpc, selected.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, selected.SecurityType);
    }

    [Fact]
    public void TryBuild_supports_splithttp_tls_binding_and_selects_by_http_path_prefix()
    {
        var inbounds = new ITrojanInboundDefinition[]
        {
            new TestInboundDefinition
            {
                Tag = "trojan-tls",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "127.0.0.1",
                Port = 18443
            },
            new TestInboundDefinition
            {
                Tag = "trojan-xhttp",
                Enabled = true,
                Protocol = InboundProtocols.Trojan,
                Transport = string.Empty,
                TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "127.0.0.1",
                Port = 18443,
                Host = " edge.example.com ",
                Path = "xhttp",
                SplitHttpMode = " STREAM-UP ",
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 24,
                    To = 8
                },
                SplitHttpXPaddingObfsMode = true,
                SplitHttpXPaddingKey = " pad ",
                SplitHttpXPaddingHeader = " X-Noise ",
                SplitHttpXPaddingPlacement = " QueryInHeader ",
                SplitHttpXPaddingMethod = " Tokenish ",
                SplitHttpSessionPlacement = " Query ",
                SplitHttpSeqPlacement = " Header ",
                SplitHttpUplinkDataPlacement = " Cookie ",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 64,
                    To = 32
                },
                SplitHttpScMaxBufferedPosts = -3,
                SplitHttpScStreamUpServerSecs = new RuntimeInt32Range
                {
                    From = 40,
                    To = 20
                },
                SplitHttpServerMaxHeaderBytes = 16384
            }
        };

        var result = TrojanInboundRuntimePlanner.TryBuild(inbounds, out var plan, out var error);

        Assert.True(result, error);
        Assert.True(plan.HasTcpTls);
        Assert.True(plan.HasSplitHttp);

        var listener = Assert.Single(plan.Listeners);
        Assert.Equal(["http/1.1", "h2"], listener.ApplicationProtocols);
        Assert.NotNull(listener.RawTlsInbound);
        Assert.NotNull(listener.SplitHttpInbound);
        Assert.Equal("/xhttp/", listener.SplitHttpInbound!.Path);
        Assert.Equal("edge.example.com", listener.SplitHttpInbound.Host);
        Assert.Equal("stream-up", listener.SplitHttpInbound.SplitHttp.Mode);
        Assert.Equal("query", listener.SplitHttpInbound.SplitHttp.SessionPlacement);
        Assert.Equal("x_session", listener.SplitHttpInbound.SplitHttp.SessionKey);
        Assert.Equal("header", listener.SplitHttpInbound.SplitHttp.SeqPlacement);
        Assert.Equal("X-Seq", listener.SplitHttpInbound.SplitHttp.SeqKey);
        Assert.Equal("cookie", listener.SplitHttpInbound.SplitHttp.UplinkDataPlacement);
        Assert.Equal("x_data", listener.SplitHttpInbound.SplitHttp.UplinkDataKey);
        Assert.True(listener.SplitHttpInbound.SplitHttp.XPaddingObfsMode);
        Assert.Equal("pad", listener.SplitHttpInbound.SplitHttp.XPaddingKey);
        Assert.Equal("X-Noise", listener.SplitHttpInbound.SplitHttp.XPaddingHeader);
        Assert.Equal("queryInHeader", listener.SplitHttpInbound.SplitHttp.XPaddingPlacement);
        Assert.Equal("tokenish", listener.SplitHttpInbound.SplitHttp.XPaddingMethod);
        Assert.Equal(8, listener.SplitHttpInbound.SplitHttp.XPaddingBytes.From);
        Assert.Equal(24, listener.SplitHttpInbound.SplitHttp.XPaddingBytes.To);
        Assert.Equal(32, listener.SplitHttpInbound.SplitHttp.ScMaxEachPostBytes.From);
        Assert.Equal(64, listener.SplitHttpInbound.SplitHttp.ScMaxEachPostBytes.To);
        Assert.Equal(0, listener.SplitHttpInbound.SplitHttp.ScMaxBufferedPosts);
        Assert.Equal(20, listener.SplitHttpInbound.SplitHttp.ScStreamUpServerSecs.From);
        Assert.Equal(40, listener.SplitHttpInbound.SplitHttp.ScStreamUpServerSecs.To);
        Assert.Equal(16384, listener.SplitHttpInbound.SplitHttp.ServerMaxHeaderBytes);

        var splitHttpInbound = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("GET /xhttp/session-1 HTTP/1.1\r\nHost: edge.example.com\r\n\r\n"));
        var rawTlsInbound = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("not-http"));

        Assert.NotNull(splitHttpInbound);
        Assert.NotNull(rawTlsInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.SplitHttp, splitHttpInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, rawTlsInbound!.TransportProtocol);
    }

    [Fact]
    public void SelectInbound_prefers_splithttp_for_http2_requests_when_path_matches()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-grpc",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 3443,
                    GrpcServiceName = "/trojan/service/Tun|TunMulti"
                },
                new TestInboundDefinition
                {
                    Tag = "trojan-xhttp",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 3443,
                    Path = "xhttp"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.Listeners);

        var selected = TrojanInboundRuntimePlanner.SelectInbound(
            listener,
            Http2InitialPayloadTestBuilder.BuildRequestInitialPayload(
                method: "GET",
                path: "/xhttp/?x_padding=X"));

        Assert.NotNull(selected);
        Assert.Equal(InboundTransports.SplitHttp, selected!.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.SplitHttp, selected.TransportProtocol);
    }

    [Fact]
    public void TryBuild_supports_splithttp_h3_only_listener_application_protocols()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-xhttp-h3",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 19443,
                    Path = "xhttp",
                    ApplicationProtocols = [" h3 "],
                    QuicOptions = new RuntimeQuicOptions
                    {
                        Congestion = " reNo ",
                        BrutalUp = -1,
                        UdpHop = new RuntimeUdpHopOptions
                        {
                            Ports = [443, 443, -1, 8443, 65_536],
                            IntervalMinSeconds = -5,
                            IntervalMaxSeconds = 9
                        },
                        InitStreamReceiveWindow = -2,
                        MaxStreamReceiveWindow = 16_384,
                        MaxIdleTimeoutSeconds = -3,
                        KeepAlivePeriodSeconds = 7,
                        MaxIncomingStreams = -4
                    }
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.Listeners);
        Assert.Equal(["h3"], listener.ApplicationProtocols);
        Assert.Equal(["h3"], listener.SplitHttpInbound!.ApplicationProtocols);
        Assert.Equal("reno", listener.SplitHttpInbound.QuicOptions.Congestion);
        Assert.Equal(0, listener.SplitHttpInbound.QuicOptions.BrutalUp);
        Assert.Equal([443, 8443], listener.SplitHttpInbound.QuicOptions.UdpHop.Ports);
        Assert.Equal(0, listener.SplitHttpInbound.QuicOptions.UdpHop.IntervalMinSeconds);
        Assert.Equal(9, listener.SplitHttpInbound.QuicOptions.UdpHop.IntervalMaxSeconds);
        Assert.Equal(0, listener.SplitHttpInbound.QuicOptions.InitStreamReceiveWindow);
        Assert.Equal(16_384, listener.SplitHttpInbound.QuicOptions.MaxStreamReceiveWindow);
        Assert.Equal(0, listener.SplitHttpInbound.QuicOptions.MaxIdleTimeoutSeconds);
        Assert.Equal(7, listener.SplitHttpInbound.QuicOptions.KeepAlivePeriodSeconds);
        Assert.Equal(0, listener.SplitHttpInbound.QuicOptions.MaxIncomingStreams);
    }

    [Fact]
    public void TryBuild_rejects_splithttp_h3_only_shared_binding_with_tcp_transports()
    {
        var result = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "trojan-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 19443
                },
                new TestInboundDefinition
                {
                    Tag = "trojan-xhttp-h3",
                    Enabled = true,
                    Protocol = InboundProtocols.Trojan,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 19443,
                    Path = "xhttp",
                    ApplicationProtocols = ["h3"]
                }
            },
            out _,
            out var error);

        Assert.False(result);
        Assert.Contains("mixes SplitHTTP h3-only with TCP-based transports", error, StringComparison.Ordinal);
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

    private sealed record TestInboundDefinition
        : ITrojanInboundDefinition,
          ITrojanInboundScopeDefinition,
          IInboundInternetDefinition,
          IInboundGrpcDefinition,
          IInboundSplitHttpDefinition,
          IInboundQuicDefinition
    {
        public string Tag { get; init; } = string.Empty;

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Trojan;

        public string Transport { get; init; } = InboundTransports.Tls;

        public string TransportProtocol { get; init; } = string.Empty;

        public string TransportSecurity { get; init; } = string.Empty;

        public string ListenAddress { get; init; } = "0.0.0.0";

        public int Port { get; init; } = 443;

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoSseHeader { get; init; }

        public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode { get; init; }

        public string SplitHttpXPaddingKey { get; init; } = string.Empty;

        public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

        public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

        public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

        public string SplitHttpSessionPlacement { get; init; } = string.Empty;

        public string SplitHttpSessionKey { get; init; } = string.Empty;

        public string SplitHttpSeqPlacement { get; init; } = string.Empty;

        public string SplitHttpSeqKey { get; init; } = string.Empty;

        public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

        public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts { get; init; }

        public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpServerMaxHeaderBytes { get; init; }

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public bool ReceiveOriginalDestination { get; init; }

        public IRuntimeSniffingDefinition Sniffing { get; init; } = new RuntimeSniffingOptions();

        public IReadOnlyList<ITrojanUserDefinition> Users { get; init; } = Array.Empty<ITrojanUserDefinition>();

        public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks { get; init; } = Array.Empty<ITrojanFallbackDefinition>();

        public IReadOnlyList<ITrojanUserDefinition> GetUsers() => Users;

        public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Fallbacks;

        public IRuntimeSniffingDefinition GetSniffing() => Sniffing;

        public bool GetReceiveOriginalDestination() => ReceiveOriginalDestination;
    }
}

using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessInboundRuntimePlannerTests
{
    [Fact]
    public void TryBuild_supports_grpc_tls_binding_and_selects_grpc_by_http2_preface()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 2443
                },
                new TestInboundDefinition
                {
                    Tag = "vless-grpc",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 2443,
                    GrpcServiceName = "/vless/service/Tun|TunMulti"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        Assert.True(plan.HasTcpTls);
        Assert.True(plan.HasGrpc);

        var listener = Assert.Single(plan.Listeners);
        Assert.Equal(["h2"], listener.ApplicationProtocols);
        Assert.NotNull(listener.RawTlsInbound);
        Assert.NotNull(listener.GrpcInbound);
        Assert.Equal("/vless/service/Tun|TunMulti", listener.GrpcInbound!.Grpc.ServiceName);
        Assert.Equal(["h2"], listener.GrpcInbound.ApplicationProtocols);

        var selected = VlessInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));

        Assert.NotNull(selected);
        Assert.Equal(InboundTransports.Grpc, selected!.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Grpc, selected.TransportProtocol);
    }

    [Fact]
    public void TryBuild_supports_splithttp_tls_binding_and_selects_by_http_path_prefix()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 2443
                },
                new TestInboundDefinition
                {
                    Tag = "vless-xhttp",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 2443,
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
            },
            out var plan,
            out var error);

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

        var splitHttpInbound = VlessInboundRuntimePlanner.SelectInbound(
            listener,
            Encoding.ASCII.GetBytes("GET /xhttp/session-1 HTTP/1.1\r\nHost: edge.example.com\r\n\r\n"));
        var rawTlsInbound = VlessInboundRuntimePlanner.SelectInbound(
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
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-grpc",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 3443,
                    GrpcServiceName = "/vless/service/Tun|TunMulti"
                },
                new TestInboundDefinition
                {
                    Tag = "vless-xhttp",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
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

        var selected = VlessInboundRuntimePlanner.SelectInbound(
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
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-xhttp-h3",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 25443,
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
    public void TryBuild_supports_plain_tcp_binding_without_requiring_certificate()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-plain",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 2080
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        Assert.False(plan.RequiresCertificate);
        Assert.Empty(plan.TlsListeners);

        var listener = Assert.Single(plan.PlainListeners);
        Assert.Empty(listener.ApplicationProtocols);
        Assert.NotNull(listener.RawTlsInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, listener.RawTlsInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, listener.RawTlsInbound.SecurityType);
    }

    [Fact]
    public void TryBuild_supports_plain_mkcp_binding_without_requiring_certificate()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-mkcp",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Mkcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 2081
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.PlainListeners);
        Assert.NotNull(listener.MkcpInbound);
        Assert.Equal(RuntimeInternetTransportProtocols.Mkcp, listener.MkcpInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, listener.MkcpInbound.SecurityType);
    }

    [Fact]
    public void TryBuild_rejects_shared_mkcp_binding_with_tcp_transport()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-mkcp",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Mkcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 2081
                },
                new TestInboundDefinition
                {
                    Tag = "vless-tcp",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 2081
                }
            },
            out _,
            out var error);

        Assert.False(result);
        Assert.Contains("cannot share mKCP", error, StringComparison.Ordinal);
    }

    [Fact]
    public void TryBuild_merges_fallback_alpn_into_listener_application_protocols()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 2443,
                    Fallbacks =
                    [
                        new TestTrojanFallback
                        {
                            Alpn = " h2 ",
                            Path = " health ",
                            Dest = "127.0.0.1:8080"
                        }
                    ]
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.Listeners);
        Assert.Equal(["h2"], listener.ApplicationProtocols);

        var inbound = Assert.Single(listener.Inbounds);
        var fallback = Assert.Single(inbound.Fallbacks);
        Assert.Equal("h2", fallback.Alpn);
        Assert.Equal("/health", fallback.Path);
        Assert.Equal("127.0.0.1:8080", fallback.Dest);
    }

    [Fact]
    public void TryBuild_rejects_splithttp_h3_only_shared_binding_with_tcp_transports()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 25443
                },
                new TestInboundDefinition
                {
                    Tag = "vless-xhttp-h3",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 25443,
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
    public void TryBuild_rejects_shared_binding_that_mixes_plain_and_tls_security()
    {
        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-plain",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    ListenAddress = "127.0.0.1",
                    Port = 2443
                },
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Ws,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 2443,
                    Path = "/ws"
                }
            },
            out _,
            out var error);

        Assert.False(result);
        Assert.Contains("mixes none/tls/reality security", error, StringComparison.Ordinal);
    }

    [Fact]
    public void TryBuild_carries_transport_decryption_settings()
    {
        using var keyPair = RuntimeX25519.CreateKeyPair();

        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 5443,
                    Decryption = EncodeBase64Url(keyPair.PrivateKey),
                    XorMode = 2,
                    SecondsFrom = 30,
                    SecondsTo = 90,
                    Padding = "100-111-1111.75-0-111"
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.Listeners);
        var inbound = listener.RawTlsInbound;
        Assert.NotNull(inbound);
        Assert.Equal(EncodeBase64Url(keyPair.PrivateKey), inbound!.Decryption);
        Assert.Equal(2u, inbound.XorMode);
        Assert.Equal(30, inbound.SecondsFrom);
        Assert.Equal(90, inbound.SecondsTo);
        Assert.Equal("100-111-1111.75-0-111", inbound.Padding);
    }

    [Fact]
    public void TryBuild_rejects_transport_decryption_with_fallbacks()
    {
        using var keyPair = RuntimeX25519.CreateKeyPair();

        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 6443,
                    Decryption = EncodeBase64Url(keyPair.PrivateKey),
                    Fallbacks =
                    [
                        new TrojanFallbackRuntime
                        {
                            Dest = "127.0.0.1:8080"
                        }
                    ]
                }
            },
            out _,
            out var error);

        Assert.False(result);
        Assert.Contains("cannot be used together with fallbacks", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_carries_reverse_tag_into_runtime_users()
    {
        const string uuid = "11111111-1111-1111-1111-111111111111";

        var result = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                new TestInboundDefinition
                {
                    Tag = "vless-tls",
                    Enabled = true,
                    Protocol = InboundProtocols.Vless,
                    Transport = string.Empty,
                    TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 7443,
                    Users =
                    [
                        new TestVlessUserDefinition
                        {
                            UserId = "user-a",
                            Uuid = uuid,
                            ReverseTag = " reverse-edge "
                        }
                    ]
                }
            },
            out var plan,
            out var error);

        Assert.True(result, error);
        var listener = Assert.Single(plan.Listeners);
        var inbound = Assert.Single(listener.Inbounds);
        Assert.True(inbound.UsersByUuid.TryGetValue(uuid, out var user));
        Assert.Equal("reverse-edge", user!.ReverseTag);
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed record TestInboundDefinition
        : IVlessInboundDefinition,
          IVlessInboundScopeDefinition,
          IInboundInternetDefinition,
          IInboundGrpcDefinition,
          IInboundSplitHttpDefinition,
          IInboundQuicDefinition
    {
        public string Tag { get; init; } = string.Empty;

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Vless;

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

        public IReadOnlyList<IVlessUserDefinition> Users { get; init; } = Array.Empty<IVlessUserDefinition>();

        public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks { get; init; } = Array.Empty<ITrojanFallbackDefinition>();

        public string Flow { get; init; } = string.Empty;

        public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

        public string Decryption { get; init; } = string.Empty;

        public uint XorMode { get; init; }

        public int SecondsFrom { get; init; }

        public int SecondsTo { get; init; }

        public string Padding { get; init; } = string.Empty;

        public IReadOnlyList<IVlessUserDefinition> GetVlessUsers() => Users;

        public string GetVlessFlow() => Flow;

        public IReadOnlyList<uint> GetVlessTestSeed() => TestSeed;

        public string GetVlessDecryption() => Decryption;

        public uint GetVlessXorMode() => XorMode;

        public int GetVlessSecondsFrom() => SecondsFrom;

        public int GetVlessSecondsTo() => SecondsTo;

        public string GetVlessPadding() => Padding;

        public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Fallbacks;

        public IRuntimeSniffingDefinition GetSniffing() => Sniffing;

        public bool GetReceiveOriginalDestination() => ReceiveOriginalDestination;
    }

    private sealed record TestVlessUserDefinition : IVlessUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Uuid { get; init; } = string.Empty;

        public string Flow { get; init; } = string.Empty;

        public string ReverseTag { get; init; } = string.Empty;

        public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }
}

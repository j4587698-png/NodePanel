using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ProxyOutboundOptionsCompilerTests
{
    [Fact]
    public void Compile_trojan_canonicalizes_transport_headers_and_timeouts()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = " trojan-edge ",
                ServerHost = " edge.example.com ",
                ServerPort = 443,
                ServerName = " tls.example.com ",
                Transport = " WSS ",
                WebSocketPath = " websocket ",
                WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [" Host "] = " edge.example.com ",
                    [" "] = "ignored"
                },
                ApplicationProtocols = [" h2 "],
                Password = " secret ",
                ConnectTimeoutSeconds = -1,
                HandshakeTimeoutSeconds = 15
            });

        Assert.Equal("trojan-edge", compiled.Tag);
        Assert.Equal("edge.example.com", compiled.ServerHost);
        Assert.Equal("tls.example.com", compiled.ServerName);
        Assert.Equal(TrojanOutboundTransports.Wss, compiled.Transport);
        Assert.Equal("/websocket", compiled.WebSocketPath);
        Assert.Equal("edge.example.com", compiled.WebSocketHeaders["Host"]);
        Assert.Equal(["http/1.1"], compiled.ApplicationProtocols);
        Assert.Equal("secret", compiled.Password);
        Assert.Equal(0, compiled.ConnectTimeoutSeconds);
        Assert.Equal(15, compiled.HandshakeTimeoutSeconds);
    }

    [Fact]
    public void Compile_trojan_grpc_transport_forces_h2_and_normalizes_grpc_fields()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-grpc",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = " GRPC ",
                ApplicationProtocols = ["http/1.1"],
                GrpcServiceName = " /my service/tun|multi ",
                GrpcAuthority = " grpc.example.com ",
                GrpcMultiMode = true,
                GrpcUserAgent = " TestGrpc/1.0 ",
                GrpcIdleTimeoutSeconds = -5,
                GrpcHealthCheckTimeoutSeconds = 7,
                GrpcPermitWithoutStream = true,
                GrpcInitialWindowSize = -64,
                Password = "secret"
            });

        Assert.Equal(TrojanOutboundTransports.Grpc, compiled.Transport);
        Assert.Equal(["h2"], compiled.ApplicationProtocols);
        Assert.Equal("/my service/tun|multi", compiled.GrpcServiceName);
        Assert.Equal("grpc.example.com", compiled.GrpcAuthority);
        Assert.True(compiled.GrpcMultiMode);
        Assert.Equal("TestGrpc/1.0", compiled.GrpcUserAgent);
        Assert.Equal(0, compiled.GrpcIdleTimeoutSeconds);
        Assert.Equal(7, compiled.GrpcHealthCheckTimeoutSeconds);
        Assert.True(compiled.GrpcPermitWithoutStream);
        Assert.Equal(0, compiled.GrpcInitialWindowSize);
    }

    [Fact]
    public void Compile_trojan_non_grpc_transport_clears_grpc_advanced_fields()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-ws",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.Ws,
                GrpcIdleTimeoutSeconds = 5,
                GrpcHealthCheckTimeoutSeconds = 6,
                GrpcPermitWithoutStream = true,
                GrpcInitialWindowSize = 131_072,
                Password = "secret"
            });

        Assert.Equal(TrojanOutboundTransports.Ws, compiled.Transport);
        Assert.Equal(0, compiled.GrpcIdleTimeoutSeconds);
        Assert.Equal(0, compiled.GrpcHealthCheckTimeoutSeconds);
        Assert.False(compiled.GrpcPermitWithoutStream);
        Assert.Equal(0, compiled.GrpcInitialWindowSize);
    }

    [Fact]
    public void Compile_trojan_httpupgrade_preserves_host_path_and_headers()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-httpupgrade",
                ServerHost = "127.0.0.1",
                ServerPort = 80,
                Transport = " HTTPUPGRADE ",
                SplitHttpHost = " edge.example.com ",
                SplitHttpPath = " upgrade ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [" User-Agent "] = " TestUpgrade/1.0 ",
                    [" X-Test "] = " value "
                },
                Password = "secret"
            });

        Assert.Equal(TrojanOutboundTransports.HttpUpgrade, compiled.Transport);
        Assert.Equal("edge.example.com", compiled.SplitHttpHost);
        Assert.Equal("/upgrade", compiled.SplitHttpPath);
        Assert.Equal("TestUpgrade/1.0", compiled.SplitHttpHeaders["User-Agent"]);
        Assert.Equal("value", compiled.SplitHttpHeaders["X-Test"]);
        Assert.Empty(compiled.ApplicationProtocols);
    }

    [Fact]
    public void Compile_trojan_splithttp_alias_defaults_mode_to_auto_and_normalizes_path()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-xhttp",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = " XHTTP ",
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                SplitHttpPath = " tunnel?route=1 ",
                Password = "secret"
            });

        Assert.Equal(TrojanOutboundTransports.SplitHttp, compiled.Transport);
        Assert.Equal("/tunnel/?route=1", compiled.SplitHttpPath);
        Assert.Equal("auto", compiled.SplitHttpMode);
        Assert.Equal("POST", compiled.SplitHttpUplinkHttpMethod);
        Assert.Equal("auto", compiled.SplitHttpUplinkDataPlacement);
        Assert.Equal("X-Data", compiled.SplitHttpUplinkDataKey);
        Assert.Equal("path", compiled.SplitHttpSessionPlacement);
        Assert.Equal(string.Empty, compiled.SplitHttpSessionKey);
        Assert.Equal(["h2", "http/1.1"], compiled.ApplicationProtocols);
    }

    [Fact]
    public void Compile_trojan_splithttp_preserves_explicit_application_protocols()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-xhttp-h2",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ApplicationProtocols = [" h2 ", " http/1.1 "],
                Password = "secret"
            });

        Assert.Equal(["h2", "http/1.1"], compiled.ApplicationProtocols);
    }

    [Fact]
    public void Compile_trojan_splithttp_preserves_supported_explicit_mode_and_query_session_defaults()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-stream-one",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = " STREAM-ONE ",
                SplitHttpSessionPlacement = " Query ",
                SplitHttpPath = " split ",
                Password = "secret"
            });

        Assert.Equal(TrojanOutboundTransports.SplitHttp, compiled.Transport);
        Assert.Equal("stream-one", compiled.SplitHttpMode);
        Assert.Equal("query", compiled.SplitHttpSessionPlacement);
        Assert.Equal("x_session", compiled.SplitHttpSessionKey);
        Assert.Equal("/split/", compiled.SplitHttpPath);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_seq_defaults_and_custom_key_placement()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-seq",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = " header ",
                Password = "secret"
            });

        Assert.Equal("packet-up", compiled.SplitHttpMode);
        Assert.Equal("header", compiled.SplitHttpSeqPlacement);
        Assert.Equal("X-Seq", compiled.SplitHttpSeqKey);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_header_uplink_data_defaults()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-uplink-header",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = " header ",
                Password = "secret"
            });

        Assert.Equal("packet-up", compiled.SplitHttpMode);
        Assert.Equal("header", compiled.SplitHttpUplinkDataPlacement);
        Assert.Equal("X-Data", compiled.SplitHttpUplinkDataKey);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_cookie_uplink_data_key_default()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-uplink-cookie",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = "cookie",
                Password = "secret"
            });

        Assert.Equal("cookie", compiled.SplitHttpUplinkDataPlacement);
        Assert.Equal("x_data", compiled.SplitHttpUplinkDataKey);
    }

    [Fact]
    public void Compile_trojan_splithttp_preserves_empty_uplink_chunk_size_for_runtime_defaults()
    {
        var headerCompiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-header-chunk-default",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = "header",
                Password = "secret"
            });
        var cookieCompiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-cookie-chunk-default",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = "cookie",
                Password = "secret"
            });
        var bodyCompiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-body-chunk-default",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 16,
                    To = 32
                },
                Password = "secret"
            });

        Assert.Equal(RuntimeInt32Range.Empty, headerCompiled.SplitHttpUplinkChunkSize);
        Assert.Equal(RuntimeInt32Range.Empty, cookieCompiled.SplitHttpUplinkChunkSize);
        Assert.Equal(RuntimeInt32Range.Empty, bodyCompiled.SplitHttpUplinkChunkSize);
    }

    [Fact]
    public void Compile_trojan_splithttp_preserves_explicit_uplink_chunk_size_for_runtime_normalization()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-uplink-chunk-min",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = "header",
                SplitHttpUplinkChunkSize = new RuntimeInt32Range
                {
                    From = 8,
                    To = 48
                },
                Password = "secret"
            });

        Assert.Equal(8, compiled.SplitHttpUplinkChunkSize.From);
        Assert.Equal(48, compiled.SplitHttpUplinkChunkSize.To);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_xpadding_defaults()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xpadding-defaults",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                Password = "secret"
            });

        Assert.Equal(0, compiled.SplitHttpXPaddingBytes.From);
        Assert.Equal(0, compiled.SplitHttpXPaddingBytes.To);
        Assert.False(compiled.SplitHttpXPaddingObfsMode);
        Assert.Equal("x_padding", compiled.SplitHttpXPaddingKey);
        Assert.Equal("X-Padding", compiled.SplitHttpXPaddingHeader);
        Assert.Equal("queryInHeader", compiled.SplitHttpXPaddingPlacement);
        Assert.Equal("repeat-x", compiled.SplitHttpXPaddingMethod);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_explicit_xpadding_obfs_fields()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xpadding-obfs",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
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
                Password = "secret"
            });

        Assert.Equal(8, compiled.SplitHttpXPaddingBytes.From);
        Assert.Equal(24, compiled.SplitHttpXPaddingBytes.To);
        Assert.True(compiled.SplitHttpXPaddingObfsMode);
        Assert.Equal("pad", compiled.SplitHttpXPaddingKey);
        Assert.Equal("X-Noise", compiled.SplitHttpXPaddingHeader);
        Assert.Equal("queryInHeader", compiled.SplitHttpXPaddingPlacement);
        Assert.Equal("tokenish", compiled.SplitHttpXPaddingMethod);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_disabled_xpadding_bytes()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xpadding-bytes",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 1,
                    To = 0
                },
                Password = "secret"
            }));

        Assert.Contains("xPaddingBytes cannot be disabled", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_invalid_xpadding_placement()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xpadding-placement",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpXPaddingPlacement = "fragment",
                Password = "secret"
            }));

        Assert.Contains("unsupported padding placement", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_invalid_xpadding_method()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xpadding-method",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpXPaddingMethod = "binary",
                Password = "secret"
            }));

        Assert.Contains("unsupported padding method", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_preserves_packet_upload_ranges_for_runtime()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-packet-ranges",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 32,
                    To = 16
                },
                SplitHttpScMinPostsIntervalMs = new RuntimeInt32Range
                {
                    From = -10,
                    To = 25
                },
                SplitHttpScMaxBufferedPosts = -3,
                Password = "secret"
            });

        Assert.Equal(16, compiled.SplitHttpScMaxEachPostBytes.From);
        Assert.Equal(32, compiled.SplitHttpScMaxEachPostBytes.To);
        Assert.Equal(-10, compiled.SplitHttpScMinPostsIntervalMs.From);
        Assert.Equal(25, compiled.SplitHttpScMinPostsIntervalMs.To);
        Assert.Equal(-3, compiled.SplitHttpScMaxBufferedPosts);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_xmux_ranges_and_keepalive()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xmux",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
                {
                    MaxConcurrency = new RuntimeInt32Range
                    {
                        From = 8,
                        To = 4
                    },
                    MaxConnections = new RuntimeInt32Range
                    {
                        From = 2,
                        To = 0
                    },
                    CMaxReuseTimes = new RuntimeInt32Range
                    {
                        From = 0,
                        To = 3
                    },
                    HMaxRequestTimes = new RuntimeInt32Range
                    {
                        From = 5,
                        To = 1
                    },
                    HMaxReusableSecs = new RuntimeInt32Range
                    {
                        From = -10,
                        To = 30
                    },
                    HKeepAlivePeriodSeconds = -7
                },
                Password = "secret"
            });

        Assert.Equal(4, compiled.SplitHttpXmux.MaxConcurrency.From);
        Assert.Equal(8, compiled.SplitHttpXmux.MaxConcurrency.To);
        Assert.Equal(0, compiled.SplitHttpXmux.MaxConnections.From);
        Assert.Equal(2, compiled.SplitHttpXmux.MaxConnections.To);
        Assert.Equal(0, compiled.SplitHttpXmux.CMaxReuseTimes.From);
        Assert.Equal(3, compiled.SplitHttpXmux.CMaxReuseTimes.To);
        Assert.Equal(1, compiled.SplitHttpXmux.HMaxRequestTimes.From);
        Assert.Equal(5, compiled.SplitHttpXmux.HMaxRequestTimes.To);
        Assert.Equal(0, compiled.SplitHttpXmux.HMaxReusableSecs.From);
        Assert.Equal(30, compiled.SplitHttpXmux.HMaxReusableSecs.To);
        Assert.Equal(0, compiled.SplitHttpXmux.HKeepAlivePeriodSeconds);
    }

    [Fact]
    public void Compile_trojan_splithttp_defaults_empty_xmux_to_xray_defaults()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xmux-defaults",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                Password = "secret"
            });

        Assert.Equal(1, compiled.SplitHttpXmux.MaxConcurrency.From);
        Assert.Equal(1, compiled.SplitHttpXmux.MaxConcurrency.To);
        Assert.Equal(0, compiled.SplitHttpXmux.MaxConnections.From);
        Assert.Equal(0, compiled.SplitHttpXmux.MaxConnections.To);
        Assert.Equal(600, compiled.SplitHttpXmux.HMaxRequestTimes.From);
        Assert.Equal(900, compiled.SplitHttpXmux.HMaxRequestTimes.To);
        Assert.Equal(1800, compiled.SplitHttpXmux.HMaxReusableSecs.From);
        Assert.Equal(3000, compiled.SplitHttpXmux.HMaxReusableSecs.To);
        Assert.Equal(0, compiled.SplitHttpXmux.HKeepAlivePeriodSeconds);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_conflicting_xmux_connection_and_concurrency_limits()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-xmux-conflict",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
                {
                    MaxConcurrency = new RuntimeInt32Range
                    {
                        From = 1,
                        To = 2
                    },
                    MaxConnections = new RuntimeInt32Range
                    {
                        From = 0,
                        To = 3
                    }
                },
                Password = "secret"
            }));

        Assert.Contains("maxConnections", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("maxConcurrency", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_quic_options()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-quic",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ApplicationProtocols = [" h3 "],
                QuicOptions = new RuntimeQuicOptions
                {
                    Congestion = " RENO ",
                    BrutalUp = -1,
                    BrutalDown = 4096,
                    UdpHop = new RuntimeUdpHopOptions
                    {
                        Ports = [0, 443, 8443, 8443, 70000],
                        IntervalMinSeconds = -3,
                        IntervalMaxSeconds = 9
                    },
                    InitStreamReceiveWindow = -1,
                    MaxStreamReceiveWindow = 32,
                    InitConnReceiveWindow = 0,
                    MaxConnReceiveWindow = -5,
                    MaxIdleTimeoutSeconds = -7,
                    KeepAlivePeriodSeconds = 4,
                    DisablePathMtuDiscovery = true,
                    MaxIncomingStreams = -5
                },
                Password = "secret"
            });

        Assert.Equal(["h3"], compiled.ApplicationProtocols);
        Assert.Equal("reno", compiled.QuicOptions.Congestion);
        Assert.Equal(0, compiled.QuicOptions.BrutalUp);
        Assert.Equal(4096, compiled.QuicOptions.BrutalDown);
        Assert.Equal([443, 8443], compiled.QuicOptions.UdpHop.Ports);
        Assert.Equal(0, compiled.QuicOptions.UdpHop.IntervalMinSeconds);
        Assert.Equal(9, compiled.QuicOptions.UdpHop.IntervalMaxSeconds);
        Assert.Equal(0, compiled.QuicOptions.InitStreamReceiveWindow);
        Assert.Equal(32, compiled.QuicOptions.MaxStreamReceiveWindow);
        Assert.Equal(0, compiled.QuicOptions.InitConnReceiveWindow);
        Assert.Equal(0, compiled.QuicOptions.MaxConnReceiveWindow);
        Assert.Equal(0, compiled.QuicOptions.MaxIdleTimeoutSeconds);
        Assert.Equal(4, compiled.QuicOptions.KeepAlivePeriodSeconds);
        Assert.True(compiled.QuicOptions.DisablePathMtuDiscovery);
        Assert.Equal(0, compiled.QuicOptions.MaxIncomingStreams);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_server_side_config_fields()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-server-side-fields",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpNoSseHeader = true,
                SplitHttpScStreamUpServerSecs = new RuntimeInt32Range
                {
                    From = 90,
                    To = 15
                },
                SplitHttpServerMaxHeaderBytes = 0,
                Password = "secret"
            });

        Assert.True(compiled.SplitHttpNoSseHeader);
        Assert.Equal(15, compiled.SplitHttpScStreamUpServerSecs.From);
        Assert.Equal(90, compiled.SplitHttpScStreamUpServerSecs.To);
        Assert.Equal(0, compiled.SplitHttpServerMaxHeaderBytes);
    }

    [Fact]
    public void Compile_trojan_splithttp_preserves_unconfigured_server_side_runtime_defaults()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-server-defaults",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                Password = "secret"
            });

        Assert.Equal(0, compiled.SplitHttpScStreamUpServerSecs.From);
        Assert.Equal(0, compiled.SplitHttpScStreamUpServerSecs.To);
        Assert.Equal(0, compiled.SplitHttpServerMaxHeaderBytes);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_negative_server_max_header_bytes()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-server-header-bytes",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpServerMaxHeaderBytes = -1,
                Password = "secret"
            }));

        Assert.Contains("serverMaxHeaderBytes", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("negative", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_normalizes_download_settings_and_inherits_unspecified_values()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-download-settings",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                ServerName = "tls.example.com",
                Transport = TrojanOutboundTransports.SplitHttp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                SplitHttpHost = "cdn.example.com",
                SplitHttpPath = " upload?route=1 ",
                SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                {
                    ServerHost = " down.example.com ",
                    ServerPort = 8443,
                    Path = " down?route=2 ",
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [" X-Down "] = " 2 "
                    },
                    ConnectTimeoutSeconds = -3,
                    SkipCertificateValidation = true
                },
                Password = "secret"
            });

        var downloadSettings = Assert.IsType<RuntimeSplitHttpDownloadOptions>(compiled.SplitHttpDownloadSettings);
        Assert.Equal("down.example.com", downloadSettings.ServerHost);
        Assert.Equal(8443, downloadSettings.ServerPort);
        Assert.Equal("tls.example.com", downloadSettings.ServerName);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, downloadSettings.TransportSecurity);
        Assert.Equal("cdn.example.com", downloadSettings.Host);
        Assert.Equal("/down/?route=2", downloadSettings.Path);
        Assert.Equal("2", Assert.IsAssignableFrom<IReadOnlyDictionary<string, string>>(downloadSettings.Headers)["X-Down"]);
        Assert.Equal(0, downloadSettings.ConnectTimeoutSeconds);
        Assert.Equal(0, downloadSettings.HandshakeTimeoutSeconds);
        Assert.True(downloadSettings.SkipCertificateValidation);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_download_settings_in_stream_one_mode()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-download-stream-one",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "stream-one",
                SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                {
                    ServerHost = "down.example.com",
                    ServerPort = 8443
                },
                Password = "secret"
            }));

        Assert.Contains("stream-one", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("downloadSettings", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_host_header_in_download_headers()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-download-host-header",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                {
                    ServerHost = "down.example.com",
                    ServerPort = 8443,
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [" Host "] = "down.example.com"
                    }
                },
                Password = "secret"
            }));

        Assert.Contains("downloadSettings.headers", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("host", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_unknown_mode()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-invalid-mode",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "burst-up",
                Password = "secret"
            }));

        Assert.Contains("unsupported mode", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_invalid_seq_placement()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-invalid-seq-placement",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "fragment",
                Password = "secret"
            }));

        Assert.Contains("unsupported seq placement", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_get_uplink_method_outside_packet_up_mode()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-invalid-get",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "stream-up",
                SplitHttpUplinkHttpMethod = "get",
                Password = "secret"
            }));

        Assert.Contains("GET only in packet-up mode", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_allows_non_get_uplink_method_in_stream_up_mode()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-put",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "stream-up",
                SplitHttpUplinkHttpMethod = "put",
                Password = "secret"
            });

        Assert.Equal("PUT", compiled.SplitHttpUplinkHttpMethod);
        Assert.Equal("stream-up", compiled.SplitHttpMode);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_header_uplink_data_placement_outside_packet_up_mode()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-invalid-uplink-placement",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpMode = "auto",
                SplitHttpUplinkDataPlacement = "header",
                Password = "secret"
            }));

        Assert.Contains("only in packet-up mode", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_splithttp_rejects_host_header_in_headers()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-splithttp-host-header",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.SplitHttp,
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [" Host "] = "cdn.example.com"
                },
                Password = "secret"
            }));

        Assert.Contains("\"headers\" can't contain \"host\"", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_trojan_reality_security_normalizes_runtime_reality_options()
    {
        var realityKey = EncodeBase64Url(32, 0x66);
        var realityVerify = EncodeBase64Url(1952, 0x77);
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-reality",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = " grpc ",
                TransportSecurity = " REALITY ",
                ApplicationProtocols = ["http/1.1"],
                RealityOptions = new RuntimeRealityOptions
                {
                    Fingerprint = " Chrome ",
                    Password = $" {realityKey} ",
                    ShortId = " A1B2 ",
                    Mldsa65Verify = $" {realityVerify} ",
                    SpiderX = " /portal?p=10-20&keep=1&r=99 "
                },
                Password = "secret"
            });

        Assert.Equal(TrojanOutboundTransports.Grpc, compiled.Transport);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, compiled.TransportSecurity);
        Assert.Equal(["h2"], compiled.ApplicationProtocols);
        Assert.Equal("chrome", compiled.RealityOptions.Fingerprint);
        Assert.Equal(realityKey, compiled.RealityOptions.Password);
        Assert.Equal(realityKey, compiled.RealityOptions.PublicKey);
        Assert.Equal("a1b2", compiled.RealityOptions.ShortId);
        Assert.Equal("/portal?keep=1", compiled.RealityOptions.SpiderX);
        Assert.Equal([10L, 20L, 0L, 0L, 0L, 0L, 0L, 0L, 99L, 99L], compiled.RealityOptions.SpiderY);
    }

    [Fact]
    public void Compile_trojan_reality_security_rejects_hellogolang_fingerprint_like_xray_core()
    {
        var realityKey = EncodeBase64Url(32, 0x66);
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-reality-hellogolang",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.Grpc,
                TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    Fingerprint = " hellogolang ",
                    Password = realityKey
                },
                Password = "secret"
            }));

        Assert.Contains("does not support", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hellogolang", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(" hellogolang ", "hellogolang")]
    [InlineData(" unsafe ", "unsafe")]
    [InlineData(" HelloChrome_Auto ", "hellochrome_auto")]
    [InlineData(" ", "")]
    public void Compile_trojan_tls_accepts_known_normal_fingerprints(string configuredFingerprint, string expectedFingerprint)
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-tls-known-fingerprint",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                Fingerprint = configuredFingerprint,
                Password = "secret"
            });

        Assert.Equal(expectedFingerprint, compiled.Fingerprint);
    }

    [Fact]
    public void Compile_trojan_tls_rejects_unknown_normal_fingerprint()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileTrojan(
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-tls-unknown-fingerprint",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                Fingerprint = " not-a-browser ",
                Password = "secret"
            }));

        Assert.Contains("Unknown TLS fingerprint", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not-a-browser", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_vless_rejects_reality_for_websocket_transport()
    {
        var realityKey = EncodeBase64Url(32, 0x44);
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-reality-ws",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = VlessOutboundTransports.Ws,
                TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    Password = realityKey
                },
                UserUuid = "22222222-2222-2222-2222-222222222222"
            }));

        Assert.Contains("REALITY", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("gRPC", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_rejects_invalid_trojan_port()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeTrojanOutboundOptions
            {
                Tag = "trojan-invalid-port",
                ServerHost = "edge.example.com",
                ServerPort = 0,
                Password = "secret"
            }
        ]));

        Assert.Equal("Invalid Trojan port.", exception.Message);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_rejects_invalid_vless_uuid()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-invalid-uuid",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "not-a-uuid"
            }
        ]));

        Assert.Equal("VLESS user UUID is invalid.", exception.Message);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_preserves_zero_vless_port()
    {
        var catalog = RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-zero-port",
                ServerHost = "edge.example.com",
                ServerPort = 0,
                UserUuid = "22222222-2222-2222-2222-222222222222"
            }
        ]);

        Assert.True(catalog.TryGetVless("vless-zero-port", out var vless));
        Assert.Equal(0, vless.ServerPort);
    }

    [Fact]
    public void Compile_vless_normalizes_supported_flow_values()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-vision",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                Flow = " XTLS-RPRX-VISION-UDP443 "
            });

        Assert.Equal(VlessFlowTypes.VisionUdp443, compiled.Flow);
    }

    [Fact]
    public void Compile_vless_clamps_negative_testpre_to_zero()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-testpre-negative",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                TestPre = -3
            });

        Assert.Equal(0, compiled.TestPre);
    }

    [Fact]
    public void Compile_vless_preserves_positive_testpre()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-testpre-positive",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                TestPre = 4
            });

        Assert.Equal(4, compiled.TestPre);
    }

    [Fact]
    public void Compile_vless_normalizes_reverse_tag()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-reverse",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                ReverseTag = " reverse-edge "
            });

        Assert.Equal("reverse-edge", compiled.ReverseTag);
    }

    [Fact]
    public void Compile_vless_normalizes_encryption_segments_and_padding()
    {
        var firstKey = EncodeBase64Url(32, 0x11);
        var secondKey = EncodeBase64Url(32, 0x22);
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-encryption-normalized",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                Encryption = $" {firstKey} . {secondKey} ",
                Padding = " 100-35-40.75-0-10 "
            });

        Assert.Equal($"{firstKey}.{secondKey}", compiled.Encryption);
        Assert.Equal("100-35-40.75-0-10", compiled.Padding);
    }

    [Fact]
    public void Compile_vless_rejects_invalid_encryption_configuration()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-encryption-invalid",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                Encryption = "bad!"
            }));

        Assert.Contains("Base-64", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_vless_rejects_websocket_early_data_when_encryption_is_enabled()
    {
        var encryption = EncodeBase64Url(32, 0x33);
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-encryption-early-data",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                Transport = VlessOutboundTransports.Ws,
                WebSocketEarlyDataBytes = 1024,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                Encryption = encryption
            }));

        Assert.Contains("early-data", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_vless_rejects_unknown_flow()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-flow-invalid",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                Flow = "vision-v2"
            }));

        Assert.Contains("flow", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Compile_vless_normalizes_effective_testseed()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-vision-seed",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                TestSeed = [1u, 2u, 3u, 4u, 5u]
            });

        Assert.Equal([1u, 2u, 3u, 4u], compiled.TestSeed);
    }

    [Fact]
    public void Compile_vless_discards_partial_testseed()
    {
        var compiled = ProxyOutboundOptionsCompiler.CompileVless(
            new RuntimeVlessOutboundOptions
            {
                Tag = "vless-vision-seed-partial",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "22222222-2222-2222-2222-222222222222",
                TestSeed = [1u, 2u, 3u]
            });

        Assert.Empty(compiled.TestSeed);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_normalizes_unknown_vmess_security_to_auto()
    {
        var catalog = RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeVmessOutboundOptions
            {
                Tag = "vmess-auto-security",
                ServerHost = "edge.example.com",
                ServerPort = 443,
                UserUuid = "33333333-3333-3333-3333-333333333333",
                Security = "demo-security",
                NoTerminationSignal = true
            }
        ]);

        Assert.True(catalog.TryGetVmess("vmess-auto-security", out var vmess));
        Assert.Equal(VmessOutboundSecurityTypes.Auto, vmess.Security);
        Assert.True(vmess.NoTerminationSignal);
    }

    private static string EncodeBase64Url(int length, byte value)
        => Convert.ToBase64String(Enumerable.Repeat(value, length).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

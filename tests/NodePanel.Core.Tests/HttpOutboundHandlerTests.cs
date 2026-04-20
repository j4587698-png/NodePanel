using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class HttpOutboundHandlerTests
{
    [Fact]
    public async Task OpenTcpAsync_sends_connect_request_and_relays_payload()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunServerAsync(
                listener,
                lifetimeCts.Token,
                static async (requestText, stream, token) =>
                {
                    Assert.Contains("CONNECT target.example.com:443 HTTP/1.1", requestText, StringComparison.Ordinal);
                    Assert.Contains("Host: target.example.com:443", requestText, StringComparison.Ordinal);
                    Assert.Contains("Proxy-Connection: Keep-Alive", requestText, StringComparison.Ordinal);
                    Assert.Contains($"User-Agent: {RuntimeInternetHttpUtilities.DefaultChromeUserAgent}", requestText, StringComparison.Ordinal);

                    var buffer = new byte[64];
                    var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
                    await stream.WriteAsync(buffer.AsMemory(0, read), token);
                });

            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-edge",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-edge"
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var payload = Encoding.UTF8.GetBytes("hello-http-connect");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_uses_system_dns_for_proxy_server_when_skip_dns_resolve_is_enabled()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunServerAsync(
                listener,
                lifetimeCts.Token,
                static (_, _, _) => Task.CompletedTask);

            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-skip-dns",
                    ServerHost = "localhost",
                    ServerPort = serverPort
                },
                dnsResolver: new ThrowingDnsResolver());

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-skip-dns",
                    Content = new DispatchContent
                    {
                        SkipDnsResolve = true
                    }
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_presends_initial_payload_after_http1_connect()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var initialPayload = Encoding.ASCII.GetBytes("prefetch-http1");

        try
        {
            var serverTask = RunServerAsync(
                listener,
                lifetimeCts.Token,
                static async (_, stream, token) =>
                {
                    var payload = new byte["prefetch-http1".Length];
                    await ReadExactAsync(stream, payload, token);
                    await stream.WriteAsync(payload, token);
                });

            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-initial-http1",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-initial-http1",
                    InitialPayload = initialPayload
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var echoed = new byte[initialPayload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(initialPayload, echoed);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_renders_contextual_headers_for_http1_connect()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunServerAsync(
                listener,
                lifetimeCts.Token,
                static (requestText, _, _) =>
                {
                    Assert.Contains("X-Source: 127.0.0.1:54321", requestText, StringComparison.Ordinal);
                    Assert.Contains("X-Source-Address: 127.0.0.1", requestText, StringComparison.Ordinal);
                    Assert.Contains("X-Target: target.example.com:443", requestText, StringComparison.Ordinal);
                    Assert.Contains("X-Target-Network: tcp", requestText, StringComparison.Ordinal);
                    Assert.Contains("X-Target-String: tcp:target.example.com:443", requestText, StringComparison.Ordinal);
                    return Task.CompletedTask;
                });

            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-headers-http1",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["X-Source"] = "{{ .Source.NetAddr }}",
                        ["X-Source-Address"] = "{{ .Source.Address }}",
                        ["X-Target"] = "{{ .Target.NetAddr }}",
                        ["X-Target-Network"] = "{{ .Target.Network }}",
                        ["X-Target-String"] = "{{ .Target }}"
                    }
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-headers-http1",
                    InboundSourceNetwork = RoutingNetworks.Tcp,
                    SourceEndPoint = new IPEndPoint(IPAddress.Loopback, 54321)
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            await stream.DisposeAsync();
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_supports_basic_auth_and_custom_headers()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunServerAsync(
                listener,
                lifetimeCts.Token,
                static (requestText, _, _) =>
                {
                    Assert.Contains(
                        "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0",
                        requestText,
                        StringComparison.Ordinal);
                    Assert.Contains("X-Test: demo", requestText, StringComparison.Ordinal);
                    Assert.Contains("User-Agent: CustomAgent/1.0", requestText, StringComparison.Ordinal);
                    return Task.CompletedTask;
                });

            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-auth",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Username = "alice",
                    Password = "secret",
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["X-Test"] = "demo",
                        ["User-Agent"] = "CustomAgent/1.0"
                    }
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-auth"
                },
                new DispatchDestination
                {
                    Host = "auth.example.com",
                    Port = 8443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            await stream.DisposeAsync();
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_supports_proxy_outbound_tag_chaining()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var chainedHandler = new RecordingTcpForwardOutboundHandler("chain", IPAddress.Loopback.ToString(), serverPort);
        var serviceProvider = new MutableDispatcherServiceProvider();
        var httpHandler = new HttpOutboundHandler(
            new StaticCommonSettingsProvider(new OutboundCommonSettings
            {
                Tag = "http-chain",
                Protocol = OutboundProtocols.Http,
                ProxyOutboundTag = "chain"
            }),
            new StaticRuntimeSettingsProvider(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-chain",
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerPort = serverPort
                }),
            serviceProvider);
        var dispatcher = new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    chainedHandler,
                    httpHandler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = "http-chain",
                                Protocol = OutboundProtocols.Http
                            },
                            new OutboundRuntime
                            {
                                Tag = "chain",
                                Protocol = "chain"
                            }
                        ],
                        DefaultOutboundTag = "http-chain"
                    })));
        serviceProvider.Dispatcher = dispatcher;

        var serverTask = RunServerAsync(
            listener,
            lifetimeCts.Token,
            static async (_, stream, token) =>
            {
                var buffer = new byte[32];
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
                await stream.WriteAsync(buffer.AsMemory(0, read), token);
            });

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "chain.example.com",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            lifetimeCts.Token);

        var payload = Encoding.ASCII.GetBytes("ping");
        await outbound.WriteAsync(payload, lifetimeCts.Token);
        await outbound.FlushAsync(lifetimeCts.Token);

        var response = new byte[payload.Length];
        await ReadExactAsync(outbound, response, lifetimeCts.Token);

        Assert.True(chainedHandler.WasOpened);
        Assert.Equal("ping", Encoding.ASCII.GetString(response));
        await serverTask;
    }

    [Fact]
    public async Task OpenTransportStreamAsync_uses_runtime_internet_profile_for_tls_transport()
    {
        var securityFactory = new RecordingInternetSecurityFactory(RuntimeInternetSecurityTypes.Tls);
        var profile = CreateTestInternetProfile(securityFactory);
        var handler = CreateHandler(
            new RuntimeHttpOutboundOptions
            {
                Tag = "http-tls",
                ServerHost = "proxy.example.com",
                ServerName = "edge.example.com",
                Transport = HttpOutboundTransports.Tls,
                ApplicationProtocols = ["h2", "http/1.1"],
                SkipCertificateValidation = true
            },
            profile);
        await using var baseStream = new MemoryStream();

        var stream = await handler.OpenTransportStreamAsync(
            baseStream,
            new RuntimeHttpOutboundOptions
            {
                Tag = "http-tls",
                ServerHost = "proxy.example.com",
                ServerName = "edge.example.com",
                Transport = HttpOutboundTransports.Tls,
                ApplicationProtocols = ["h2", "http/1.1"],
                SkipCertificateValidation = true
            },
            CancellationToken.None);

        Assert.Same(baseStream, stream);
        Assert.True(securityFactory.WasInvoked);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, securityFactory.ObservedStack.SecurityType);
        Assert.Equal("edge.example.com", securityFactory.ObservedOptions!.ServerName);
        Assert.Equal(["h2", "http/1.1"], securityFactory.ObservedOptions.ApplicationProtocols);
        Assert.True(securityFactory.ObservedOptions.SkipCertificateValidation);
    }

    [Fact]
    public async Task OpenTransportStreamAsync_preserves_empty_alpn_for_tls_transport_when_unset()
    {
        var securityFactory = new RecordingInternetSecurityFactory(RuntimeInternetSecurityTypes.Tls);
        var profile = CreateTestInternetProfile(securityFactory);
        var handler = CreateHandler(
            new RuntimeHttpOutboundOptions
            {
                Tag = "http-tls-default-alpn",
                ServerHost = "proxy.example.com",
                ServerName = "edge.example.com",
                Transport = HttpOutboundTransports.Tls
            },
            profile);
        await using var baseStream = new MemoryStream();

        _ = await handler.OpenTransportStreamAsync(
            baseStream,
            new RuntimeHttpOutboundOptions
            {
                Tag = "http-tls-default-alpn",
                ServerHost = "proxy.example.com",
                ServerName = "edge.example.com",
                Transport = HttpOutboundTransports.Tls
            },
            CancellationToken.None);

        Assert.True(securityFactory.WasInvoked);
        Assert.Empty(securityFactory.ObservedOptions!.ApplicationProtocols);
    }

    [Fact]
    public async Task OpenTcpAsync_uses_http2_connect_when_negotiated_protocol_is_h2()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunHttp2EchoServerAsync(
                listener,
                lifetimeCts.Token,
                static headers =>
                {
                    Assert.Equal("CONNECT", headers[":method"]);
                    Assert.Equal("target.example.com:443", headers[":authority"]);
                    Assert.Equal("Basic YWxpY2U6c2VjcmV0", headers["proxy-authorization"]);
                    Assert.Equal("demo", headers["x-h2"]);
                    Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, headers["user-agent"]);
                    Assert.False(headers.ContainsKey("proxy-connection"));
                });

            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-h2",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls,
                    Username = "alice",
                    Password = "secret",
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["X-H2"] = "demo"
                    }
                },
                profile);

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-h2"
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var payload = Encoding.UTF8.GetBytes("hello-http2-connect");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
            Assert.True(securityFactory.WasInvoked);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_renders_contextual_headers_for_http2_connect()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunHttp2EchoServerAsync(
                listener,
                lifetimeCts.Token,
                static headers =>
                {
                    Assert.Equal("127.0.0.1:65432", headers["x-source"]);
                    Assert.Equal("127.0.0.1", headers["x-source-address"]);
                    Assert.Equal("secure.example.com:8443", headers["x-target"]);
                    Assert.Equal("tcp", headers["x-target-network"]);
                    Assert.Equal("tcp:secure.example.com:8443", headers["x-target-string"]);
                });

            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-headers-http2",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls,
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["X-Source"] = "{{ .Source.NetAddr }}",
                        ["X-Source-Address"] = "{{ .Source.Address }}",
                        ["X-Target"] = "{{ .Target.NetAddr }}",
                        ["X-Target-Network"] = "{{ .Target.Network }}",
                        ["X-Target-String"] = "{{ .Target }}"
                    }
                },
                profile);

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-headers-http2",
                    InboundSourceNetwork = RoutingNetworks.Tcp,
                    SourceEndPoint = new IPEndPoint(IPAddress.Loopback, 65432)
                },
                new DispatchDestination
                {
                    Host = "secure.example.com",
                    Port = 8443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("templated-http2");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            await serverTask;
            Assert.True(securityFactory.WasInvoked);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_presends_initial_payload_on_http2_connect()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var initialPayload = Encoding.ASCII.GetBytes("prefetch-http2");

        try
        {
            var serverTask = RunHttp2InitialPayloadBeforeStatusServerAsync(
                listener,
                lifetimeCts.Token,
                "prefetch-http2",
                static headers =>
                {
                    Assert.Equal("CONNECT", headers[":method"]);
                    Assert.Equal("target.example.com:443", headers[":authority"]);
                });

            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-initial-http2",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls
                },
                profile);

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-initial-http2",
                    InitialPayload = initialPayload
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var echoed = new byte[initialPayload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(initialPayload, echoed);
            Assert.True(securityFactory.WasInvoked);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_presends_initial_payload_on_reused_http2_connect()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var initialPayload = Encoding.ASCII.GetBytes("prefetch-reuse");

        try
        {
            var serverTask = RunHttp2ReuseServerWithInlineInitialPayloadAsync(listener, lifetimeCts.Token);
            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-initial-http2-reuse",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls
                },
                profile);

            await using (var firstStream = await handler.OpenTcpAsync(
                             new DispatchContext
                             {
                                 OutboundTag = "http-initial-http2-reuse"
                             },
                             new DispatchDestination
                             {
                                 Host = "first.example.com",
                                 Port = 443,
                                 Network = DispatchNetwork.Tcp
                             },
                             lifetimeCts.Token))
            {
                var payload = Encoding.ASCII.GetBytes("first-payload");
                await firstStream.WriteAsync(payload, lifetimeCts.Token);

                var echoed = new byte[payload.Length];
                await ReadExactAsync(firstStream, echoed, lifetimeCts.Token);
                Assert.Equal(payload, echoed);
            }

            await using var secondStream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-initial-http2-reuse",
                    InitialPayload = initialPayload
                },
                new DispatchDestination
                {
                    Host = "second.example.com",
                    Port = 8443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var echoedInitialPayload = new byte[initialPayload.Length];
            await ReadExactAsync(secondStream, echoedInitialPayload, lifetimeCts.Token);
            Assert.Equal(initialPayload, echoedInitialPayload);
            Assert.True(securityFactory.WasInvoked);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void BuildConnectHeaders_throws_for_unsupported_template_expression()
    {
        var settings = new RuntimeHttpOutboundOptions
        {
            Tag = "http-invalid-template",
            ServerHost = "127.0.0.1",
            ServerPort = 8080,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["X-Test"] = "{{ printf \"%s\" .Target }}"
            }
        };

        var error = Assert.Throws<InvalidOperationException>(() =>
            HttpOutboundHandler.BuildConnectHeaders(
                settings,
                new DispatchContext
                {
                    SourceEndPoint = new IPEndPoint(IPAddress.Loopback, 1000),
                    InboundSourceNetwork = RoutingNetworks.Tcp
                },
                new DispatchDestination
                {
                    Host = "invalid.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                includeProxyConnection: true));

        Assert.Contains("Unsupported HTTP outbound header template expression", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenTcpAsync_reuses_http2_session_for_sequential_connects()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunHttp2ReuseServerAsync(listener, lifetimeCts.Token);
            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-h2-reuse",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls
                },
                profile);

            await using (var firstStream = await handler.OpenTcpAsync(
                             new DispatchContext
                             {
                                 OutboundTag = "http-h2-reuse"
                             },
                             new DispatchDestination
                             {
                                 Host = "first.example.com",
                                 Port = 443,
                                 Network = DispatchNetwork.Tcp
                             },
                             lifetimeCts.Token))
            {
                var payload = Encoding.ASCII.GetBytes("first-payload");
                await firstStream.WriteAsync(payload, lifetimeCts.Token);

                var echoed = new byte[payload.Length];
                await ReadExactAsync(firstStream, echoed, lifetimeCts.Token);
                Assert.Equal(payload, echoed);
            }

            await using (var secondStream = await handler.OpenTcpAsync(
                             new DispatchContext
                             {
                                 OutboundTag = "http-h2-reuse"
                             },
                             new DispatchDestination
                             {
                                 Host = "second.example.com",
                                 Port = 8443,
                                 Network = DispatchNetwork.Tcp
                             },
                             lifetimeCts.Token))
            {
                var payload = Encoding.ASCII.GetBytes("second-payload");
                await secondStream.WriteAsync(payload, lifetimeCts.Token);

                var echoed = new byte[payload.Length];
                await ReadExactAsync(secondStream, echoed, lifetimeCts.Token);
                Assert.Equal(payload, echoed);
            }

            await serverTask;
            Assert.True(securityFactory.WasInvoked);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_reuses_http2_session_for_concurrent_connects()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunHttp2ConcurrentReuseServerAsync(listener, lifetimeCts.Token);
            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-h2-concurrent-reuse",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls
                },
                profile);

            await using var firstStream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-h2-concurrent-reuse"
                },
                new DispatchDestination
                {
                    Host = "first.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            await using var secondStream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-h2-concurrent-reuse"
                },
                new DispatchDestination
                {
                    Host = "second.example.com",
                    Port = 8443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var firstPayload = Encoding.ASCII.GetBytes("first-concurrent-payload");
            var secondPayload = Encoding.ASCII.GetBytes("second-concurrent-payload");
            await Task.WhenAll(
                firstStream.WriteAsync(firstPayload, lifetimeCts.Token).AsTask(),
                secondStream.WriteAsync(secondPayload, lifetimeCts.Token).AsTask());

            var echoedFirst = new byte[firstPayload.Length];
            var echoedSecond = new byte[secondPayload.Length];
            await Task.WhenAll(
                ReadExactAsync(firstStream, echoedFirst, lifetimeCts.Token),
                ReadExactAsync(secondStream, echoedSecond, lifetimeCts.Token));

            Assert.Equal(firstPayload, echoedFirst);
            Assert.Equal(secondPayload, echoedSecond);

            await serverTask;
            Assert.True(securityFactory.WasInvoked);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_retries_when_initial_connect_response_is_non_200()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var attempts = 0;

        try
        {
            var serverTask = RunRetryingHttpServerAsync(
                listener,
                lifetimeCts.Token,
                (attempt, requestText) =>
                {
                    Interlocked.Exchange(ref attempts, attempt);
                    Assert.Contains("CONNECT retry.example.com:443 HTTP/1.1", requestText, StringComparison.Ordinal);
                });

            var handler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-retry",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-retry"
                },
                new DispatchDestination
                {
                    Host = "retry.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("retry-payload");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
            Assert.Equal(2, Volatile.Read(ref attempts));

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_reuses_http2_session_across_handlers_when_pool_is_shared()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var pool = new Http2TunnelSessionPool();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunHttp2ReuseServerAsync(listener, lifetimeCts.Token);
            var securityFactory = new RecordingInternetSecurityFactory(
                RuntimeInternetSecurityTypes.Tls,
                negotiatedApplicationProtocol: "h2");
            var profile = CreateTestInternetProfile(securityFactory);
            var firstHandler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-h2-shared-a",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls
                },
                profile,
                pool);
            var secondHandler = CreateHandler(
                new RuntimeHttpOutboundOptions
                {
                    Tag = "http-h2-shared-b",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Transport = HttpOutboundTransports.Tls
                },
                profile,
                pool);

            await using (var firstStream = await firstHandler.OpenTcpAsync(
                             new DispatchContext
                             {
                                 OutboundTag = "http-h2-shared-a"
                             },
                             new DispatchDestination
                             {
                                 Host = "first.example.com",
                                 Port = 443,
                                 Network = DispatchNetwork.Tcp
                             },
                             lifetimeCts.Token))
            {
                var payload = Encoding.ASCII.GetBytes("first-payload");
                await firstStream.WriteAsync(payload, lifetimeCts.Token);

                var echoed = new byte[payload.Length];
                await ReadExactAsync(firstStream, echoed, lifetimeCts.Token);
                Assert.Equal(payload, echoed);
            }

            await using (var secondStream = await secondHandler.OpenTcpAsync(
                             new DispatchContext
                             {
                                 OutboundTag = "http-h2-shared-b"
                             },
                             new DispatchDestination
                             {
                                 Host = "second.example.com",
                                 Port = 8443,
                                 Network = DispatchNetwork.Tcp
                             },
                             lifetimeCts.Token))
            {
                var payload = Encoding.ASCII.GetBytes("second-payload");
                await secondStream.WriteAsync(payload, lifetimeCts.Token);

                var echoed = new byte[payload.Length];
                await ReadExactAsync(secondStream, echoed, lifetimeCts.Token);
                Assert.Equal(payload, echoed);
            }

            await serverTask;
            Assert.True(securityFactory.WasInvoked);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenUdpAsync_is_not_supported()
    {
        var handler = CreateHandler(
            new RuntimeHttpOutboundOptions
            {
                Tag = "http-udp",
                ServerHost = "127.0.0.1",
                ServerPort = 8080
            });

        await Assert.ThrowsAsync<NotSupportedException>(async () =>
            _ = await handler.OpenUdpAsync(
                new DispatchContext
                {
                    OutboundTag = "http-udp"
                },
                CancellationToken.None));
    }

    [Fact]
    public void RuntimeCapabilities_include_http_protocol()
    {
        Assert.Contains(OutboundProtocols.Http, RuntimeCapabilities.SupportedOutboundProtocols);
    }

    private static HttpOutboundHandler CreateHandler(
        RuntimeHttpOutboundOptions settings,
        RuntimeInternetProfile? internetProfile = null,
        Http2TunnelSessionPool? http2TunnelSessionPool = null,
        IDnsResolver? dnsResolver = null)
        => new(
            new StaticCommonSettingsProvider(new OutboundCommonSettings
            {
                Tag = settings.Tag,
                Protocol = OutboundProtocols.Http
            }),
            new StaticRuntimeSettingsProvider(settings),
            serviceProvider: null,
            dnsResolver,
            internetProfile,
            http2TunnelSessionPool);

    private static async Task RunServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken,
        Func<string, Stream, CancellationToken, Task> continuation)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var requestText = await ReadHttpHeadersAsync(stream, cancellationToken);
        await stream.WriteAsync(
            Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n"),
            cancellationToken);
        await continuation(requestText, stream, cancellationToken);
    }

    private static async Task RunHttp2EchoServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken,
        Action<IReadOnlyDictionary<string, string>> assertHeaders)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var headers = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        assertHeaders(headers);

        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);

        var payload = await ReadHttp2DataPayloadAsync(stream, expectedStreamId: 1, cancellationToken);
        await WriteHttp2DataAsync(stream, payload, streamId: 1, cancellationToken);
    }

    private static async Task RunHttp2InitialPayloadBeforeStatusServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken,
        string expectedInitialPayload,
        Action<IReadOnlyDictionary<string, string>> assertHeaders)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var headers = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        assertHeaders(headers);

        var payload = await ReadHttp2DataPayloadAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal(expectedInitialPayload, Encoding.ASCII.GetString(payload));

        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);
        await WriteHttp2DataAsync(stream, payload, streamId: 1, cancellationToken);
    }

    private static async Task RunHttp2ReuseServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var firstHeaders = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal("CONNECT", firstHeaders[":method"]);
        Assert.Equal("first.example.com:443", firstHeaders[":authority"]);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);

        var firstPayload = await ReadHttp2DataPayloadAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal("first-payload", Encoding.ASCII.GetString(firstPayload));
        await WriteHttp2DataAsync(stream, firstPayload, streamId: 1, cancellationToken);

        var secondHeaders = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 3, cancellationToken);
        Assert.Equal("CONNECT", secondHeaders[":method"]);
        Assert.Equal("second.example.com:8443", secondHeaders[":authority"]);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 3, cancellationToken);

        var secondPayload = await ReadHttp2DataPayloadAsync(stream, expectedStreamId: 3, cancellationToken);
        Assert.Equal("second-payload", Encoding.ASCII.GetString(secondPayload));
        await WriteHttp2DataAsync(stream, secondPayload, streamId: 3, cancellationToken);
    }

    private static async Task RunHttp2ReuseServerWithInlineInitialPayloadAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var firstHeaders = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal("CONNECT", firstHeaders[":method"]);
        Assert.Equal("first.example.com:443", firstHeaders[":authority"]);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);

        var firstPayload = await ReadHttp2DataPayloadAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal("first-payload", Encoding.ASCII.GetString(firstPayload));
        await WriteHttp2DataAsync(stream, firstPayload, streamId: 1, cancellationToken);

        var secondHeaders = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 3, cancellationToken);
        Assert.Equal("CONNECT", secondHeaders[":method"]);
        Assert.Equal("second.example.com:8443", secondHeaders[":authority"]);

        var secondPayload = await ReadHttp2DataPayloadAsync(stream, expectedStreamId: 3, cancellationToken);
        Assert.Equal("prefetch-reuse", Encoding.ASCII.GetString(secondPayload));

        await WriteHttp2HeadersStatusAsync(stream, streamId: 3, cancellationToken);
        await WriteHttp2DataAsync(stream, secondPayload, streamId: 3, cancellationToken);
    }

    private static async Task RunHttp2ConcurrentReuseServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var firstHeaders = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal("CONNECT", firstHeaders[":method"]);
        Assert.Equal("first.example.com:443", firstHeaders[":authority"]);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);

        var secondHeaders = await ReadHttp2ConnectRequestHeadersAsync(stream, expectedStreamId: 3, cancellationToken);
        Assert.Equal("CONNECT", secondHeaders[":method"]);
        Assert.Equal("second.example.com:8443", secondHeaders[":authority"]);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 3, cancellationToken);

        var pendingStreams = new HashSet<int> { 1, 3 };
        while (pendingStreams.Count > 0)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            Assert.Equal(Http2TestFrameTypes.Data, frame.Type);
            Assert.Contains(frame.StreamId, pendingStreams);

            var expectedPayload = frame.StreamId == 1
                ? "first-concurrent-payload"
                : "second-concurrent-payload";
            Assert.Equal(expectedPayload, Encoding.ASCII.GetString(frame.Payload));

            await WriteHttp2DataAsync(stream, frame.Payload, frame.StreamId, cancellationToken);
            pendingStreams.Remove(frame.StreamId);
        }
    }

    private static async Task RunRetryingHttpServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken,
        Action<int, string> assertRequest)
    {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = client.GetStream();

            var requestText = await ReadHttpHeadersAsync(stream, cancellationToken);
            assertRequest(attempt, requestText);

            if (attempt == 1)
            {
                await stream.WriteAsync(
                    Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: retry-test\r\n\r\n"),
                    cancellationToken);
                continue;
            }

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: retry-test\r\n\r\n"),
                cancellationToken);

            var buffer = new byte[64];
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static RuntimeInternetProfile CreateTestInternetProfile(RecordingInternetSecurityFactory securityFactory)
    {
        return new RuntimeInternetProfile(
        [
            new PassThroughInternetTransportFactory(RuntimeInternetTransportProtocols.Tcp)
        ],
        [
            new PassThroughInternetSecurityFactory(RuntimeInternetSecurityTypes.None),
            securityFactory
        ]);
    }

    private static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        var builder = new StringBuilder();

        while (true)
        {
            var line = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(
                    stream,
                    "Unexpected EOF while reading HTTP request headers.",
                    cancellationToken)
                ;
            if (line.Length == 0)
            {
                break;
            }

            if (builder.Length > 0)
            {
                builder.Append("\r\n");
            }

            builder.Append(line);
        }

        return builder.ToString();
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (count == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading test payload.");
            }

            read += count;
        }
    }

    private static async Task<byte[]> ReadExactBytesAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await ReadExactAsync(stream, buffer, cancellationToken);
        return buffer;
    }

    private static async Task<Http2TestFrame> ReadHttp2FrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = await ReadExactBytesAsync(stream, 9, cancellationToken);
        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var payload = length == 0
            ? Array.Empty<byte>()
            : await ReadExactBytesAsync(stream, length, cancellationToken);
        return new Http2TestFrame(
            Type: header[3],
            Flags: header[4],
            StreamId:
                ((header[5] & 0x7F) << 24) |
                (header[6] << 16) |
                (header[7] << 8) |
                header[8],
            Payload: payload);
    }

    private static async Task<IReadOnlyDictionary<string, string>> ReadHttp2ConnectRequestHeadersAsync(
        Stream stream,
        int expectedStreamId,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            if (frame.Type != Http2TestFrameTypes.Headers)
            {
                continue;
            }

            Assert.Equal(expectedStreamId, frame.StreamId);
            var headerBlock = await ReadHttp2HeaderBlockAsync(stream, frame, cancellationToken);
            return DecodeHttp2RequestHeaders(headerBlock);
        }
    }

    private static async Task<byte[]> ReadHttp2HeaderBlockAsync(
        Stream stream,
        Http2TestFrame firstFrame,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        if (firstFrame.Payload.Length > 0)
        {
            buffer.Write(firstFrame.Payload, 0, firstFrame.Payload.Length);
        }

        if ((firstFrame.Flags & Http2TestFrameFlags.EndHeaders) == Http2TestFrameFlags.EndHeaders)
        {
            return buffer.ToArray();
        }

        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Continuation, frame.Type);
            Assert.Equal(firstFrame.StreamId, frame.StreamId);
            if (frame.Payload.Length > 0)
            {
                buffer.Write(frame.Payload, 0, frame.Payload.Length);
            }

            if ((frame.Flags & Http2TestFrameFlags.EndHeaders) == Http2TestFrameFlags.EndHeaders)
            {
                return buffer.ToArray();
            }
        }
    }

    private static Dictionary<string, string> DecodeHttp2RequestHeaders(byte[] headerBlock)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            Assert.False((first & 0x80) != 0, "Unexpected indexed header field in CONNECT request.");
            Assert.False((first & 0x20) != 0, "Unexpected dynamic table size update in CONNECT request.");

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var name = nameIndex switch
            {
                1 => ":authority",
                2 => ":method",
                49 => "proxy-authorization",
                58 => "user-agent",
                0 => ReadHpackString(headerBlock, ref offset),
                _ => throw new InvalidDataException($"Unsupported HPACK name index in test decoder: {nameIndex}.")
            };
            var value = ReadHpackString(headerBlock, ref offset);
            headers[name] = value;
        }

        return headers;
    }

    private static int ReadHpackInteger(byte[] buffer, ref int offset, int prefixBits)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static string ReadHpackString(byte[] buffer, ref int offset)
    {
        Assert.False((buffer[offset] & 0x80) != 0, "Test decoder does not support Huffman-encoded HPACK strings.");
        var length = ReadHpackInteger(buffer, ref offset, 7);
        var value = Encoding.ASCII.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static async Task WriteHttp2SettingsAsync(Stream stream, CancellationToken cancellationToken)
        => await WriteHttp2FrameAsync(
                stream,
                Http2TestFrameTypes.Settings,
                Http2TestFrameFlags.None,
                streamId: 0,
                payload: Array.Empty<byte>(),
                cancellationToken)
            ;

    private static async Task WriteHttp2HeadersStatusAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
        => await WriteHttp2FrameAsync(
                stream,
                Http2TestFrameTypes.Headers,
                Http2TestFrameFlags.EndHeaders,
                streamId,
                payload: [0x88],
                cancellationToken)
            ;

    private static async Task<byte[]> ReadHttp2DataPayloadAsync(
        Stream stream,
        int expectedStreamId,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            Assert.Equal(Http2TestFrameTypes.Data, frame.Type);
            Assert.Equal(expectedStreamId, frame.StreamId);
            return frame.Payload;
        }
    }

    private static async Task WriteHttp2DataAsync(
        Stream stream,
        byte[] payload,
        int streamId,
        CancellationToken cancellationToken)
        => await WriteHttp2FrameAsync(
                stream,
                Http2TestFrameTypes.Data,
                Http2TestFrameFlags.None,
                streamId,
                payload,
                cancellationToken)
            ;

    private static async Task WriteHttp2FrameAsync(
        Stream stream,
        byte type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)((payload.Length >> 16) & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)(payload.Length & 0xFF);
        header[3] = type;
        header[4] = flags;
        header[5] = (byte)((streamId >> 24) & 0x7F);
        header[6] = (byte)((streamId >> 16) & 0xFF);
        header[7] = (byte)((streamId >> 8) & 0xFF);
        header[8] = (byte)(streamId & 0xFF);

        await stream.WriteAsync(header.AsMemory(0, header.Length), cancellationToken);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken);
        }

        await stream.FlushAsync(cancellationToken);
    }

    private sealed class StaticCommonSettingsProvider : IOutboundCommonSettingsProvider
    {
        private readonly OutboundCommonSettings _settings;

        public StaticCommonSettingsProvider(OutboundCommonSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticRuntimeSettingsProvider : IRuntimeOutboundSettingsProvider
    {
        private readonly IRuntimeOutboundOptions _settings;

        public StaticRuntimeSettingsProvider(IRuntimeOutboundOptions settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
        {
            settings = _settings;
            return true;
        }

        public bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
            where TOptions : class, IRuntimeOutboundOptions
        {
            if (_settings is TOptions typed)
            {
                settings = typed;
                return true;
            }

            settings = default!;
            return false;
        }
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

    private sealed class ThrowingDnsResolver : IDnsResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The custom DNS resolver should not be used when SkipDnsResolve is enabled.");
    }

    private sealed class RecordingTcpForwardOutboundHandler : IOutboundHandler
    {
        private readonly string _host;
        private readonly int _port;

        public RecordingTcpForwardOutboundHandler(string protocol, string host, int port)
        {
            Protocol = protocol;
            _host = host;
            _port = port;
        }

        public string Protocol { get; }

        public bool WasOpened { get; private set; }

        public async ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Parse(_host), _port, cancellationToken);
            WasOpened = true;
            return client.GetStream();
        }

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

    private sealed class MutableDispatcherServiceProvider : IServiceProvider
    {
        public IDispatcher? Dispatcher { get; set; }

        public object? GetService(Type serviceType)
            => serviceType == typeof(IDispatcher) ? Dispatcher : null;
    }

    private sealed class PassThroughInternetTransportFactory : IRuntimeInternetTransportFactory
    {
        public PassThroughInternetTransportFactory(string name)
        {
            Name = name;
        }

        public string Name { get; }

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class PassThroughInternetSecurityFactory : IRuntimeInternetSecurityFactory
    {
        public PassThroughInternetSecurityFactory(string name)
        {
            Name = name;
        }

        public string Name { get; }

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class RecordingInternetSecurityFactory : IRuntimeInternetSecurityFactory
    {
        private readonly string _negotiatedApplicationProtocol;

        public RecordingInternetSecurityFactory(
            string name,
            string negotiatedApplicationProtocol = "")
        {
            Name = name;
            _negotiatedApplicationProtocol = negotiatedApplicationProtocol;
        }

        public string Name { get; }

        public bool WasInvoked { get; private set; }

        public RuntimeInternetStack ObservedStack { get; private set; }

        public IRuntimeInternetOptions? ObservedOptions { get; private set; }

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
        {
            WasInvoked = true;
            ObservedStack = stack;
            ObservedOptions = options;
            if (!string.IsNullOrWhiteSpace(_negotiatedApplicationProtocol))
            {
                context.SetTransportStream(
                    context.TransportStream,
                    negotiatedApplicationProtocol: _negotiatedApplicationProtocol);
            }

            return ValueTask.CompletedTask;
        }
    }

    private readonly record struct Http2TestFrame(
        byte Type,
        byte Flags,
        int StreamId,
        byte[] Payload);

    private static class Http2TestFrameTypes
    {
        public const byte Data = 0x0;
        public const byte Headers = 0x1;
        public const byte RstStream = 0x3;
        public const byte Settings = 0x4;
        public const byte WindowUpdate = 0x8;
        public const byte Continuation = 0x9;
    }

    private static class Http2TestFrameFlags
    {
        public const byte None = 0x0;
        public const byte Ack = 0x1;
        public const byte EndHeaders = 0x4;
    }
}

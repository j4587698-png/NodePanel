using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ProxyInboundServerTests
{
    [Fact]
    public async Task SocksInboundServer_relays_connect_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SocksInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            var request = new List<byte>
            {
                0x05, 0x01, 0x00, 0x01
            };
            request.AddRange(IPAddress.Loopback.GetAddressBytes());
            request.Add((byte)(echoPort >> 8));
            request.Add((byte)(echoPort & 0xFF));
            await stream.WriteAsync(request.ToArray(), lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-socks");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_overrides_fake_dns_metadata_for_connect_tunnels()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("localhost", ipv4: true, ipv6: false));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService(), fakeDnsEngine);
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        UserLevel = 7,
                        HandshakeTimeoutSeconds = 10,
                        Sniffing = new RuntimeSniffingOptions
                        {
                            Enabled = true,
                            MetadataOnly = true,
                            DestinationOverride = [RoutingProtocols.FakeDns]
                        }
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            await WriteSocks5ConnectRequestAsync(stream, fakeAddress.ToString(), echoPort, lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-socks-fakedns");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var destination = await dispatcher.DestinationTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(7, context.InboundUserLevel);
            Assert.Equal(fakeAddress.ToString(), context.OriginalDestinationHost);
            Assert.Equal("localhost", context.TargetHost);
            Assert.Equal(RoutingProtocols.FakeDns, context.DetectedProtocol);
            Assert.Equal("localhost", context.DetectedDomain);
            Assert.Equal("localhost", destination.Host);
            Assert.Equal(echoPort, destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_relays_connect_traffic_with_username_password_authentication()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SocksInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["socks-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x02 }, lifetimeCts.Token);
            var method = new byte[2];
            await ReadExactAsync(stream, method, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x02 }, method);

            await WriteSocks5UsernamePasswordAsync(stream, "alice", "secret", lifetimeCts.Token);
            var authStatus = new byte[2];
            await ReadExactAsync(stream, authStatus, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x01, 0x00 }, authStatus);

            await WriteSocks5ConnectRequestAsync(stream, "127.0.0.1", echoPort, lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-socks-auth");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_rejects_invalid_username_password()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SocksInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["socks-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x02 }, lifetimeCts.Token);
            var method = new byte[2];
            await ReadExactAsync(stream, method, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x02 }, method);

            await WriteSocks5UsernamePasswordAsync(stream, "alice", "wrong", lifetimeCts.Token);
            var authStatus = new byte[2];
            await ReadExactAsync(stream, authStatus, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x01, 0xFF }, authStatus);

            var eof = await stream.ReadAsync(new byte[1], lifetimeCts.Token);
            Assert.Equal(0, eof);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task SocksInboundServer_relays_socks4_connect_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await WriteSocks4ConnectRequestAsync(stream, "127.0.0.1", echoPort, lifetimeCts.Token);

            var reply = await ReadSocks4ReplyAsync(stream, lifetimeCts.Token);
            Assert.Equal(Socks4ProtocolConstants.ReplyGranted, reply.ReplyCode);

            var payload = Encoding.ASCII.GetBytes("hello-socks4");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var destination = await dispatcher.DestinationTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(ProxyInboundProtocols.Socks, context.InboundProtocol);
            Assert.Equal("127.0.0.1", destination.Host);
            Assert.Equal(echoPort, destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_relays_socks4a_connect_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await WriteSocks4ConnectRequestAsync(
                stream,
                "localhost",
                echoPort,
                lifetimeCts.Token,
                useSocks4a: true);

            var reply = await ReadSocks4ReplyAsync(stream, lifetimeCts.Token);
            Assert.Equal(Socks4ProtocolConstants.ReplyGranted, reply.ReplyCode);

            var payload = Encoding.ASCII.GetBytes("hello-socks4a");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var destination = await dispatcher.DestinationTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(ProxyInboundProtocols.Socks, context.InboundProtocol);
            Assert.Equal("localhost", destination.Host);
            Assert.Equal(echoPort, destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_rejects_socks4_when_authentication_is_required()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SocksInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["socks-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await WriteSocks4ConnectRequestAsync(stream, "127.0.0.1", 80, lifetimeCts.Token);

            var reply = await ReadSocks4ReplyAsync(stream, lifetimeCts.Token);
            Assert.Equal(Socks4ProtocolConstants.ReplyRejected, reply.ReplyCode);

            var eof = await stream.ReadAsync(new byte[1], lifetimeCts.Token);
            Assert.Equal(0, eof);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task HttpInboundServer_relays_connect_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var request = $"CONNECT 127.0.0.1:{echoPort} HTTP/1.1\r\nHost: 127.0.0.1:{echoPort}\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var payload = Encoding.ASCII.GetBytes("hello-http");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_overrides_fake_dns_metadata_for_connect_tunnels()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("localhost", ipv4: true, ipv6: false));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new HttpInboundServer(dispatcher, new RelayService(), fakeDnsEngine);
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        UserLevel = 5,
                        HandshakeTimeoutSeconds = 10,
                        Sniffing = new RuntimeSniffingOptions
                        {
                            Enabled = true,
                            MetadataOnly = true,
                            DestinationOverride = [RoutingProtocols.FakeDns]
                        }
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpConnectRequest(fakeAddress.ToString(), echoPort)),
                lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var payload = Encoding.ASCII.GetBytes("hello-http-fakedns");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var destination = await dispatcher.DestinationTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(5, context.InboundUserLevel);
            Assert.Equal(fakeAddress.ToString(), context.OriginalDestinationHost);
            Assert.Equal("localhost", context.TargetHost);
            Assert.Equal(RoutingProtocols.FakeDns, context.DetectedProtocol);
            Assert.Equal("localhost", context.DetectedDomain);
            Assert.Equal("localhost", destination.Host);
            Assert.Equal(echoPort, destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_requires_proxy_authentication_when_configured()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new ThrowingTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["http-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpConnectRequest("127.0.0.1", 443)),
                lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("407 Proxy Authentication Required", response, StringComparison.Ordinal);
            Assert.Contains("Proxy-Authenticate: Basic realm=\"proxy\"", response, StringComparison.Ordinal);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task HttpInboundServer_preserves_connect_payload_buffered_with_request()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new HttpInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var payload = Encoding.ASCII.GetBytes("hello-http-buffered");
            var request = CreateHttpConnectRequest("127.0.0.1", echoPort);
            var combined = Encoding.ASCII.GetBytes(request).Concat(payload).ToArray();
            await stream.WriteAsync(combined, lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(payload, context.InitialPayload);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_relays_plain_http_requests_with_proxy_authentication()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new HttpInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["http-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest(
                    "127.0.0.1",
                    originPort,
                    "/auth",
                    keepAlive: false,
                    proxyAuthorization: CreateBasicProxyAuthorizationHeaderValue("alice", "secret"))),
                lifetimeCts.Token);

            var response = await ReadHttpResponseAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 OK", response.HeaderText, StringComparison.Ordinal);
            Assert.Equal("ok", response.GetBodyText());

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(ProxyInboundProtocols.Http, context.InboundProtocol);
            Assert.Equal("alice", context.UserId);
            Assert.Equal("alice", context.ScopedUserId);
            Assert.Equal("127.0.0.1", context.OriginalDestinationHost);
            Assert.Equal(originPort, context.OriginalDestinationPort);

            await AwaitCompletionAsync(originTask);
            var originRequest = Assert.Single(requests);
            Assert.Contains("GET /auth HTTP/1.1", originRequest, StringComparison.Ordinal);
            Assert.DoesNotContain("Proxy-Authorization:", originRequest, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_sets_empty_user_agent_and_populates_dispatch_content()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new HttpInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest(
                    "127.0.0.1",
                    originPort,
                    "/attrs?query=1",
                    keepAlive: false,
                    additionalHeaders:
                    [
                        new KeyValuePair<string, string>("X-Test", "value")
                    ])),
                lifetimeCts.Token);

            var response = await ReadHttpResponseAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 OK", response.HeaderText, StringComparison.Ordinal);
            Assert.Equal("ok", response.GetBodyText());

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("http/1.1", context.Content.Protocol);
            Assert.True(context.Content.Attributes.TryGetValue(":method", out var method));
            Assert.Equal("GET", method);
            Assert.True(context.Content.Attributes.TryGetValue(":path", out var path));
            Assert.Equal("/attrs", path);
            Assert.True(context.Content.Attributes.TryGetValue("x-test", out var testHeader));
            Assert.Equal("value", testHeader);
            Assert.True(context.Content.Attributes.TryGetValue("user-agent", out var userAgent));
            Assert.Equal(string.Empty, userAgent);
            Assert.False(context.Content.Attributes.ContainsKey("host"));
            Assert.False(context.Content.Attributes.ContainsKey("connection"));

            await AwaitCompletionAsync(originTask);
            var originRequest = Assert.Single(requests);
            Assert.Contains("GET /attrs?query=1 HTTP/1.1", originRequest, StringComparison.Ordinal);
            Assert.Contains("User-Agent: ", originRequest, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_uses_absolute_request_authority_for_forwarded_host_header()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest(
                    "127.0.0.1",
                    originPort,
                    "/authority",
                    keepAlive: false,
                    hostHeaderOverride: "wrong.example")),
                lifetimeCts.Token);

            var response = await ReadHttpResponseAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 OK", response.HeaderText, StringComparison.Ordinal);
            Assert.Equal("ok", response.GetBodyText());

            await AwaitCompletionAsync(originTask);
            var originRequest = Assert.Single(requests);
            Assert.Contains($"Host: 127.0.0.1:{originPort}", originRequest, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Host: wrong.example", originRequest, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_relays_chunked_request_body_and_preserves_transfer_encoding()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var request = CreateHttpGetRequest(
                "127.0.0.1",
                originPort,
                "/chunked-request",
                keepAlive: false,
                additionalHeaders:
                [
                    new KeyValuePair<string, string>("Transfer-Encoding", "chunked")
                ]);
            var requestBody = "3\r\none\r\n0\r\n\r\n";
            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(request + requestBody),
                lifetimeCts.Token);

            var response = await ReadHttpResponseAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 OK", response.HeaderText, StringComparison.Ordinal);
            Assert.Equal("ok", response.GetBodyText());

            await AwaitCompletionAsync(originTask);
            var originRequest = Assert.Single(requests);
            Assert.Contains("Transfer-Encoding: chunked", originRequest, StringComparison.OrdinalIgnoreCase);
            Assert.Contains(requestBody, originRequest, StringComparison.Ordinal);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_relays_plain_http_requests_with_keep_alive()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartRawHttpServer(
            2,
            static (index, _) => index switch
            {
                0 => "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
                1 => "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo",
                _ => throw new InvalidOperationException("Unexpected request index.")
            },
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest("127.0.0.1", originPort, "/first", keepAlive: true)),
                lifetimeCts.Token);
            var response1 = await ReadHttpResponseAsync(stream, lifetimeCts.Token);

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest("127.0.0.1", originPort, "/second", keepAlive: true)),
                lifetimeCts.Token);
            var response2 = await ReadHttpResponseAsync(stream, lifetimeCts.Token);

            await AwaitCompletionAsync(originTask);

            Assert.Contains("200 OK", response1.HeaderText, StringComparison.Ordinal);
            Assert.Contains("Proxy-Connection: keep-alive", response1.HeaderText, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Connection: keep-alive", response1.HeaderText, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("one", response1.GetBodyText());

            Assert.Contains("200 OK", response2.HeaderText, StringComparison.Ordinal);
            Assert.Contains("Proxy-Connection: keep-alive", response2.HeaderText, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("two", response2.GetBodyText());

            var capturedRequests = requests.ToArray();
            Assert.Equal(2, capturedRequests.Length);
            Assert.Contains("GET /first HTTP/1.1", capturedRequests[0], StringComparison.Ordinal);
            Assert.Contains("GET /second HTTP/1.1", capturedRequests[1], StringComparison.Ordinal);
            Assert.DoesNotContain("Proxy-Connection:", capturedRequests[0], StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Proxy-Connection:", capturedRequests[1], StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Connection: close", capturedRequests[0], StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Connection: close", capturedRequests[1], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_closes_after_chunked_response_even_when_keep_alive_is_requested()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, _) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\none\r\n0\r\n\r\n",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest("127.0.0.1", originPort, "/chunked-response", keepAlive: true)),
                lifetimeCts.Token);

            var responseHeader = await ReadHeaderAsync(stream, lifetimeCts.Token);
            var responseBody = Encoding.ASCII.GetString(await ReadToEndAsync(stream, lifetimeCts.Token));

            Assert.Contains("200 OK", responseHeader, StringComparison.Ordinal);
            Assert.Contains("Transfer-Encoding: chunked", responseHeader, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Proxy-Connection: close", responseHeader, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("Connection: close", responseHeader, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Proxy-Connection: keep-alive", responseHeader, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("3\r\none\r\n0\r\n\r\n", responseBody);

            await AwaitCompletionAsync(originTask);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_rejects_origin_form_request_when_allow_transparent_is_disabled()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new ThrowingTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest(
                    "127.0.0.1",
                    8080,
                    "/blocked",
                    keepAlive: false,
                    absoluteForm: false)),
                lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("400 Bad Request", response, StringComparison.Ordinal);
            Assert.Contains("Proxy-Connection: close", response, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task HttpInboundServer_accepts_origin_form_request_when_allow_transparent_is_enabled()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nallowed",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new HttpInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10,
                        AllowTransparent = true
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest(
                    "127.0.0.1",
                    originPort,
                    "/origin",
                    keepAlive: false,
                    absoluteForm: false)),
                lifetimeCts.Token);

            var response = await ReadHttpResponseAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 OK", response.HeaderText, StringComparison.Ordinal);
            Assert.Equal("allowed", response.GetBodyText());

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("127.0.0.1", context.OriginalDestinationHost);
            Assert.Equal(originPort, context.OriginalDestinationPort);

            await AwaitCompletionAsync(originTask);
            var originRequest = Assert.Single(requests);
            Assert.Contains("GET /origin HTTP/1.1", originRequest, StringComparison.Ordinal);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_forwards_informational_response_before_final_response()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, _) = StartRawHttpServer(
            1,
            static (_, _) => "HTTP/1.1 100 Continue\r\nX-Interim: yes\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest("127.0.0.1", originPort, "/info", keepAlive: false)),
                lifetimeCts.Token);

            var provisional = await ReadHeaderAsync(stream, lifetimeCts.Token);
            var final = await ReadHttpResponseAsync(stream, lifetimeCts.Token);

            Assert.Contains("100 Continue", provisional, StringComparison.Ordinal);
            Assert.Contains("X-Interim: yes", provisional, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("200 OK", final.HeaderText, StringComparison.Ordinal);
            Assert.Equal("ok", final.GetBodyText());

            await AwaitCompletionAsync(originTask);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task HttpInboundServer_forwards_100_continue_before_request_body_is_uploaded()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (originListener, originTask, originPort, requests) = StartExpectContinueServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpInboundServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var requestHeader = new StringBuilder()
                .Append("POST http://127.0.0.1:")
                .Append(originPort)
                .Append("/continue?query=1 HTTP/1.1\r\nHost: 127.0.0.1:")
                .Append(originPort)
                .Append("\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
                .ToString();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(requestHeader), lifetimeCts.Token);

            var provisional = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("100 Continue", provisional, StringComparison.Ordinal);

            await stream.WriteAsync(Encoding.ASCII.GetBytes("one"), lifetimeCts.Token);

            var final = await ReadHttpResponseAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 OK", final.HeaderText, StringComparison.Ordinal);
            Assert.Equal("ok", final.GetBodyText());

            await AwaitCompletionAsync(originTask);
            var originRequest = Assert.Single(requests);
            Assert.Contains("POST /continue?query=1 HTTP/1.1", originRequest, StringComparison.Ordinal);
            Assert.Contains("Expect: 100-continue", originRequest, StringComparison.OrdinalIgnoreCase);
            Assert.EndsWith("one", originRequest, StringComparison.Ordinal);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            originListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_accepts_http_connect_fallback()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpConnectRequest("127.0.0.1", echoPort)),
                lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var payload = Encoding.ASCII.GetBytes("hello-http-fallback");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var destination = await dispatcher.DestinationTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(ProxyInboundProtocols.Http, context.InboundProtocol);
            Assert.Equal(ProxyInboundProtocols.Http, context.InboundKind);
            Assert.Equal("socks-local", context.InboundTag);
            Assert.Equal("127.0.0.1", destination.Host);
            Assert.Equal(echoPort, destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_http_connect_fallback_uses_socks_authentication()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingTcpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["socks-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using (var unauthorizedClient = new TcpClient())
            {
                await unauthorizedClient.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
                await using var unauthorizedStream = unauthorizedClient.GetStream();

                await unauthorizedStream.WriteAsync(
                    Encoding.ASCII.GetBytes(CreateHttpConnectRequest("127.0.0.1", echoPort)),
                    lifetimeCts.Token);

                var unauthorizedResponse = await ReadHeaderAsync(unauthorizedStream, lifetimeCts.Token);
                Assert.Contains("407 Proxy Authentication Required", unauthorizedResponse, StringComparison.Ordinal);
            }

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpConnectRequest(
                    "127.0.0.1",
                    echoPort,
                    CreateBasicProxyAuthorizationHeaderValue("alice", "secret"))),
                lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var payload = Encoding.ASCII.GetBytes("hello-http-fallback-auth");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(ProxyInboundProtocols.Http, context.InboundProtocol);
            Assert.Equal("alice", context.UserId);
            Assert.Equal("alice", context.ScopedUserId);
            Assert.Equal("127.0.0.1", context.OriginalDestinationHost);
            Assert.Equal(echoPort, context.OriginalDestinationPort);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task SocksInboundServer_http_fallback_rejects_origin_form_even_when_listener_allows_transparent()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new SocksInboundServer(new ThrowingTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10,
                        AllowTransparent = true
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes(CreateHttpGetRequest(
                    "127.0.0.1",
                    8080,
                    "/fallback-origin",
                    keepAlive: false,
                    absoluteForm: false)),
                lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("400 Bad Request", response, StringComparison.Ordinal);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task SocksInboundServer_relays_udp_associate_traffic_and_marks_udp_source_context()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingUdpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var controlStream = tcpClient.GetStream();

            await controlStream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(controlStream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            await controlStream.WriteAsync(
                new byte[]
                {
                    0x05, 0x03, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                },
                lifetimeCts.Token);

            var reply = await ReadSocks5ReplyAsync(controlStream, lifetimeCts.Token);
            Assert.Equal(Socks5ProtocolConstants.ReplySucceeded, reply.ReplyCode);
            Assert.Equal(proxyPort, reply.Port);

            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var requestPayload = Socks5UdpPacketCodec.Encode("8.8.8.8", 53, Encoding.ASCII.GetBytes("ping"));
            await udpClient.SendAsync(
                requestPayload,
                new IPEndPoint(IPAddress.Parse(reply.Host), reply.Port),
                lifetimeCts.Token);

            var response = await udpClient.ReceiveAsync(lifetimeCts.Token);
            var packet = Socks5UdpPacketCodec.Decode(response.Buffer);
            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var capture = await dispatcher.CaptureTcs.Task.WaitAsync(lifetimeCts.Token);

            Assert.Equal("8.8.8.8", packet.Host);
            Assert.Equal(53, packet.Port);
            Assert.Equal("pong", Encoding.ASCII.GetString(packet.Payload));

            Assert.Equal("8.8.8.8", capture.Host);
            Assert.Equal(53, capture.Port);
            Assert.Equal("ping", capture.PayloadText);

            Assert.Equal(ProxyInboundProtocols.Socks, context.InboundProtocol);
            Assert.Equal(ProxyInboundProtocols.Socks, context.InboundKind);
            Assert.Equal(RoutingNetworks.Udp, context.Network);
            Assert.Equal(RoutingNetworks.Udp, context.InboundSourceNetwork);
            Assert.Equal("8.8.8.8", context.OriginalDestinationHost);
            Assert.Equal(53, context.OriginalDestinationPort);

            var udpSource = Assert.IsType<IPEndPoint>(context.SourceEndPoint);
            var udpLocal = Assert.IsType<IPEndPoint>(context.LocalEndPoint);
            var clientLocal = Assert.IsType<IPEndPoint>(udpClient.Client.LocalEndPoint);
            Assert.Equal(clientLocal.Port, udpSource.Port);
            Assert.Equal(reply.Port, udpLocal.Port);
            Assert.NotEqual(new byte[8], TrojanMuxProtocol.CreateGlobalId(context));
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task SocksInboundServer_overrides_fake_dns_metadata_for_udp_associate_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("localhost", ipv4: true, ipv6: false));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new CapturingUdpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService(), fakeDnsEngine);
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10,
                        Sniffing = new RuntimeSniffingOptions
                        {
                            Enabled = true,
                            MetadataOnly = true,
                            DestinationOverride = [RoutingProtocols.FakeDns]
                        }
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var controlStream = tcpClient.GetStream();

            await controlStream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(controlStream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            await controlStream.WriteAsync(
                new byte[]
                {
                    0x05, 0x03, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                },
                lifetimeCts.Token);

            var reply = await ReadSocks5ReplyAsync(controlStream, lifetimeCts.Token);
            Assert.Equal(Socks5ProtocolConstants.ReplySucceeded, reply.ReplyCode);
            Assert.Equal(proxyPort, reply.Port);

            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var requestPayload = Socks5UdpPacketCodec.Encode(fakeAddress.ToString(), 53, Encoding.ASCII.GetBytes("ping"));
            await udpClient.SendAsync(
                requestPayload,
                new IPEndPoint(IPAddress.Parse(reply.Host), reply.Port),
                lifetimeCts.Token);

            var response = await udpClient.ReceiveAsync(lifetimeCts.Token);
            var packet = Socks5UdpPacketCodec.Decode(response.Buffer);
            var context = await dispatcher.ContextTcs.Task.WaitAsync(lifetimeCts.Token);
            var capture = await dispatcher.CaptureTcs.Task.WaitAsync(lifetimeCts.Token);

            Assert.Equal("localhost", packet.Host);
            Assert.Equal(53, packet.Port);
            Assert.Equal("pong", Encoding.ASCII.GetString(packet.Payload));

            Assert.Equal(fakeAddress.ToString(), context.OriginalDestinationHost);
            Assert.Equal("localhost", context.TargetHost);
            Assert.Equal(RoutingProtocols.FakeDns, context.DetectedProtocol);
            Assert.Equal("localhost", context.DetectedDomain);

            Assert.Equal("localhost", capture.Host);
            Assert.Equal(53, capture.Port);
            Assert.Equal("ping", capture.PayloadText);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task SocksInboundServer_authenticated_udp_associate_requires_authorized_source_ip()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new RecordingUdpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                AuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                {
                    ["socks-local"] = Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])
                },
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var unauthorizedPayload = Socks5UdpPacketCodec.Encode("8.8.8.8", 53, Encoding.ASCII.GetBytes("unauthorized"));
            await udpClient.SendAsync(
                unauthorizedPayload,
                new IPEndPoint(IPAddress.Loopback, proxyPort),
                lifetimeCts.Token);

            using (var unauthorizedCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400)))
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(
                    async () =>
                    {
                        await udpClient.ReceiveAsync(unauthorizedCts.Token);
                    });
                await Assert.ThrowsAnyAsync<OperationCanceledException>(
                    async () =>
                    {
                        await dispatcher.ReadContextAsync(unauthorizedCts.Token);
                    });
            }

            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var controlStream = tcpClient.GetStream();

            await controlStream.WriteAsync(new byte[] { 0x05, 0x02, 0x00, 0x02 }, lifetimeCts.Token);
            var method = new byte[2];
            await ReadExactAsync(controlStream, method, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x02 }, method);

            await WriteSocks5UsernamePasswordAsync(controlStream, "alice", "secret", lifetimeCts.Token);
            var authStatus = new byte[2];
            await ReadExactAsync(controlStream, authStatus, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x01, 0x00 }, authStatus);

            await controlStream.WriteAsync(
                new byte[]
                {
                    0x05, 0x03, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                },
                lifetimeCts.Token);

            var reply = await ReadSocks5ReplyAsync(controlStream, lifetimeCts.Token);
            Assert.Equal(Socks5ProtocolConstants.ReplySucceeded, reply.ReplyCode);
            Assert.Equal(proxyPort, reply.Port);

            var authorizedPayload = Socks5UdpPacketCodec.Encode("1.1.1.1", 53, Encoding.ASCII.GetBytes("authorized"));
            await udpClient.SendAsync(
                authorizedPayload,
                new IPEndPoint(IPAddress.Parse(reply.Host), reply.Port),
                lifetimeCts.Token);

            var response = await udpClient.ReceiveAsync(lifetimeCts.Token);
            var packet = Socks5UdpPacketCodec.Decode(response.Buffer);
            var context = await dispatcher.ReadContextAsync(lifetimeCts.Token);
            var capture = await dispatcher.ReadCaptureAsync(lifetimeCts.Token);

            Assert.Equal("1.1.1.1", packet.Host);
            Assert.Equal(53, packet.Port);
            Assert.Equal("pong", Encoding.ASCII.GetString(packet.Payload));
            Assert.Equal("1.1.1.1", capture.Host);
            Assert.Equal("authorized", capture.PayloadText);

            var source = Assert.IsType<IPEndPoint>(context.SourceEndPoint);
            var clientLocal = Assert.IsType<IPEndPoint>(udpClient.Client.LocalEndPoint);
            Assert.Equal(clientLocal.Port, source.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    [Fact]
    public async Task SocksInboundServer_udp_associate_accepts_same_source_ip_from_multiple_udp_ports()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var dispatcher = new RecordingUdpDispatcher();
        var server = new SocksInboundServer(dispatcher, new RelayService());
        var serverTask = server.RunAsync(
            new SocksInboundServerOptions
            {
                Listeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new ProxyInboundServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var controlStream = tcpClient.GetStream();

            await controlStream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(controlStream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            await controlStream.WriteAsync(
                new byte[]
                {
                    0x05, 0x03, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                },
                lifetimeCts.Token);

            var reply = await ReadSocks5ReplyAsync(controlStream, lifetimeCts.Token);
            Assert.Equal(Socks5ProtocolConstants.ReplySucceeded, reply.ReplyCode);
            Assert.Equal(proxyPort, reply.Port);

            using var udpClient1 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            using var udpClient2 = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

            var endpoint = new IPEndPoint(IPAddress.Parse(reply.Host), reply.Port);
            await udpClient1.SendAsync(
                Socks5UdpPacketCodec.Encode("8.8.8.8", 53, Encoding.ASCII.GetBytes("first")),
                endpoint,
                lifetimeCts.Token);
            var response1 = await udpClient1.ReceiveAsync(lifetimeCts.Token);

            await udpClient2.SendAsync(
                Socks5UdpPacketCodec.Encode("1.1.1.1", 53, Encoding.ASCII.GetBytes("second")),
                endpoint,
                lifetimeCts.Token);
            var response2 = await udpClient2.ReceiveAsync(lifetimeCts.Token);

            var decoded1 = Socks5UdpPacketCodec.Decode(response1.Buffer);
            var decoded2 = Socks5UdpPacketCodec.Decode(response2.Buffer);
            Assert.Equal("pong", Encoding.ASCII.GetString(decoded1.Payload));
            Assert.Equal("pong", Encoding.ASCII.GetString(decoded2.Payload));
            Assert.Equal("8.8.8.8", decoded1.Host);
            Assert.Equal("1.1.1.1", decoded2.Host);

            var context1 = await dispatcher.ReadContextAsync(lifetimeCts.Token);
            var context2 = await dispatcher.ReadContextAsync(lifetimeCts.Token);
            var capture1 = await dispatcher.ReadCaptureAsync(lifetimeCts.Token);
            var capture2 = await dispatcher.ReadCaptureAsync(lifetimeCts.Token);

            var source1 = Assert.IsType<IPEndPoint>(context1.SourceEndPoint);
            var source2 = Assert.IsType<IPEndPoint>(context2.SourceEndPoint);
            Assert.Equal(IPAddress.Loopback, source1.Address);
            Assert.Equal(IPAddress.Loopback, source2.Address);
            Assert.NotEqual(source1.Port, source2.Port);

            Assert.Equal("first", capture1.PayloadText);
            Assert.Equal("second", capture2.PayloadText);
            Assert.Equal("8.8.8.8", capture1.Host);
            Assert.Equal("1.1.1.1", capture2.Host);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
        }
    }

    private static (TcpListener Listener, Task Task, int Port) StartEchoServer(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = RunEchoServerAsync(listener, cancellationToken);
        return (listener, task, port);
    }

    private static async Task RunEchoServerAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = client.GetStream();
            var buffer = new byte[4096];

            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private static (TcpListener Listener, Task Task, int Port, System.Collections.Concurrent.ConcurrentQueue<string> Requests) StartRawHttpServer(
        int expectedConnections,
        Func<int, string, string> responseFactory,
        CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var requests = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = RunRawHttpServerAsync(listener, expectedConnections, responseFactory, requests, cancellationToken);
        return (listener, task, port, requests);
    }

    private static async Task RunRawHttpServerAsync(
        TcpListener listener,
        int expectedConnections,
        Func<int, string, string> responseFactory,
        System.Collections.Concurrent.ConcurrentQueue<string> requests,
        CancellationToken cancellationToken)
    {
        try
        {
            for (var index = 0; index < expectedConnections && !cancellationToken.IsCancellationRequested; index++)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken);
                await using var stream = client.GetStream();

                var requestHeader = await ReadHeaderAsync(stream, cancellationToken);
                var requestBody = await ReadHttpBodyAsync(stream, requestHeader, cancellationToken);
                var requestText = requestHeader + requestBody;
                requests.Enqueue(requestText);

                var response = responseFactory(index, requestText);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private static (TcpListener Listener, Task Task, int Port, System.Collections.Concurrent.ConcurrentQueue<string> Requests) StartExpectContinueServer(
        CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var requests = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = RunExpectContinueServerAsync(listener, requests, cancellationToken);
        return (listener, task, port, requests);
    }

    private static async Task RunExpectContinueServerAsync(
        TcpListener listener,
        System.Collections.Concurrent.ConcurrentQueue<string> requests,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = client.GetStream();

            var requestHeader = await ReadHeaderAsync(stream, cancellationToken);
            await stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\nX-Continue: yes\r\n\r\n"),
                cancellationToken);
            await stream.FlushAsync(cancellationToken);

            var requestBody = await ReadHttpBodyAsync(stream, requestHeader, cancellationToken);
            requests.Enqueue(requestHeader + requestBody);

            await stream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
                cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private static int GetAvailableTcpPort()
    {
        for (var attempt = 0; attempt < 128; attempt++)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, port));
                return port;
            }
            catch (SocketException)
            {
            }
        }

        throw new InvalidOperationException("Unable to allocate a loopback port that supports both TCP and UDP.");
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream.");
            }

            offset += read;
        }
    }

    private static async Task<string> ReadHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();
        var single = new byte[1];

        while (buffer.Count < 8192)
        {
            var read = await stream.ReadAsync(single.AsMemory(0, 1), cancellationToken);
            if (read == 0)
            {
                break;
            }

            buffer.Add(single[0]);
            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' &&
                buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' &&
                buffer[^1] == (byte)'\n')
            {
                break;
            }
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static async Task<string> ReadHttpBodyAsync(
        Stream stream,
        string headerText,
        CancellationToken cancellationToken)
    {
        if (HasChunkedTransferEncoding(headerText))
        {
            var chunkedPayload = await ReadChunkedPayloadAsync(stream, cancellationToken);
            return Encoding.ASCII.GetString(chunkedPayload);
        }

        var contentLength = GetContentLength(headerText);
        if (contentLength <= 0)
        {
            return string.Empty;
        }

        var body = await ReadBytesAsync(stream, contentLength, cancellationToken);
        return Encoding.ASCII.GetString(body);
    }

    private static bool HasChunkedTransferEncoding(string headerText)
    {
        foreach (var line in headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            const string prefix = "Transfer-Encoding:";
            if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return line[prefix.Length..]
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Any(static value => value.Equals("chunked", StringComparison.OrdinalIgnoreCase));
        }

        return false;
    }

    private static async Task<byte[]> ReadChunkedPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();

        while (true)
        {
            var chunkHeader = await ReadLineBytesAsync(stream, cancellationToken);
            buffer.AddRange(chunkHeader);

            var headerText = Encoding.ASCII.GetString(chunkHeader).TrimEnd('\r', '\n');
            var sizeText = headerText.Split(';', 2)[0].Trim();
            if (!int.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var chunkSize) ||
                chunkSize < 0)
            {
                throw new InvalidDataException("Chunked HTTP payload header is invalid.");
            }

            if (chunkSize == 0)
            {
                while (true)
                {
                    var trailerLine = await ReadLineBytesAsync(stream, cancellationToken);
                    buffer.AddRange(trailerLine);
                    if (trailerLine.Length == 2 &&
                        trailerLine[0] == (byte)'\r' &&
                        trailerLine[1] == (byte)'\n')
                    {
                        return buffer.ToArray();
                    }
                }
            }

            var chunkPayload = await ReadBytesAsync(stream, chunkSize + 2, cancellationToken);
            buffer.AddRange(chunkPayload);
        }
    }

    private static async Task<byte[]> ReadLineBytesAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();
        var single = new byte[1];

        while (buffer.Count < 8192)
        {
            var read = await stream.ReadAsync(single.AsMemory(0, 1), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of chunked payload.");
            }

            buffer.Add(single[0]);
            if (single[0] == (byte)'\n')
            {
                return buffer.ToArray();
            }
        }

        throw new InvalidDataException("HTTP line exceeds maximum test limit.");
    }

    private static async Task<byte[]> ReadToEndAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[4096];

        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            if (read == 0)
            {
                return output.ToArray();
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
    }

    private static async Task<RawHttpResponse> ReadHttpResponseAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = await ReadHeaderAsync(stream, cancellationToken);
        var contentLength = GetContentLength(header);
        var body = contentLength > 0
            ? await ReadBytesAsync(stream, contentLength, cancellationToken)
            : Array.Empty<byte>();
        return new RawHttpResponse(header, body);
    }

    private static async Task<Socks5Reply> ReadSocks5ReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await ReadExactAsync(stream, header, cancellationToken);

        var addressTail = header[3] switch
        {
            0x01 => await ReadBytesAsync(stream, 6, cancellationToken),
            0x03 => await ReadDomainAddressTailAsync(stream, cancellationToken),
            0x04 => await ReadBytesAsync(stream, 18, cancellationToken),
            _ => throw new InvalidDataException($"Unsupported SOCKS5 reply address type: {header[3]}.")
        };

        var addressBuffer = new byte[1 + addressTail.Length];
        addressBuffer[0] = header[3];
        addressTail.CopyTo(addressBuffer, 1);
        var target = Socks5AddressCodec.ReadAddressPort(addressBuffer);
        return new Socks5Reply(header[1], target.Host, target.Port);
    }

    private static async Task<Socks4Reply> ReadSocks4ReplyAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[8];
        await ReadExactAsync(stream, buffer, cancellationToken);
        return new Socks4Reply(
            buffer[1],
            BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2, 2)),
            new IPAddress(buffer.AsSpan(4, 4)).ToString());
    }

    private static async Task<byte[]> ReadDomainAddressTailAsync(Stream stream, CancellationToken cancellationToken)
    {
        var lengthBuffer = await ReadBytesAsync(stream, 1, cancellationToken);
        var tail = new byte[1 + lengthBuffer[0] + 2];
        tail[0] = lengthBuffer[0];

        var remainder = await ReadBytesAsync(stream, tail.Length - 1, cancellationToken);
        remainder.CopyTo(tail, 1);
        return tail;
    }

    private static async Task<byte[]> ReadBytesAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await ReadExactAsync(stream, buffer, cancellationToken);
        return buffer;
    }

    private static async Task WriteSocks5ConnectRequestAsync(
        Stream stream,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        var addressLength = Socks5AddressCodec.GetSerializedLength(host);
        var target = new byte[addressLength];
        Socks5AddressCodec.WriteAddressPort(target, host, port);

        var request = new List<byte>
        {
            0x05, 0x01, 0x00
        };
        request.AddRange(target);
        await stream.WriteAsync(request.ToArray(), cancellationToken);
    }

    private static async Task WriteSocks4ConnectRequestAsync(
        Stream stream,
        string host,
        int port,
        CancellationToken cancellationToken,
        string userId = "user",
        bool useSocks4a = false)
    {
        var request = new List<byte>
        {
            Socks4ProtocolConstants.Version,
            Socks4ProtocolConstants.CommandConnect,
            (byte)(port >> 8),
            (byte)(port & 0xFF)
        };

        if (useSocks4a)
        {
            request.AddRange([0x00, 0x00, 0x00, 0x01]);
        }
        else
        {
            request.AddRange(IPAddress.Parse(host).GetAddressBytes());
        }

        request.AddRange(Encoding.ASCII.GetBytes(userId));
        request.Add(0x00);

        if (useSocks4a)
        {
            request.AddRange(Encoding.ASCII.GetBytes(host));
            request.Add(0x00);
        }

        await stream.WriteAsync(request.ToArray(), cancellationToken);
    }

    private static async Task WriteSocks5UsernamePasswordAsync(
        Stream stream,
        string username,
        string password,
        CancellationToken cancellationToken)
    {
        var usernameBytes = Encoding.UTF8.GetBytes(username);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var payload = new byte[3 + usernameBytes.Length + passwordBytes.Length];
        payload[0] = 0x01;
        payload[1] = (byte)usernameBytes.Length;
        usernameBytes.CopyTo(payload.AsSpan(2));
        payload[2 + usernameBytes.Length] = (byte)passwordBytes.Length;
        passwordBytes.CopyTo(payload.AsSpan(3 + usernameBytes.Length));
        await stream.WriteAsync(payload, cancellationToken);
    }

    private static string CreateHttpConnectRequest(
        string host,
        int port,
        string? proxyAuthorization = null)
    {
        var builder = new StringBuilder()
            .Append("CONNECT ")
            .Append(host)
            .Append(':')
            .Append(port)
            .Append(" HTTP/1.1\r\nHost: ")
            .Append(host)
            .Append(':')
            .Append(port)
            .Append("\r\n");

        if (!string.IsNullOrWhiteSpace(proxyAuthorization))
        {
            builder.Append("Proxy-Authorization: ")
                .Append(proxyAuthorization)
                .Append("\r\n");
        }

        builder.Append("\r\n");
        return builder.ToString();
    }

    private static string CreateHttpGetRequest(
        string host,
        int port,
        string path,
        bool keepAlive,
        bool absoluteForm = true,
        string? proxyAuthorization = null,
        string? hostHeaderOverride = null,
        IReadOnlyList<KeyValuePair<string, string>>? additionalHeaders = null)
    {
        var builder = new StringBuilder()
            .Append("GET ");

        if (absoluteForm)
        {
            builder.Append("http://")
                .Append(host)
                .Append(':')
                .Append(port);
        }

        builder.Append(path)
            .Append(" HTTP/1.1\r\nHost: ")
            .Append(hostHeaderOverride ?? host)
            .Append(hostHeaderOverride is null ? $":{port}" : string.Empty)
            .Append("\r\n");

        if (keepAlive)
        {
            builder.Append("Proxy-Connection: keep-alive\r\n");
        }

        if (!string.IsNullOrWhiteSpace(proxyAuthorization))
        {
            builder.Append("Proxy-Authorization: ")
                .Append(proxyAuthorization)
                .Append("\r\n");
        }

        foreach (var header in additionalHeaders ?? Array.Empty<KeyValuePair<string, string>>())
        {
            builder.Append(header.Key)
                .Append(": ")
                .Append(header.Value)
                .Append("\r\n");
        }

        builder.Append("\r\n");
        return builder.ToString();
    }

    private static int GetContentLength(string headerText)
    {
        foreach (var line in headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            const string prefix = "Content-Length:";
            if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return int.TryParse(line[prefix.Length..].Trim(), out var contentLength)
                ? Math.Max(0, contentLength)
                : 0;
        }

        return 0;
    }

    private static string CreateBasicProxyAuthorizationHeaderValue(string username, string password)
        => $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))}";

    private static FakeDnsEngine CreateFakeDnsEngine()
        => new(
        [
            new FakeDnsPoolRuntime
            {
                IpPool = FakeDnsDefaults.IPv4Pool,
                LruSize = 256
            }
        ]);

    private static async Task AwaitCompletionAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private sealed class DirectTcpDispatcher : IDispatcher
    {
        public async ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            var client = new TcpClient();
            await client.ConnectAsync(destination.Host, destination.Port, cancellationToken);
            return client.GetStream();
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class ThrowingTcpDispatcher : IDispatcher
    {
        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new InvalidOperationException("TCP dispatch should not be invoked for this test.");

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class CapturingTcpDispatcher : IDispatcher
    {
        public TaskCompletionSource<DispatchContext> ContextTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<DispatchDestination> DestinationTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            ContextTcs.TrySetResult(context);
            DestinationTcs.TrySetResult(destination);

            var client = new TcpClient();
            var host = string.Equals(destination.Host, "localhost", StringComparison.OrdinalIgnoreCase)
                ? IPAddress.Loopback.ToString()
                : destination.Host;
            await client.ConnectAsync(host, destination.Port, cancellationToken);
            return client.GetStream();
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class CapturingUdpDispatcher : IDispatcher
    {
        public TaskCompletionSource<DispatchContext> ContextTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<UdpSendCapture> CaptureTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
        {
            ContextTcs.TrySetResult(context);
            return ValueTask.FromResult<IOutboundUdpTransport>(new EchoUdpTransport(CaptureTcs));
        }
    }

    private sealed class EchoUdpTransport : IOutboundUdpTransport
    {
        private readonly TaskCompletionSource<UdpSendCapture> _captureTcs;
        private readonly System.Threading.Channels.Channel<DispatchDatagram> _responses =
            System.Threading.Channels.Channel.CreateUnbounded<DispatchDatagram>();

        public EchoUdpTransport(TaskCompletionSource<UdpSendCapture> captureTcs)
        {
            _captureTcs = captureTcs;
        }

        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            _captureTcs.TrySetResult(new UdpSendCapture(
                destination.Host,
                destination.Port,
                Encoding.ASCII.GetString(payload.Span)));
            _responses.Writer.TryWrite(
                new DispatchDatagram
                {
                    SourceHost = destination.Host,
                    SourcePort = destination.Port,
                    Payload = Encoding.ASCII.GetBytes("pong")
                });
            return ValueTask.CompletedTask;
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => await _responses.Reader.ReadAsync(cancellationToken);

        public ValueTask DisposeAsync()
        {
            _responses.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class RecordingUdpDispatcher : IDispatcher
    {
        private readonly System.Threading.Channels.Channel<DispatchContext> _contexts =
            System.Threading.Channels.Channel.CreateUnbounded<DispatchContext>();
        private readonly System.Threading.Channels.Channel<UdpSendCapture> _captures =
            System.Threading.Channels.Channel.CreateUnbounded<UdpSendCapture>();

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
        {
            _contexts.Writer.TryWrite(context);
            return ValueTask.FromResult<IOutboundUdpTransport>(new RecordingEchoUdpTransport(_captures));
        }

        public async Task<DispatchContext> ReadContextAsync(CancellationToken cancellationToken)
            => await _contexts.Reader.ReadAsync(cancellationToken);

        public async Task<UdpSendCapture> ReadCaptureAsync(CancellationToken cancellationToken)
            => await _captures.Reader.ReadAsync(cancellationToken);
    }

    private sealed class RecordingEchoUdpTransport : IOutboundUdpTransport
    {
        private readonly System.Threading.Channels.Channel<UdpSendCapture> _captures;
        private readonly System.Threading.Channels.Channel<DispatchDatagram> _responses =
            System.Threading.Channels.Channel.CreateUnbounded<DispatchDatagram>();

        public RecordingEchoUdpTransport(System.Threading.Channels.Channel<UdpSendCapture> captures)
        {
            _captures = captures;
        }

        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            _captures.Writer.TryWrite(new UdpSendCapture(
                destination.Host,
                destination.Port,
                Encoding.ASCII.GetString(payload.Span)));
            _responses.Writer.TryWrite(
                new DispatchDatagram
                {
                    SourceHost = destination.Host,
                    SourcePort = destination.Port,
                    Payload = Encoding.ASCII.GetBytes("pong")
                });
            return ValueTask.CompletedTask;
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => await _responses.Reader.ReadAsync(cancellationToken);

        public ValueTask DisposeAsync()
        {
            _responses.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }

    private sealed record RawHttpResponse(string HeaderText, byte[] Body)
    {
        public string GetBodyText() => Encoding.ASCII.GetString(Body);
    }

    private sealed record Socks5Reply(byte ReplyCode, string Host, int Port);

    private sealed record Socks4Reply(byte ReplyCode, int Port, string Host);

    private sealed record UdpSendCapture(string Host, int Port, string PayloadText);
}

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class DefaultRuntimeTests
{
    private const string EchoInboundProtocol = "echo-inbound";
    private const string EchoTunnelProtocol = "echo-tunnel";
    private const int LoopbackPortRangeStart = 20_000;
    private const int LoopbackPortRangeEnd = 60_000;
    private static int _nextLoopbackPort = LoopbackPortRangeStart - 1;

    [Fact]
    public void RuntimeComponentCatalog_rejects_duplicate_builtin_outbound_protocol_without_replace_flag()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeComponentCatalog.Create(
            registry => registry
                .AddSingleton(_ => new TaskCompletionSource<FreedomOverrideOpenCall>(TaskCreationOptions.RunContinuationsAsynchronously))
                .AddSingleton(resolver => new OverrideFreedomOutboundHandler(
                    new FreedomOverrideTarget("127.0.0.1", 1),
                    resolver.GetRequired<TaskCompletionSource<FreedomOverrideOpenCall>>())),
            outboundFactories:
            [
                new ResolvedRuntimeOutboundHandlerFactory<OverrideFreedomOutboundHandler>(OutboundProtocols.Freedom)
            ]));

        Assert.Equal("Runtime outbound handler factory 'freedom' is already registered.", exception.Message);
    }

    [Fact]
    public void RuntimeComponentCatalog_rejects_duplicate_builtin_inbound_protocol_without_replace_flag()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeComponentCatalog.Create(
            inboundFactories:
            [
                new OverrideSocksInboundHandlerFactory()
            ]));

        Assert.Equal("Runtime inbound handler factory 'socks' is already registered.", exception.Message);
    }

    [Fact]
    public void RuntimeComponentRegistry_rejects_duplicate_service_type_without_replace_flag()
    {
        var registry = new RuntimeComponentRegistry()
            .AddSingleton(_ => new RegistryMarkerService("first"));

        var exception = Assert.Throws<InvalidOperationException>(() => registry.AddSingleton(_ => new RegistryMarkerService("second")));

        Assert.Equal("Runtime component 'RegistryMarkerService' is already registered.", exception.Message);
    }

    [Fact]
    public void RuntimeComponentRegistry_can_replace_existing_service_type_when_flag_enabled()
    {
        var registry = new RuntimeComponentRegistry()
            .AddSingleton(_ => new RegistryMarkerService("first"))
            .AddSingleton(_ => new RegistryMarkerService("second"), replaceExisting: true);

        var resolved = registry.CreateResolver(CreateTestSharedContext()).GetRequired<RegistryMarkerService>();

        Assert.Equal("second", resolved.Value);
    }

    [Fact]
    public void RuntimeComponentRegistry_can_initialize_required_resolution_graph_once()
    {
        var recorder = new RegistryResolutionRecorder();
        var registry = new RuntimeComponentRegistry()
            .AddSingleton(_ => new RegistryMarkerService("graph"))
            .AddSingleton(_ => recorder)
            .Require<RegistryMarkerService, RegistryResolutionRecorder>((marker, resolutionRecorder) =>
                resolutionRecorder.Record(marker.Value));

        var resolver = registry.CreateResolver(CreateTestSharedContext());

        resolver.InitializeGraph();
        resolver.InitializeGraph();

        Assert.Equal(1, recorder.RecordCallCount);
        Assert.Equal("graph", recorder.LastValue);
    }

    [Fact]
    public void RuntimeComponentRegistry_skips_optional_resolution_when_service_is_missing()
    {
        var recorder = new RegistryResolutionRecorder();
        var registry = new RuntimeComponentRegistry()
            .AddSingleton(_ => recorder)
            .Optional<RegistryMarkerService>(marker => recorder.Record(marker.Value));

        var resolver = registry.CreateResolver(CreateTestSharedContext());

        resolver.InitializeGraph();

        Assert.Equal(0, recorder.RecordCallCount);
        Assert.Equal(string.Empty, recorder.LastValue);
        Assert.Null(resolver.GetOptional<RegistryMarkerService>());
    }

    [Fact]
    public async Task DefaultRuntime_can_start_socks_local_proxy_and_relay_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(RuntimeState.Running, listener.State);
            Assert.Equal(ProxyInboundProtocols.Socks, listener.Protocol);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-socks");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            await host.StopAsync(lifetimeCts.Token);
            Assert.Equal(RuntimeState.Stopped, host.GetStatus().State);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_authenticated_socks_local_proxy_and_relay_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateSocksPlan(
                    1,
                    proxyPort,
                    Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])),
                lifetimeCts.Token);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-socks-auth");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_reload_from_socks_to_http_proxy()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var socksPort = GetAvailableTcpPort();
        var httpPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(CreateSocksPlan(1, socksPort), lifetimeCts.Token);
            await host.ReloadAsync(CreateHttpPlan(2, httpPort), lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(2, status.Revision);
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(ProxyInboundProtocols.Http, listener.Protocol);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, httpPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var request = $"CONNECT 127.0.0.1:{echoPort} HTTP/1.1\r\nHost: 127.0.0.1:{echoPort}\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-http");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_authenticated_http_local_proxy_and_relay_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateHttpPlan(
                    1,
                    proxyPort,
                    Socks5LocalAuthenticationOptions.Create(
                    [
                        new Socks5LocalUserCredential
                        {
                            Username = "alice",
                            Password = "secret"
                        }
                    ])),
                lifetimeCts.Token);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-http-auth");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_throws_when_plan_uses_unsupported_custom_inbound_protocol()
    {
        var inboundPort = GetAvailableTcpPort();
        var plan = CreateCustomInboundPlan(1, inboundPort, targetPort: 1);
        await using var host = new DefaultRuntime();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(plan));
        Assert.Equal("Inbound protocol 'echo-inbound' is not supported.", exception.Message);
    }

    [Fact]
    public async Task DefaultRuntime_can_start_dokodemo_door_inbound_and_relay_tcp()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(CreateDokodemoPlan(1, inboundPort, "127.0.0.1", echoPort), lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(InboundProtocols.DokodemoDoor, listener.Protocol);
            Assert.Equal("dokodemo-inbound", listener.Tag);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-dokodemo");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_dokodemo_door_inbound_and_relay_udp()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoServer, echoTask, echoPort) = StartUdpEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateDokodemoPlan(
                    1,
                    inboundPort,
                    "127.0.0.1",
                    echoPort,
                    networks: [RoutingNetworks.Udp]),
                lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(InboundProtocols.DokodemoDoor, listener.Protocol);
            Assert.Equal("dokodemo-inbound", listener.Tag);
            Assert.Equal(RoutingNetworks.Udp, listener.Transport);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-dokodemo-udp");
            await client.SendAsync(payload, payload.Length, new IPEndPoint(IPAddress.Loopback, inboundPort));

            var response = await client.ReceiveAsync(lifetimeCts.Token);
            Assert.Equal(payload, response.Buffer);
        }
        finally
        {
            lifetimeCts.Cancel();
            echoServer.Dispose();
            await AwaitCompletionAsync(echoTask);
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_dokodemo_door_udp_follow_redirect()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var inboundPort = GetAvailableTcpPort();
        await using var host = new DefaultRuntime();

        await host.StartAsync(
            CreateDokodemoPlan(
                1,
                inboundPort,
                destinationHost: string.Empty,
                destinationPort: 0,
                networks: [RoutingNetworks.Udp],
                followRedirect: true),
            lifetimeCts.Token);

        var status = host.GetStatus();
        Assert.Equal(RuntimeState.Running, status.State);
        var listener = Assert.Single(status.Listeners);
        Assert.Equal(InboundProtocols.DokodemoDoor, listener.Protocol);
        Assert.Equal("dokodemo-inbound", listener.Tag);
        Assert.Equal(RoutingNetworks.Udp, listener.Transport);
        Assert.Equal(RuntimeState.Running, listener.State);

        await host.StopAsync(lifetimeCts.Token);
        Assert.Equal(RuntimeState.Stopped, host.GetStatus().State);
    }

    [Fact]
    public async Task DefaultRuntime_can_start_shadowsocks_2022_single_user_inbound_and_relay_tcp()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        var serverKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm);
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateShadowsocks2022InboundPlan(1, inboundPort, serverKey: serverKey),
                lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(InboundProtocols.Shadowsocks, listener.Protocol);
            Assert.Equal("ss-2022", listener.Tag);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var transport = client.GetStream();

            var account = Shadowsocks2022Account.Create(
                ShadowsocksCipherTypes.Blake3Aes128Gcm,
                serverKey);
            await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                transport,
                account,
                "127.0.0.1",
                echoPort,
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-ss2022");
            await stream.WriteAsync(payload, lifetimeCts.Token);
            await stream.FlushAsync(lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_shadowsocks_2022_single_user_inbound_and_relay_udp()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoServer, echoTask, echoPort) = StartUdpEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        var serverKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm);
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateShadowsocks2022InboundPlan(
                    1,
                    inboundPort,
                    networks: [RoutingNetworks.Udp],
                    serverKey: serverKey),
                lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(InboundProtocols.Shadowsocks, listener.Protocol);
            Assert.Equal("ss-2022", listener.Tag);
            Assert.Equal(RoutingNetworks.Udp, listener.Transport);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var account = Shadowsocks2022Account.Create(
                ShadowsocksCipherTypes.Blake3Aes128Gcm,
                serverKey);
            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-ss2022-udp");
            var packet = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
                account,
                "127.0.0.1",
                echoPort,
                payload);

            await client.SendAsync(packet, packet.Length, new IPEndPoint(IPAddress.Loopback, inboundPort));

            var response = await client.ReceiveAsync(lifetimeCts.Token);
            var decoded = Shadowsocks2022ProtocolCodec.DecodeUdpPacket(account, response.Buffer);

            Assert.Equal("127.0.0.1", decoded.Host);
            Assert.Equal(echoPort, decoded.Port);
            Assert.Equal(payload, decoded.Payload);
        }
        finally
        {
            lifetimeCts.Cancel();
            echoServer.Dispose();
            await AwaitCompletionAsync(echoTask);
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_shadowsocks_2022_multi_user_inbound_and_relay_tcp()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        var serverKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm);
        var userKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm, 32);
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateShadowsocks2022InboundPlan(
                    1,
                    inboundPort,
                    Shadowsocks2022InboundModes.MultiUser,
                    [
                        new Shadowsocks2022User
                        {
                            UserId = "user-a",
                            Password = userKey,
                            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022", "user-a"),
                            BytesPerSecond = 0
                        }
                    ],
                    serverKey: serverKey),
                lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var transport = client.GetStream();

            var account = Shadowsocks2022Account.Create(
                ShadowsocksCipherTypes.Blake3Aes128Gcm,
                $"{serverKey}:{userKey}");
            await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                transport,
                account,
                "127.0.0.1",
                echoPort,
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-ss2022-multi");
            await stream.WriteAsync(payload, lifetimeCts.Token);
            await stream.FlushAsync(lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_shadowsocks_2022_relay_inbound_and_ignore_requested_destination()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, relayPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        var requestedPort = GetAvailableTcpPort();
        var serverKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm);
        var userKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm, 32);
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateShadowsocks2022InboundPlan(
                    1,
                    inboundPort,
                    Shadowsocks2022InboundModes.Relay,
                    [
                        new Shadowsocks2022User
                        {
                            UserId = "relay-a",
                            Password = userKey,
                            Address = "127.0.0.1",
                            Port = relayPort,
                            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022", "relay-a"),
                            BytesPerSecond = 0
                        }
                    ],
                    serverKey: serverKey),
                lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var transport = client.GetStream();

            var account = Shadowsocks2022Account.Create(
                ShadowsocksCipherTypes.Blake3Aes128Gcm,
                $"{serverKey}:{userKey}");
            await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                transport,
                account,
                "127.0.0.1",
                requestedPort,
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-ss2022-relay");
            await stream.WriteAsync(payload, lifetimeCts.Token);
            await stream.FlushAsync(lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_hot_add_and_remove_shadowsocks_2022_multi_user()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var sharedIdentityKey = CreateShadowsocks2022Key(method, 32);
        var userIdentityKey = CreateShadowsocks2022Key(method, 48);
        var userKey = CreateShadowsocks2022Key(method, 64);
        var userPassword = $"{sharedIdentityKey}:{userIdentityKey}:{userKey}";
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateShadowsocks2022InboundPlan(
                    1,
                    inboundPort,
                    Shadowsocks2022InboundModes.MultiUser,
                    Array.Empty<Shadowsocks2022User>(),
                    serverKey: serverKey,
                    method: method),
                lifetimeCts.Token);

            Assert.Equal(0, host.GetStatus().KnownUsers);
            Assert.Equal(0, host.Users.GetUsersCount(InboundProtocols.Shadowsocks, "ss-2022"));

            host.Users.AddUser(
                InboundProtocols.Shadowsocks,
                "ss-2022",
                new TestShadowsocksUserDefinition
                {
                    UserId = "user-live",
                    Cipher = string.Empty,
                    Password = userPassword,
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                });

            Assert.Equal(1, host.GetStatus().KnownUsers);
            Assert.Equal(1, host.Users.GetUsersCount(InboundProtocols.Shadowsocks, "ss-2022"));

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var transport = client.GetStream();

            var account = Shadowsocks2022Account.Create(
                method,
                $"{serverKey}:{userPassword}");
            await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                transport,
                account,
                "127.0.0.1",
                echoPort,
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-ss2022-live-user");
            await stream.WriteAsync(payload, lifetimeCts.Token);
            await stream.FlushAsync(lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.True(host.Users.RemoveUser(InboundProtocols.Shadowsocks, "ss-2022", "user-live"));
            Assert.Equal(0, host.GetStatus().KnownUsers);
            Assert.Equal(0, host.Users.GetUsersCount(InboundProtocols.Shadowsocks, "ss-2022"));
            Assert.False(host.Users.RemoveUser(InboundProtocols.Shadowsocks, "ss-2022", "user-live"));
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_hot_add_shadowsocks_2022_relay_user()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, relayPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        var requestedPort = GetAvailableTcpPort();
        var serverKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm);
        var userKey = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm, 32);
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(
                CreateShadowsocks2022InboundPlan(
                    1,
                    inboundPort,
                    Shadowsocks2022InboundModes.Relay,
                    Array.Empty<Shadowsocks2022User>(),
                    serverKey: serverKey),
                lifetimeCts.Token);

            Assert.Equal(0, host.GetStatus().KnownUsers);

            host.Users.AddUser(
                InboundProtocols.Shadowsocks,
                "ss-2022",
                new Shadowsocks2022User
                {
                    UserId = "relay-live",
                    Password = userKey,
                    Address = "127.0.0.1",
                    Port = relayPort,
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022", "relay-live"),
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                });

            Assert.Equal(1, host.GetStatus().KnownUsers);
            Assert.Equal(1, host.Users.GetUsersCount(InboundProtocols.Shadowsocks, "ss-2022"));

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var transport = client.GetStream();

            var account = Shadowsocks2022Account.Create(
                ShadowsocksCipherTypes.Blake3Aes128Gcm,
                $"{serverKey}:{userKey}");
            await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                transport,
                account,
                "127.0.0.1",
                requestedPort,
                lifetimeCts.Token);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-ss2022-live-relay");
            await stream.WriteAsync(payload, lifetimeCts.Token);
            await stream.FlushAsync(lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.True(host.Users.RemoveUser(InboundProtocols.Shadowsocks, "ss-2022", "relay-live"));
            Assert.Equal(0, host.GetStatus().KnownUsers);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_use_custom_runtime_component_catalog_for_inbound_protocol()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var inboundPort = GetAvailableTcpPort();
        var components = RuntimeComponentCatalog.Create(
            inboundFactories:
            [
                new EchoInboundHandlerFactory()
            ]);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateCustomInboundPlan(1, inboundPort, echoPort), lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(EchoInboundProtocol, listener.Protocol);
            Assert.Equal("echo-listener", listener.Tag);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, inboundPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-custom-inbound");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await host.StopAsync(CancellationToken.None);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_replace_builtin_socks_inbound_protocol_with_custom_factory()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var components = RuntimeComponentCatalog.Create(
            inboundFactories:
            [
                new OverrideSocksInboundHandlerFactory()
            ],
            replaceExistingInboundFactories: true);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            var listener = Assert.Single(status.Listeners);
            Assert.Equal(ProxyInboundProtocols.Socks, listener.Protocol);
            Assert.Equal(RuntimeState.Running, listener.State);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-override-socks");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await host.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_publish_generic_runtime_events_for_custom_inbound_protocol()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var inboundPort = GetAvailableTcpPort();
        var components = RuntimeComponentCatalog.Create(
            inboundFactories:
            [
                new EchoInboundHandlerFactory()
            ]);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(
                CreateCustomInboundPlan(1, inboundPort, targetPort: 1, emitSyntheticEvents: true),
                lifetimeCts.Token);

            var events = await CollectEventsUntilAsync(
                host,
                collected =>
                    collected.OfType<RuntimeConnectionErrorEvent>().Any(evt => evt.Protocol == EchoInboundProtocol) &&
                    collected.OfType<RuntimeClientHelloRejectedEvent>().Any(evt => evt.Protocol == EchoInboundProtocol) &&
                    collected.OfType<RuntimeUnknownServerNameRejectedEvent>().Any(evt => evt.Protocol == EchoInboundProtocol),
                lifetimeCts.Token);

            var connectionError = Assert.Single(
                events.OfType<RuntimeConnectionErrorEvent>(),
                evt => evt.Protocol == EchoInboundProtocol);
            Assert.Equal("echo-listener", connectionError.Tag);
            Assert.False(connectionError.IsProxyInbound);
            Assert.Equal("127.0.0.1:10001", connectionError.RemoteEndPoint);
            Assert.Equal("Echo inbound synthetic failure.", connectionError.Message);
            Assert.Equal("Synthetic echo inbound failure.", connectionError.Exception?.Message);

            var clientHelloRejected = Assert.Single(
                events.OfType<RuntimeClientHelloRejectedEvent>(),
                evt => evt.Protocol == EchoInboundProtocol);
            Assert.Equal("127.0.0.1:10002", clientHelloRejected.RemoteEndPoint);
            Assert.Equal("demo.example.com", clientHelloRejected.ServerName);
            Assert.Equal("demo-ja3", clientHelloRejected.Ja3Hash);
            Assert.Equal("Synthetic reject.", clientHelloRejected.Reason);

            var unknownServerNameRejected = Assert.Single(
                events.OfType<RuntimeUnknownServerNameRejectedEvent>(),
                evt => evt.Protocol == EchoInboundProtocol);
            Assert.Equal("127.0.0.1:10003", unknownServerNameRejected.RemoteEndPoint);
            Assert.Equal("blocked.example.com", unknownServerNameRejected.RequestedServerName);
        }
        finally
        {
            lifetimeCts.Cancel();
            await host.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public Task DefaultRuntime_faults_when_custom_inbound_faults_after_startup()
        => AssertCustomInboundTransitionsToFaultedAsync(
            EchoInboundPostStartBehavior.Fault,
            "Echo inbound failed after startup.");

    [Fact]
    public Task DefaultRuntime_faults_when_custom_inbound_stops_unexpectedly_after_startup()
        => AssertCustomInboundTransitionsToFaultedAsync(
            EchoInboundPostStartBehavior.StopUnexpectedly,
            "Runtime task 'echo-inbound' stopped unexpectedly.");

    [Fact]
    public async Task DefaultRuntime_throws_when_plan_uses_unsupported_custom_outbound_protocol()
    {
        var proxyPort = GetAvailableTcpPort();
        var plan = CreateCustomOutboundPlan(
            1,
            proxyPort,
            new EchoTunnelOutboundOptions
            {
                Tag = "echo-out",
                ServerHost = "127.0.0.1",
                ServerPort = 1
            });

        await using var host = new DefaultRuntime();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(plan));
        Assert.Equal("Outbound 'echo-out' uses unsupported protocol 'echo-tunnel'.", exception.Message);
    }

    [Fact]
    public async Task DefaultRuntime_can_start_with_blackhole_outbound_without_runtime_settings()
    {
        await using var host = new DefaultRuntime();

        await host.StartAsync(CreateBlackholePlan(1), CancellationToken.None);

        Assert.Equal(RuntimeState.Running, host.GetStatus().State);

        await host.StopAsync(CancellationToken.None);

        Assert.Equal(RuntimeState.Stopped, host.GetStatus().State);
    }

    [Fact]
    public async Task DefaultRuntime_can_use_custom_runtime_component_catalog_for_outbound_protocol()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var openCall = new TaskCompletionSource<EchoTunnelOpenCall>(TaskCreationOptions.RunContinuationsAsynchronously);
        var components = RuntimeComponentCatalog.Create(
            registry => registry
                .AddSingleton(_ => openCall)
                .AddSingleton(resolver => new EchoTunnelOutboundHandler(
                    resolver.GetRequired<IOutboundRuntimePlanProvider>(),
                    resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                    resolver.GetRequired<TaskCompletionSource<EchoTunnelOpenCall>>())),
            [
                new ResolvedRuntimeOutboundHandlerFactory<EchoTunnelOutboundHandler>(EchoTunnelProtocol)
            ]);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(
                CreateCustomOutboundPlan(
                    1,
                    proxyPort,
                    new EchoTunnelOutboundOptions
                    {
                        Tag = "echo-out",
                        ServerHost = "127.0.0.1",
                        ServerPort = echoPort
                    }),
                lifetimeCts.Token);

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
            request.Add(0x00);
            request.Add(0x01);
            await stream.WriteAsync(request.ToArray(), lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-custom-outbound");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var captured = await openCall.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("echo-out", captured.OutboundTag);
            Assert.Equal("127.0.0.1", captured.Destination.Host);
            Assert.Equal(1, captured.Destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_create_distinct_handlers_per_tag_for_bound_custom_outbound_factory()
    {
        var manager = new RecordingOutboundManager();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IOutboundManager>(
                resolver =>
                {
                    manager.AttachInner(resolver.GetRequired<DefaultOutboundManager>());
                    return manager;
                },
                replaceExisting: true),
            outboundFactories:
            [
                new BoundEchoTunnelOutboundHandlerFactory()
            ]);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateBoundCustomOutboundPlan(1), CancellationToken.None);

            var handlers = manager.ListHandlers()
                .OfType<BoundEchoTunnelOutboundHandler>()
                .OrderBy(handler => handler.InstanceTag, StringComparer.Ordinal)
                .ToArray();

            Assert.Equal(2, handlers.Length);
            Assert.Equal(["echo-a", "echo-b"], handlers.Select(handler => handler.InstanceTag).ToArray());
            Assert.NotSame(handlers[0], handlers[1]);
            Assert.All(handlers, handler => Assert.Equal(1, handler.StartCallCount));
        }
        finally
        {
            await host.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_replace_builtin_freedom_outbound_protocol_with_custom_factory()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var openCall = new TaskCompletionSource<FreedomOverrideOpenCall>(TaskCreationOptions.RunContinuationsAsynchronously);
        var components = RuntimeComponentCatalog.Create(
            registry => registry
                .AddSingleton(_ => new FreedomOverrideTarget("127.0.0.1", echoPort))
                .AddSingleton(_ => openCall)
                .AddSingleton(resolver => new OverrideFreedomOutboundHandler(
                    resolver.GetRequired<FreedomOverrideTarget>(),
                    resolver.GetRequired<TaskCompletionSource<FreedomOverrideOpenCall>>())),
            outboundFactories:
            [
                new ResolvedRuntimeOutboundHandlerFactory<OverrideFreedomOutboundHandler>(OutboundProtocols.Freedom)
            ],
            replaceExistingOutboundFactories: true);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

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
            request.Add(0x00);
            request.Add(0x01);
            await stream.WriteAsync(request.ToArray(), lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-override-freedom");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var captured = await openCall.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("127.0.0.1", captured.Destination.Host);
            Assert.Equal(1, captured.Destination.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_dns_resolver_for_builtin_freedom_outbound()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        const string overrideHost = "runtime-host-override.invalid";
        var dnsQuery = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IDnsResolver>(_ => new OverrideDnsResolver(
                overrideHost,
                IPAddress.Loopback,
                dnsQuery)));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            await stream.WriteAsync(CreateSocks5DomainConnectRequest(overrideHost, echoPort), lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-dns-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var queriedHost = await dnsQuery.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal(overrideHost, queriedHost);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_refresh_strategy_statuses_for_running_runtime()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (probeListener, probeTask, probePort) = StartProbeServer(lifetimeCts.Token);
        await using var host = new DefaultRuntime();

        try
        {
            await host.StartAsync(CreateStrategyProbePlan(1, probePort), lifetimeCts.Token);

            var strategies = await host.RefreshStrategyStatusesAsync(lifetimeCts.Token);

            var strategy = Assert.Single(strategies);
            Assert.Equal("auto", strategy.Tag);
            Assert.Equal(OutboundProtocols.UrlTest, strategy.Protocol);

            var candidate = Assert.Single(strategy.ProbeResults);
            Assert.Equal("direct", candidate.Tag);
            Assert.True(candidate.Success);

            var cachedStrategy = Assert.Single(host.GetStatus().Strategies);
            Assert.Single(cachedStrategy.ProbeResults);
            Assert.True(cachedStrategy.ProbeResults[0].Success);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(probeTask);
            probeListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_strategy_probe_service_for_host_statuses()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var probeService = new RecordingStrategyProbeService(
        [
            new StrategyCandidateProbeResult
            {
                Tag = "direct",
                Success = true,
                LatencyMilliseconds = 12
            }
        ]);
        var components = RuntimeComponentCatalog.Create(
            registry => registry
                .AddSingleton(_ => probeService)
                .AddSingleton<IStrategyOutboundProbeService>(resolver => resolver.GetRequired<RecordingStrategyProbeService>()));
        await using var host = new DefaultRuntime(components);

        await host.StartAsync(CreateStrategyProbePlan(1, probePort: 1), lifetimeCts.Token);

        Assert.Equal(1, probeService.InvalidateAllCount);
        Assert.Empty(Assert.Single(host.GetStatus().Strategies).ProbeResults);

        var strategies = await host.RefreshStrategyStatusesAsync(lifetimeCts.Token);

        var strategy = Assert.Single(strategies);
        Assert.Equal("auto", strategy.Tag);
        var result = Assert.Single(strategy.ProbeResults);
        Assert.Equal("direct", result.Tag);
        Assert.True(result.Success);
        Assert.Equal(12, result.LatencyMilliseconds);
        Assert.Equal(["auto"], probeService.ProbeTags.ToArray());

        var cachedStatus = Assert.Single(host.GetStatus().Strategies);
        var cachedResult = Assert.Single(cachedStatus.ProbeResults);
        Assert.Equal("direct", cachedResult.Tag);
        Assert.True(cachedResult.Success);
        Assert.Equal(12, cachedResult.LatencyMilliseconds);
    }

    [Fact]
    public async Task DefaultRuntime_can_override_shared_host_feature_services()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var proxyPort = GetAvailableTcpPort();
        var sessionRegistry = new FixedRuntimeSessionRegistry(activeSessions: 7);
        sessionRegistry.SetSnapshot(
        [
            new UserSessionSnapshot
            {
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Trojan, "trojan-in", "alice"),
                Protocol = InboundProtocols.Trojan,
                InboundTag = "trojan-in",
                UserId = "alice",
                ActiveSessions = 3,
                RemoteIps = ["203.0.113.10", "203.0.113.11"]
            }
        ]);
        var trafficRegistry = new FixedRuntimeTrafficRegistry(
        [
            new UserTrafficSnapshot
            {
                UserId = "alice",
                UploadBytes = 128,
                DownloadBytes = 256
            }
        ]);
        var rateLimiterRegistry = new RecordingRuntimeRateLimiterRegistry();
        var userStore = new RecordingRuntimeUserStore();
        var components = RuntimeComponentCatalog.Create(
            registry => registry
                .AddSingleton<IRuntimeSessionRegistry>(_ => sessionRegistry)
                .AddSingleton<IRuntimeTrafficRegistry>(_ => trafficRegistry)
                .AddSingleton<IRuntimeRateLimiterRegistry>(_ => rateLimiterRegistry)
                .AddSingleton<IRuntimeUserStore>(_ => userStore));
        await using var host = new DefaultRuntime(components);

        await host.StartAsync(
            CreateSocksPlan(
                1,
                proxyPort,
                activeUsers:
                [
                    new TestRuntimeUserDefinition
                    {
                        UserId = "alice",
                        BytesPerSecond = 128,
                        DeviceLimit = 2
                    }
                ]),
            lifetimeCts.Token);

        Assert.Same(userStore, host.Users);

        var status = host.GetStatus();
        Assert.Equal(7, status.ActiveSessions);
        Assert.Equal(1, status.KnownUsers);

        var traffic = Assert.Single(host.GetTrafficSnapshot());
        Assert.Equal("alice", traffic.UserId);
        Assert.Equal(128, traffic.UploadBytes);
        Assert.Equal(256, traffic.DownloadBytes);

        var sessions = Assert.Single(host.GetSessionSnapshot());
        Assert.Equal("alice", sessions.UserId);
        Assert.Equal(3, sessions.ActiveSessions);
        Assert.Equal(2, sessions.ActiveRemoteIpCount);
        Assert.Equal(["203.0.113.10", "203.0.113.11"], sessions.RemoteIps);

        Assert.Equal(1, rateLimiterRegistry.ApplyCallCount);
        var appliedUser = Assert.Single(rateLimiterRegistry.LastUsers);
        Assert.Equal("alice", appliedUser.UserId);
        Assert.Equal(128, appliedUser.BytesPerSecond);
        Assert.Equal(2, appliedUser.DeviceLimit);
        Assert.Equal(1, userStore.ReplaceCallCount);
    }

    [Fact]
    public async Task DefaultRuntime_can_override_plan_state_for_host_and_runtime_bootstrap()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var openCall = new TaskCompletionSource<EchoTunnelOpenCall>(TaskCreationOptions.RunContinuationsAsynchronously);
        var planState = new RecordingRuntimePlanState(
            plan => plan with
            {
                OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
                [
                    new EchoTunnelOutboundOptions
                    {
                        Tag = "echo-out",
                        ServerHost = "127.0.0.1",
                        ServerPort = echoPort
                    }
                ])
            });
        var components = RuntimeComponentCatalog.Create(
            registry => registry
                .AddSingleton(_ => openCall)
                .AddSingleton<IRuntimePlanState>(_ => planState)
                .AddSingleton(resolver => new EchoTunnelOutboundHandler(
                    resolver.GetRequired<IOutboundRuntimePlanProvider>(),
                    resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                    resolver.GetRequired<TaskCompletionSource<EchoTunnelOpenCall>>())),
            outboundFactories:
            [
                new ResolvedRuntimeOutboundHandlerFactory<EchoTunnelOutboundHandler>(EchoTunnelProtocol)
            ]);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(
                CreateCustomOutboundPlan(
                    1,
                    proxyPort,
                    new EchoTunnelOutboundOptions
                    {
                        Tag = "echo-out",
                        ServerHost = "127.0.0.1",
                        ServerPort = 1
                    }),
                lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            Assert.True(planState.GetCurrentPlanCallCount > 0);

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
            request.Add(0x00);
            request.Add(0x01);
            await stream.WriteAsync(request.ToArray(), lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-plan-state-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            var captured = await openCall.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("echo-out", captured.OutboundTag);
            Assert.Equal("127.0.0.1", captured.Destination.Host);
            Assert.Equal(1, captured.Destination.Port);

            Assert.Equal(1, planState.ApplyCallCount);
            Assert.True(planState.GetCurrentOutboundPlanCallCount > 0);
            Assert.True(planState.RuntimeSettingsResolveCallCount > 0);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_dispatcher_controller_for_host_and_builtins()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var dispatcherController = new RecordingDispatcherController();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IRuntimeDispatcherController>(_ => dispatcherController));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-dispatcher-controller");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.Equal(1, dispatcherController.SetCallCount);
            Assert.True(dispatcherController.GetRequiredDispatcherCallCount > 0);
            Assert.NotNull(dispatcherController.CurrentDispatcher);

            await host.StopAsync(lifetimeCts.Token);

            Assert.Equal(1, dispatcherController.ClearCallCount);
            Assert.Null(dispatcherController.CurrentDispatcher);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_outbound_manager_service_for_runtime_bootstrap()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var manager = new RecordingOutboundManager();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IOutboundManager>(
                resolver =>
                {
                    manager.AttachInner(resolver.GetRequired<DefaultOutboundManager>());
                    return manager;
                },
                replaceExisting: true));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-outbound-manager-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.True(manager.GetHandlerCallCount > 0 || manager.GetDefaultHandlerCallCount > 0);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_outbound_router_service_for_runtime_bootstrap()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var router = new RecordingOutboundRouter();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IOutboundRouter>(
                resolver =>
                {
                    router.AttachInner(resolver.GetRequired<DefaultOutboundRouter>());
                    return router;
                },
                replaceExisting: true));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-outbound-router-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.True(router.ResolveCallCount > 0);
            Assert.NotNull(router.LastDestination);
            Assert.Equal(echoPort, router.LastDestination!.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_dispatcher_service_for_runtime_bootstrap()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var dispatcher = new RecordingDispatcher();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IDispatcher>(
                resolver =>
                {
                    dispatcher.AttachInner(resolver.GetRequired<DefaultDispatcher>());
                    return dispatcher;
                },
                replaceExisting: true));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-dispatcher-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.True(dispatcher.DispatchTcpCallCount > 0);
            Assert.NotNull(dispatcher.LastDestination);
            Assert.Equal(echoPort, dispatcher.LastDestination!.Port);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_inbound_composition_service_for_runtime_bootstrap()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var composition = new RecordingInboundComposition();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IRuntimeInboundComposition>(
                resolver =>
                {
                    composition.AttachInner(resolver.GetRequired<DefaultRuntimeInboundComposition>());
                    return composition;
                },
                replaceExisting: true));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            Assert.Single(status.Listeners);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-inbound-composition-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.True(composition.CreateListenerStatusesCallCount > 0);
            Assert.True(composition.CountStartupSignalsCallCount > 0);
            Assert.True(composition.CreateManagerCallCount > 0);
            Assert.Equal(1, composition.LastContext?.Plan.Revision);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_override_runtime_execution_factory_for_runtime_bootstrap()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var plan = CreateSocksPlan(1, proxyPort);
        var executionFactory = new RecordingRuntimeExecutionFactory();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IRuntimeExecutionFactory>(
                resolver =>
                {
                    executionFactory.AttachInner(resolver.GetRequired<DefaultRuntimeExecutionFactory>());
                    return executionFactory;
                },
                replaceExisting: true));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(plan, lifetimeCts.Token);

            var status = host.GetStatus();
            Assert.Equal(RuntimeState.Running, status.State);
            Assert.Single(status.Listeners);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-execution-factory-override");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            Assert.Equal(1, executionFactory.CreateCallCount);
            Assert.NotNull(executionFactory.LastContext);
            Assert.NotNull(executionFactory.LastExecution);

            var context = executionFactory.LastContext!;
            Assert.Equal(plan.Revision, context.Plan.Revision);
            Assert.Equal(plan.ProxyInbounds.SocksListeners.Count, context.Plan.ProxyInbounds.SocksListeners.Count);
            Assert.Equal(plan.TransportLimits.GlobalBytesPerSecond, context.InboundLimits.GlobalBytesPerSecond);
            Assert.Equal(plan.TransportLimits.ConnectTimeoutSeconds, context.ProxyInboundLimits.ConnectTimeoutSeconds);
            Assert.Null(context.InboundTls);
            Assert.Same(executionFactory, context.Resolver.GetRequired<IRuntimeExecutionFactory>());

            var execution = executionFactory.LastExecution!;
            Assert.True(execution.StartupAccessCount > 0);
            Assert.True(execution.GetImmediateFailureCallCount > 0);

            await host.StopAsync(lifetimeCts.Token);

            Assert.Equal(RuntimeState.Stopped, host.GetStatus().State);
            Assert.Equal(1, execution.CancelCallCount);
            Assert.Equal(1, execution.DisposeCallCount);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task DefaultRuntime_can_start_and_dispose_runtime_startable_components_from_runtime_graph()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var dispatcher = new RuntimeLifecycleDispatcher();
        var components = RuntimeComponentCatalog.Create(
            registry => registry.AddSingleton<IDispatcher>(
                resolver =>
                {
                    dispatcher.AttachInner(resolver.GetRequired<DefaultDispatcher>());
                    return dispatcher;
                },
                replaceExisting: true));
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(CreateSocksPlan(1, proxyPort), lifetimeCts.Token);

            Assert.Equal(1, dispatcher.StartCallCount);

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

            var payload = Encoding.ASCII.GetBytes("hello-runtime-host-lifecycle-dispatcher");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
            Assert.True(dispatcher.DispatchTcpCallCount > 0);

            await host.StopAsync(lifetimeCts.Token);

            Assert.Equal(1, dispatcher.DisposeCallCount);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    private static RuntimePlan CreateSocksPlan(
        int revision,
        int port,
        Socks5LocalAuthenticationOptions? authentication = null,
        IReadOnlyList<IRuntimeUserDefinition>? activeUsers = null)
        => CreatePlan(
            revision,
            new ProxyInboundRuntimePlan
            {
                SocksListeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", port),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                SocksAuthenticationsByTag = authentication?.Enabled == true
                    ? new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["socks-local"] = authentication!
                    }
                    : new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
            },
            activeUsers);

    private static RuntimePlan CreateHttpPlan(
        int revision,
        int port,
        Socks5LocalAuthenticationOptions? authentication = null,
        bool allowTransparent = false)
        => CreatePlan(
            revision,
            new ProxyInboundRuntimePlan
            {
                HttpListeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", port),
                        HandshakeTimeoutSeconds = 10,
                        AllowTransparent = allowTransparent
                    }
                ],
                HttpAuthenticationsByTag = authentication?.Enabled == true
                    ? new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["http-local"] = authentication!
                    }
                    : new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase)
            });

    private static RuntimePlan CreateStrategyProbePlan(int revision, int probePort)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
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
                            Tag = "auto",
                            Protocol = OutboundProtocols.UrlTest,
                            CandidateTags = ["direct"],
                            SelectedTag = "direct",
                            ProbeUrl = $"http://127.0.0.1:{probePort}/",
                            ProbeIntervalSeconds = 1,
                            ProbeTimeoutSeconds = 5
                        }
                    ],
                    DefaultOutboundTag = "auto"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };

    private static RuntimePlan CreateDokodemoPlan(
        int revision,
        int inboundPort,
        string destinationHost,
        int destinationPort,
        IReadOnlyList<string>? networks = null,
        IReadOnlyDictionary<string, string>? portMap = null,
        bool followRedirect = false)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Create(
                [
                    new DokodemoInboundRuntimePlan
                    {
                        Inbounds =
                        [
                            new DokodemoInboundRuntime
                            {
                                Tag = "dokodemo-inbound",
                                Binding = new ListenerBinding("127.0.0.1", inboundPort),
                                DestinationHost = destinationHost,
                                DestinationPort = destinationPort,
                                Networks = networks ?? [RoutingNetworks.Tcp],
                                PortMap = portMap ?? new Dictionary<string, string>(StringComparer.Ordinal),
                                FollowRedirect = followRedirect
                            }
                        ]
                    }
                ]),
                Outbound = new OutboundRuntimePlan
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
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };

    private static RuntimePlan CreateShadowsocks2022InboundPlan(
        int revision,
        int port,
        string mode = Shadowsocks2022InboundModes.SingleUser,
        IReadOnlyList<Shadowsocks2022User>? users = null,
        IReadOnlyList<string>? networks = null,
        string? serverKey = null,
        string method = ShadowsocksCipherTypes.Blake3Aes128Gcm)
    {
        var normalizedMethod = ShadowsocksCipherTypes.Normalize(method);
        var effectiveServerKey = string.IsNullOrWhiteSpace(serverKey)
            ? CreateShadowsocks2022Key(normalizedMethod)
            : serverKey.Trim();
        var normalizedMode = string.IsNullOrWhiteSpace(mode)
            ? Shadowsocks2022InboundModes.SingleUser
            : mode.Trim();
        var runtimeUsers = users?.ToArray() ?? CreateDefaultShadowsocks2022Users(effectiveServerKey);

        return new RuntimePlan
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Create(
                [
                    new ShadowsocksInboundRuntimePlan
                    {
                        Inbounds2022 =
                        [
                            new Shadowsocks2022InboundRuntime
                            {
                                RuntimeState = new Shadowsocks2022InboundRuntimeState(
                                    normalizedMethod,
                                    effectiveServerKey,
                                    normalizedMode,
                                    runtimeUsers),
                                Tag = "ss-2022",
                                Binding = new ListenerBinding("127.0.0.1", port),
                                Networks = networks ?? [RoutingNetworks.Tcp],
                                Method = normalizedMethod,
                                Key = effectiveServerKey,
                                Mode = normalizedMode,
                                Users = runtimeUsers
                            }
                        ]
                    }
                ]),
                Outbound = new OutboundRuntimePlan
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
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = runtimeUsers
        };
    }

    private static string CreateShadowsocks2022Key(string method, int seed = 0)
    {
        var keySize = method switch
        {
            ShadowsocksCipherTypes.Blake3Aes128Gcm => 16,
            ShadowsocksCipherTypes.Blake3Aes256Gcm => 32,
            ShadowsocksCipherTypes.Blake3ChaCha20Poly1305 => 32,
            _ => throw new NotSupportedException($"Unsupported Shadowsocks 2022 method: {method}.")
        };

        return Convert.ToBase64String(
            Enumerable.Range(seed, keySize)
                .Select(static value => (byte)(value & 0xFF))
                .ToArray());
    }

    private static Shadowsocks2022User[] CreateDefaultShadowsocks2022Users(string serverKey)
        =>
        [
            new Shadowsocks2022User
            {
                UserId = "default",
                Password = serverKey,
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022", "default"),
                BytesPerSecond = 0
            }
        ];

    private static RuntimePlan CreateCustomInboundPlan(
        int revision,
        int inboundPort,
        int targetPort,
        bool emitSyntheticEvents = false,
        EchoInboundPostStartBehavior postStartBehavior = EchoInboundPostStartBehavior.None,
        TaskCompletionSource? postStartReady = null,
        TaskCompletionSource? postStartContinue = null)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Create(
                [
                    new EchoInboundRuntimePlan
                    {
                        Listeners =
                        [
                            new ProxyInboundListenerDefinition
                            {
                                Tag = "echo-listener",
                                Binding = new ListenerBinding("127.0.0.1", inboundPort),
                                HandshakeTimeoutSeconds = 10
                            }
                        ],
                        EmitSyntheticEvents = emitSyntheticEvents,
                        PostStartBehavior = postStartBehavior,
                        PostStartReady = postStartReady,
                        PostStartContinue = postStartContinue,
                        TargetHost = "127.0.0.1",
                        TargetPort = targetPort
                    }
                ]),
                Outbound = new OutboundRuntimePlan
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
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };

    private static RuntimePlan CreateCustomOutboundPlan(
        int revision,
        int port,
        EchoTunnelOutboundOptions settings)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = settings.Tag,
                            Protocol = settings.Protocol
                        }
                    ],
                    DefaultOutboundTag = settings.Tag
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = new ProxyInboundRuntimePlan
            {
                SocksListeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", port),
                        HandshakeTimeoutSeconds = 10
                    }
                ]
            },
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create([settings]),
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };

    private static RuntimePlan CreateBlackholePlan(int revision)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "sink",
                            Protocol = OutboundProtocols.Blackhole
                        }
                    ],
                    DefaultOutboundTag = "sink"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };

    private static RuntimePlan CreateBoundCustomOutboundPlan(int revision)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "echo-a",
                            Protocol = EchoTunnelProtocol
                        },
                        new OutboundRuntime
                        {
                            Tag = "echo-b",
                            Protocol = EchoTunnelProtocol
                        }
                    ],
                    DefaultOutboundTag = "echo-a"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
            [
                new EchoTunnelOutboundOptions
                {
                    Tag = "echo-a",
                    ServerHost = "127.0.0.1",
                    ServerPort = 1
                },
                new EchoTunnelOutboundOptions
                {
                    Tag = "echo-b",
                    ServerHost = "127.0.0.1",
                    ServerPort = 1
                }
            ]),
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };

    private static RuntimePlan CreatePlan(
        int revision,
        ProxyInboundRuntimePlan proxyInbounds,
        IReadOnlyList<IRuntimeUserDefinition>? activeUsers = null)
        => new()
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
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
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = proxyInbounds,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = activeUsers ?? Array.Empty<IRuntimeUserDefinition>()
        };

    private static (TcpListener Listener, Task Task, int Port) StartEchoServer(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = RunEchoServerAsync(listener, cancellationToken);
        return (listener, task, port);
    }

    private static (TcpListener Listener, Task Task, int Port) StartProbeServer(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = RunProbeServerAsync(listener, cancellationToken);
        return (listener, task, port);
    }

    private static (UdpClient Server, Task Task, int Port) StartUdpEchoServer(CancellationToken cancellationToken)
    {
        var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        var task = RunUdpEchoServerAsync(server, cancellationToken);
        return (server, task, port);
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

    private static async Task RunProbeServerAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = client.GetStream();

            _ = await ReadHeaderAsync(stream, cancellationToken);

            var response = Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(response, cancellationToken);
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

    private static async Task RunUdpEchoServerAsync(UdpClient server, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await server.ReceiveAsync(cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                await server.SendAsync(result.Buffer, result.Buffer.Length, result.RemoteEndPoint);
            }
        }
        finally
        {
            server.Dispose();
        }
    }

    private static int GetAvailableTcpPort()
    {
        var rangeLength = LoopbackPortRangeEnd - LoopbackPortRangeStart + 1;
        for (var attempt = 0; attempt < rangeLength; attempt++)
        {
            var port = LoopbackPortRangeStart + (int)((uint)Interlocked.Increment(ref _nextLoopbackPort) % rangeLength);
            using var tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                tcpSocket.Bind(new IPEndPoint(IPAddress.Loopback, port));
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

    private static byte[] CreateSocks5DomainConnectRequest(string host, int port)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        var request = new byte[7 + hostBytes.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = 0x03;
        request[4] = (byte)hostBytes.Length;
        hostBytes.CopyTo(request.AsSpan(5));
        request[^2] = (byte)(port >> 8);
        request[^1] = (byte)(port & 0xFF);
        return request;
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

    private static string CreateBasicProxyAuthorizationHeaderValue(string username, string password)
        => $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"))}";

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

    private static async Task<IReadOnlyList<RuntimeEvent>> CollectEventsUntilAsync(
        IRuntime host,
        Func<IReadOnlyList<RuntimeEvent>, bool> predicate,
        CancellationToken cancellationToken)
    {
        var events = new List<RuntimeEvent>();
        await foreach (var runtimeEvent in host.GetEventsAsync(cancellationToken))
        {
            events.Add(runtimeEvent);
            if (predicate(events))
            {
                return events;
            }
        }

        return events;
    }

    private static async Task AssertCustomInboundTransitionsToFaultedAsync(
        EchoInboundPostStartBehavior behavior,
        string expectedMessage)
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var inboundPort = GetAvailableTcpPort();
        var postStartReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var postStartContinue = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var components = RuntimeComponentCatalog.Create(
            inboundFactories:
            [
                new EchoInboundHandlerFactory()
            ]);
        await using var host = new DefaultRuntime(components);

        try
        {
            await host.StartAsync(
                CreateCustomInboundPlan(
                    1,
                    inboundPort,
                    targetPort: 1,
                    postStartBehavior: behavior,
                    postStartReady: postStartReady,
                    postStartContinue: postStartContinue),
                lifetimeCts.Token);
            await postStartReady.Task.WaitAsync(TimeSpan.FromSeconds(5));

            var runningStatus = host.GetStatus();
            Assert.Equal(RuntimeState.Running, runningStatus.State);
            Assert.Equal(RuntimeState.Running, Assert.Single(runningStatus.Listeners).State);

            postStartContinue.TrySetResult();

            var events = await CollectEventsUntilAsync(
                host,
                collected =>
                    collected.OfType<RuntimeListenerFaultedEvent>().Any(evt => evt.TaskName == "echo-inbound") &&
                    collected.OfType<RuntimeFaultedEvent>().Any(evt => evt.TaskName == "echo-inbound"),
                lifetimeCts.Token);

            var faultedStatus = host.GetStatus();
            Assert.Equal(RuntimeState.Faulted, faultedStatus.State);
            Assert.Equal(expectedMessage, faultedStatus.Message);
            var listenerStatus = Assert.Single(faultedStatus.Listeners);
            Assert.Equal(RuntimeState.Faulted, listenerStatus.State);
            Assert.Equal(expectedMessage, listenerStatus.Message);

            var listenerFaulted = Assert.Single(
                events.OfType<RuntimeListenerFaultedEvent>(),
                evt => evt.TaskName == "echo-inbound");
            Assert.Equal(expectedMessage, listenerFaulted.Message);
            var listener = Assert.Single(listenerFaulted.Listeners);
            Assert.Equal("echo-listener", listener.Tag);
            Assert.Equal(RuntimeState.Faulted, listener.State);
            Assert.Equal(expectedMessage, listener.Message);

            var runtimeFaulted = Assert.Single(
                events.OfType<RuntimeFaultedEvent>(),
                evt => evt.TaskName == "echo-inbound");
            var exception = Assert.IsType<InvalidOperationException>(runtimeFaulted.Exception);
            Assert.Equal(expectedMessage, runtimeFaulted.Message);
            Assert.Equal(expectedMessage, exception.Message);
        }
        finally
        {
            lifetimeCts.Cancel();
            await host.StopAsync(CancellationToken.None);
        }
    }

    private static RuntimeFeatureGraph CreateTestSharedContext()
    {
        var planState = new RuntimePlanState();
        planState.Apply(RuntimePlan.Empty);
        var routingService = new DefaultRuntimeRoutingService(planState);
        var fakeDnsEngine = new RuntimeFakeDnsEngine(planState);
        var dispatcherController = new RuntimeDispatcherServices();

        return new RuntimeFeatureGraph(
            planState,
            routingService,
            new SessionRegistry(),
            new TrafficRegistry(),
            new RateLimiterRegistry(),
            new RelayService(),
            new RuntimeDnsResolver(planState, fakeDnsEngine: fakeDnsEngine),
            fakeDnsEngine,
            new DefaultRuntimeSniffer(fakeDnsEngine),
            new UserStore(),
            new DefaultStrategyOutboundProbeService(),
            dispatcherController);
    }

    private sealed record EchoTunnelOutboundOptions : IRuntimeOutboundOptions
    {
        public required string Tag { get; init; }

        public string Protocol => EchoTunnelProtocol;

        public required string ServerHost { get; init; }

        public required int ServerPort { get; init; }
    }

    private sealed record EchoTunnelOpenCall(string OutboundTag, DispatchDestination Destination);

    private sealed record FreedomOverrideTarget(string Host, int Port);

    private sealed record FreedomOverrideOpenCall(DispatchDestination Destination);

    private sealed record RegistryMarkerService(string Value);

    private sealed class RegistryResolutionRecorder
    {
        private int _recordCallCount;

        public int RecordCallCount => Volatile.Read(ref _recordCallCount);

        public string LastValue { get; private set; } = string.Empty;

        public void Record(string value)
        {
            Interlocked.Increment(ref _recordCallCount);
            LastValue = value;
        }
    }

    private sealed class EchoTunnelOutboundHandler : IOutboundHandler
    {
        private readonly IOutboundRuntimePlanProvider _planProvider;
        private readonly TaskCompletionSource<EchoTunnelOpenCall> _openCall;
        private readonly IRuntimeOutboundSettingsProvider _settingsProvider;

        public EchoTunnelOutboundHandler(
            IOutboundRuntimePlanProvider planProvider,
            IRuntimeOutboundSettingsProvider settingsProvider,
            TaskCompletionSource<EchoTunnelOpenCall> openCall)
        {
            _planProvider = planProvider;
            _settingsProvider = settingsProvider;
            _openCall = openCall;
        }

        public string Protocol => EchoTunnelProtocol;

        public async ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            if (destination.Network != DispatchNetwork.Tcp)
            {
                throw new NotSupportedException($"Echo tunnel outbound does not support TCP open for network '{destination.Network}'.");
            }

            if (!_planProvider.GetCurrentOutboundPlan().TryResolveOutboundTag(context, out var outboundTag))
            {
                throw new InvalidOperationException("Echo tunnel outbound tag could not be resolved.");
            }

            if (!_settingsProvider.TryResolve<EchoTunnelOutboundOptions>(context, out var settings))
            {
                throw new InvalidOperationException("Echo tunnel outbound settings could not be resolved.");
            }

            _openCall.TrySetResult(new EchoTunnelOpenCall(outboundTag, destination));

            var client = new TcpClient();
            await client.ConnectAsync(settings.ServerHost, settings.ServerPort, cancellationToken);
            return client.GetStream();
        }

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Echo tunnel outbound does not support UDP.");
    }

    private sealed class BoundEchoTunnelOutboundHandlerFactory : IRuntimeBoundOutboundHandlerFactory
    {
        public string Protocol => EchoTunnelProtocol;

        public IOutboundHandler Create(RuntimeComponentResolver resolver)
            => throw new InvalidOperationException("Bound echo tunnel outbound requires outbound runtime metadata.");

        public IOutboundHandler Create(RuntimeComponentResolver resolver, OutboundRuntime outbound)
        {
            ArgumentNullException.ThrowIfNull(resolver);
            ArgumentNullException.ThrowIfNull(outbound);

            return new BoundEchoTunnelOutboundHandler(outbound.Tag);
        }
    }

    private sealed class BoundEchoTunnelOutboundHandler : IOutboundHandler, IRuntimeStartable
    {
        private int _startCallCount;

        public BoundEchoTunnelOutboundHandler(string instanceTag)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(instanceTag);
            InstanceTag = instanceTag.Trim();
        }

        public string Protocol => EchoTunnelProtocol;

        public string InstanceTag { get; }

        public int StartCallCount => Volatile.Read(ref _startCallCount);

        public void Start()
        {
            Interlocked.Increment(ref _startCallCount);
        }

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Bound echo tunnel outbound test handler does not open TCP streams.");

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Bound echo tunnel outbound test handler does not open UDP transports.");
    }

    private sealed class OverrideFreedomOutboundHandler : IOutboundHandler
    {
        private readonly TaskCompletionSource<FreedomOverrideOpenCall> _openCall;
        private readonly FreedomOverrideTarget _target;

        public OverrideFreedomOutboundHandler(
            FreedomOverrideTarget target,
            TaskCompletionSource<FreedomOverrideOpenCall> openCall)
        {
            _target = target;
            _openCall = openCall;
        }

        public string Protocol => OutboundProtocols.Freedom;

        public async ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            _openCall.TrySetResult(new FreedomOverrideOpenCall(destination));

            var client = new TcpClient();
            await client.ConnectAsync(_target.Host, _target.Port, cancellationToken);
            return client.GetStream();
        }

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException("Override freedom outbound does not support UDP.");
    }

    private sealed class OverrideDnsResolver : IDnsResolver
    {
        private readonly IPAddress _address;
        private readonly string _host;
        private readonly TaskCompletionSource<string> _query;

        public OverrideDnsResolver(
            string host,
            IPAddress address,
            TaskCompletionSource<string> query)
        {
            _host = host;
            _address = address;
            _query = query;
        }

        public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            if (string.Equals(host, _host, StringComparison.OrdinalIgnoreCase))
            {
                _query.TrySetResult(host);
                return
                [
                    _address
                ];
            }

            return await SystemDnsResolver.Instance.ResolveAsync(host, cancellationToken);
        }
    }

    private sealed class RecordingRuntimePlanState : IRuntimePlanState
    {
        private readonly RuntimePlanState _inner = new();
        private readonly Func<RuntimePlan, RuntimePlan> _transform;
        private int _applyCallCount;
        private int _getCurrentPlanCallCount;
        private int _getCurrentOutboundPlanCallCount;
        private int _runtimeSettingsResolveCallCount;

        public RecordingRuntimePlanState(Func<RuntimePlan, RuntimePlan>? transform = null)
        {
            _transform = transform ?? (static plan => plan);
            _inner.Apply(RuntimePlan.Empty);
        }

        public int ApplyCallCount => Volatile.Read(ref _applyCallCount);

        public int GetCurrentPlanCallCount => Volatile.Read(ref _getCurrentPlanCallCount);

        public int GetCurrentOutboundPlanCallCount => Volatile.Read(ref _getCurrentOutboundPlanCallCount);

        public int RuntimeSettingsResolveCallCount => Volatile.Read(ref _runtimeSettingsResolveCallCount);

        public void Apply(RuntimePlan plan)
        {
            Interlocked.Increment(ref _applyCallCount);
            _inner.Apply(_transform(plan));
        }

        public RuntimePlan GetCurrentPlan()
        {
            Interlocked.Increment(ref _getCurrentPlanCallCount);
            return _inner.GetCurrentPlan();
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan()
        {
            Interlocked.Increment(ref _getCurrentOutboundPlanCallCount);
            return _inner.GetCurrentOutboundPlan();
        }

        public DnsRuntimeSettings GetCurrentDnsSettings() => _inner.GetCurrentDnsSettings();

        public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
        {
            Interlocked.Increment(ref _runtimeSettingsResolveCallCount);
            return _inner.TryResolve(context, out settings);
        }

        public bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
            where TOptions : class, IRuntimeOutboundOptions
        {
            Interlocked.Increment(ref _runtimeSettingsResolveCallCount);
            return _inner.TryResolve(context, out settings);
        }

        public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
            => _inner.TryResolve(context, out settings);

        public bool TryResolve(DispatchContext context, out Shadowsocks2022OutboundSettings settings)
            => _inner.TryResolve(context, out settings);

        public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
            => _inner.TryResolve(context, out settings);

        public bool TryResolve(DispatchContext context, out VlessOutboundSettings settings)
            => _inner.TryResolve(context, out settings);

        public bool TryResolve(DispatchContext context, out VmessOutboundSettings settings)
            => _inner.TryResolve(context, out settings);

        public bool TryResolve(DispatchContext context, out StrategyOutboundSettings settings)
            => _inner.TryResolve(context, out settings);
    }

    private sealed class RecordingDispatcherController : IRuntimeDispatcherController
    {
        private IDispatcher? _dispatcher;
        private int _setCallCount;
        private int _clearCallCount;
        private int _getRequiredDispatcherCallCount;

        public int SetCallCount => Volatile.Read(ref _setCallCount);

        public int ClearCallCount => Volatile.Read(ref _clearCallCount);

        public int GetRequiredDispatcherCallCount => Volatile.Read(ref _getRequiredDispatcherCallCount);

        public IDispatcher? CurrentDispatcher => Volatile.Read(ref _dispatcher);

        public void SetDispatcher(IDispatcher dispatcher)
        {
            ArgumentNullException.ThrowIfNull(dispatcher);
            Interlocked.Increment(ref _setCallCount);
            Volatile.Write(ref _dispatcher, dispatcher);
        }

        public void ClearDispatcher()
        {
            Interlocked.Increment(ref _clearCallCount);
            Volatile.Write(ref _dispatcher, null);
        }

        public IDispatcher GetRequiredDispatcher()
        {
            Interlocked.Increment(ref _getRequiredDispatcherCallCount);
            return Volatile.Read(ref _dispatcher)
                   ?? throw new InvalidOperationException("Runtime dispatcher is not available.");
        }

        public object? GetService(Type serviceType)
            => serviceType == typeof(IDispatcher) ? Volatile.Read(ref _dispatcher) : null;
    }

    private sealed class RecordingOutboundManager : IOutboundManager
    {
        private IOutboundManager? _inner;
        private int _getHandlerCallCount;
        private int _getDefaultHandlerCallCount;
        private int _listHandlersCallCount;

        public int GetHandlerCallCount => Volatile.Read(ref _getHandlerCallCount);

        public int GetDefaultHandlerCallCount => Volatile.Read(ref _getDefaultHandlerCallCount);

        public int ListHandlersCallCount => Volatile.Read(ref _listHandlersCallCount);

        public void AttachInner(IOutboundManager inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public void AddHandler(IOutboundHandler handler) => GetInner().AddHandler(handler);

        public bool RemoveHandler(string protocol) => GetInner().RemoveHandler(protocol);

        public IOutboundHandler? GetHandler(string tag)
        {
            Interlocked.Increment(ref _getHandlerCallCount);
            return GetInner().GetHandler(tag);
        }

        public IOutboundHandler GetDefaultHandler()
        {
            Interlocked.Increment(ref _getDefaultHandlerCallCount);
            return GetInner().GetDefaultHandler();
        }

        public IReadOnlyList<IOutboundHandler> ListHandlers()
        {
            Interlocked.Increment(ref _listHandlersCallCount);
            return GetInner().ListHandlers();
        }

        private IOutboundManager GetInner()
            => _inner ?? throw new InvalidOperationException("Inner outbound manager is not attached.");
    }

    private sealed class RecordingOutboundRouter : IOutboundRouter
    {
        private IOutboundRouter? _inner;
        private int _resolveCallCount;

        public int ResolveCallCount => Volatile.Read(ref _resolveCallCount);

        public DispatchDestination? LastDestination { get; private set; }

        public void AttachInner(IOutboundRouter inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public ResolvedOutboundRoute Resolve(DispatchContext context, DispatchDestination? destination)
        {
            Interlocked.Increment(ref _resolveCallCount);
            LastDestination = destination;
            return GetInner().Resolve(context, destination);
        }

        private IOutboundRouter GetInner()
            => _inner ?? throw new InvalidOperationException("Inner outbound router is not attached.");
    }

    private sealed class RecordingDispatcher : IDispatcher
    {
        private IDispatcher? _inner;
        private int _dispatchTcpCallCount;

        public int DispatchTcpCallCount => Volatile.Read(ref _dispatchTcpCallCount);

        public DispatchDestination? LastDestination { get; private set; }

        public void AttachInner(IDispatcher inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _dispatchTcpCallCount);
            LastDestination = destination;
            return GetInner().DispatchTcpAsync(context, destination, cancellationToken);
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => GetInner().DispatchUdpAsync(context, cancellationToken);

        private IDispatcher GetInner()
            => _inner ?? throw new InvalidOperationException("Inner dispatcher is not attached.");
    }

    private sealed class RecordingInboundComposition : IRuntimeInboundComposition
    {
        private IRuntimeInboundComposition? _inner;
        private int _countStartupSignalsCallCount;
        private int _createListenerStatusesCallCount;
        private int _createManagerCallCount;

        public int CountStartupSignalsCallCount => Volatile.Read(ref _countStartupSignalsCallCount);

        public int CreateListenerStatusesCallCount => Volatile.Read(ref _createListenerStatusesCallCount);

        public int CreateManagerCallCount => Volatile.Read(ref _createManagerCallCount);

        public RuntimeInboundHandlerContext? LastContext { get; private set; }

        public void AttachInner(IRuntimeInboundComposition inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public int CountStartupSignals(RuntimePlan plan)
        {
            Interlocked.Increment(ref _countStartupSignalsCallCount);
            return GetInner().CountStartupSignals(plan);
        }

        public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        {
            Interlocked.Increment(ref _createListenerStatusesCallCount);
            return GetInner().CreateListenerStatuses(plan);
        }

        public IInboundManager CreateManager(RuntimeInboundHandlerContext context)
        {
            Interlocked.Increment(ref _createManagerCallCount);
            LastContext = context;
            return GetInner().CreateManager(context);
        }

        private IRuntimeInboundComposition GetInner()
            => _inner ?? throw new InvalidOperationException("Inner inbound composition is not attached.");
    }

    private sealed class RecordingRuntimeExecutionFactory : IRuntimeExecutionFactory
    {
        private IRuntimeExecutionFactory? _inner;
        private int _createCallCount;

        public int CreateCallCount => Volatile.Read(ref _createCallCount);

        public RuntimeExecutionContext? LastContext { get; private set; }

        public RecordingRuntimeExecution? LastExecution { get; private set; }

        public void AttachInner(IRuntimeExecutionFactory inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public IRuntimeExecution Create(RuntimeExecutionContext context)
        {
            Interlocked.Increment(ref _createCallCount);
            LastContext = context;

            var execution = new RecordingRuntimeExecution(GetInner().Create(context));
            LastExecution = execution;
            return execution;
        }

        private IRuntimeExecutionFactory GetInner()
            => _inner ?? throw new InvalidOperationException("Inner runtime execution factory is not attached.");
    }

    private sealed class RecordingRuntimeExecution : IRuntimeExecution
    {
        private readonly IRuntimeExecution _inner;
        private int _startupAccessCount;
        private int _getImmediateFailureCallCount;
        private int _cancelCallCount;
        private int _disposeCallCount;

        public RecordingRuntimeExecution(IRuntimeExecution inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public RuntimePlan Plan => _inner.Plan;

        public Task Startup
        {
            get
            {
                Interlocked.Increment(ref _startupAccessCount);
                return _inner.Startup;
            }
        }

        public bool IsCancellationRequested => _inner.IsCancellationRequested;

        public int StartupAccessCount => Volatile.Read(ref _startupAccessCount);

        public int GetImmediateFailureCallCount => Volatile.Read(ref _getImmediateFailureCallCount);

        public int CancelCallCount => Volatile.Read(ref _cancelCallCount);

        public int DisposeCallCount => Volatile.Read(ref _disposeCallCount);

        public void Cancel()
        {
            Interlocked.Increment(ref _cancelCallCount);
            _inner.Cancel();
        }

        public Exception? GetImmediateFailure()
        {
            Interlocked.Increment(ref _getImmediateFailureCallCount);
            return _inner.GetImmediateFailure();
        }

        public async ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref _disposeCallCount);
            await _inner.DisposeAsync();
        }
    }

    private sealed class RuntimeLifecycleDispatcher : IDispatcher, IRuntimeStartable, IAsyncDisposable
    {
        private IDispatcher? _inner;
        private int _startCallCount;
        private int _disposeCallCount;
        private int _dispatchTcpCallCount;

        public int StartCallCount => Volatile.Read(ref _startCallCount);

        public int DisposeCallCount => Volatile.Read(ref _disposeCallCount);

        public int DispatchTcpCallCount => Volatile.Read(ref _dispatchTcpCallCount);

        public void AttachInner(IDispatcher inner)
        {
            ArgumentNullException.ThrowIfNull(inner);
            _inner = inner;
        }

        public void Start()
        {
            Interlocked.Increment(ref _startCallCount);
        }

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            if (StartCallCount == 0)
            {
                throw new InvalidOperationException("Runtime lifecycle dispatcher is not started.");
            }

            Interlocked.Increment(ref _dispatchTcpCallCount);
            return GetInner().DispatchTcpAsync(context, destination, cancellationToken);
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
        {
            if (StartCallCount == 0)
            {
                throw new InvalidOperationException("Runtime lifecycle dispatcher is not started.");
            }

            return GetInner().DispatchUdpAsync(context, cancellationToken);
        }

        public ValueTask DisposeAsync()
        {
            Interlocked.Increment(ref _disposeCallCount);
            return ValueTask.CompletedTask;
        }

        private IDispatcher GetInner()
            => _inner ?? throw new InvalidOperationException("Inner dispatcher is not attached.");
    }

    private sealed class RecordingStrategyProbeService : IStrategyOutboundProbeService, IStrategyOutboundProbeCache
    {
        private readonly ConcurrentDictionary<string, IReadOnlyList<StrategyCandidateProbeResult>> _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly IReadOnlyList<StrategyCandidateProbeResult> _results;
        private int _invalidateAllCount;

        public RecordingStrategyProbeService(IReadOnlyList<StrategyCandidateProbeResult> results)
        {
            _results = results.ToArray();
        }

        public ConcurrentQueue<string> ProbeTags { get; } = new();

        public int InvalidateAllCount => Volatile.Read(ref _invalidateAllCount);

        public ValueTask<IReadOnlyList<StrategyCandidateProbeResult>> ProbeAsync(
            StrategyOutboundSettings settings,
            CancellationToken cancellationToken)
        {
            ProbeTags.Enqueue(settings.Tag);

            var results = _results
                .Select(result => result with
                {
                    CheckedAt = DateTimeOffset.UtcNow
                })
                .ToArray();
            _cache[settings.Tag] = results;
            return ValueTask.FromResult<IReadOnlyList<StrategyCandidateProbeResult>>(results);
        }

        public bool TryGetCachedResults(string? tag, out IReadOnlyList<StrategyCandidateProbeResult> results)
        {
            if (!string.IsNullOrWhiteSpace(tag) &&
                _cache.TryGetValue(tag.Trim(), out var cached))
            {
                results = cached;
                return true;
            }

            results = Array.Empty<StrategyCandidateProbeResult>();
            return false;
        }

        public void Invalidate(string? tag)
        {
            if (!string.IsNullOrWhiteSpace(tag))
            {
                _cache.TryRemove(tag.Trim(), out _);
            }
        }

        public void InvalidateAll()
        {
            Interlocked.Increment(ref _invalidateAllCount);
            _cache.Clear();
        }
    }

    private sealed class FixedRuntimeSessionRegistry : IRuntimeSessionRegistry
    {
        private IReadOnlyList<UserSessionSnapshot> _snapshot = Array.Empty<UserSessionSnapshot>();

        public FixedRuntimeSessionRegistry(int activeSessions)
        {
            ActiveSessions = activeSessions;
        }

        public int ActiveSessions { get; }

        public IDisposable OpenSession(string userId) => NoopDisposable.Instance;

        public bool TryOpenSession(string userId, string? remoteIp, int deviceLimit, out IDisposable? lease)
        {
            lease = NoopDisposable.Instance;
            return true;
        }

        public IReadOnlyList<UserSessionSnapshot> CreateSnapshot() => _snapshot;

        public void SetSnapshot(IReadOnlyList<UserSessionSnapshot> snapshot)
        {
            _snapshot = snapshot.ToArray();
        }
    }

    private sealed class FixedRuntimeTrafficRegistry : IRuntimeTrafficRegistry
    {
        private readonly IReadOnlyList<UserTrafficSnapshot> _snapshot;

        public FixedRuntimeTrafficRegistry(IReadOnlyList<UserTrafficSnapshot> snapshot)
        {
            _snapshot = snapshot.ToArray();
        }

        public void RecordUpload(string userId, int bytes)
        {
        }

        public void RecordUpload(IRuntimeUserDefinition user, int bytes)
        {
        }

        public void RecordDownload(string userId, int bytes)
        {
        }

        public void RecordDownload(IRuntimeUserDefinition user, int bytes)
        {
        }

        public IReadOnlyList<UserTrafficSnapshot> CreateSnapshot() => _snapshot;
    }

    private sealed class RecordingRuntimeRateLimiterRegistry : IRuntimeRateLimiterRegistry
    {
        public ByteRateGate GlobalGate { get; } = new(0);

        public int ApplyCallCount { get; private set; }

        public IReadOnlyList<IRuntimeUserDefinition> LastUsers { get; private set; } = Array.Empty<IRuntimeUserDefinition>();

        public void Apply(IRuntimeInboundLimits limits, IReadOnlyList<IRuntimeUserDefinition> users)
            => Apply(limits.GlobalBytesPerSecond, users);

        public void Apply(long globalBytesPerSecond, IReadOnlyList<IRuntimeUserDefinition> users)
        {
            ApplyCallCount++;
            GlobalGate.UpdateRate(globalBytesPerSecond);
            LastUsers = users.ToArray();
        }

        public ByteRateGate GetUserGate(IRuntimeUserDefinition user) => new(0);

        public ByteRateGate GetUserGate(string scopedUserId) => new(0);
    }

    private sealed class RecordingRuntimeUserStore : IRuntimeUserStore
    {
        private IReadOnlyList<IRuntimeUserDefinition> _users = Array.Empty<IRuntimeUserDefinition>();
        private int _knownUsers;

        public int KnownUsers => Volatile.Read(ref _knownUsers);

        public int ReplaceCallCount { get; private set; }

        public IReadOnlyList<IRuntimeUserDefinition> GetUsers() => _users;

        public IReadOnlyList<IRuntimeUserDefinition> GetUsers(string protocol, string inboundTag) => Array.Empty<IRuntimeUserDefinition>();

        public int GetUsersCount(string protocol, string inboundTag) => 0;

        public bool TryGetUser(string protocol, string inboundTag, string userId, out IRuntimeUserDefinition? user)
        {
            user = null;
            return false;
        }

        public void AddUser(string protocol, string inboundTag, IRuntimeUserDefinition user)
            => throw new NotSupportedException();

        public bool RemoveUser(string protocol, string inboundTag, string userId) => false;

        public void Replace(IReadOnlyList<IRuntimeUserDefinition> users)
        {
            ReplaceCallCount++;
            _users = users.ToArray();
            Volatile.Write(ref _knownUsers, users.Count(user => !string.IsNullOrWhiteSpace(user.UserId)));
        }
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static NoopDisposable Instance { get; } = new();

        public void Dispose()
        {
        }
    }

    private sealed record TestRuntimeUserDefinition : IRuntimeUserDefinition
    {
        public required string UserId { get; init; }

        public int Level { get; init; }

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestShadowsocksUserDefinition : IShadowsocksUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Cipher { get; init; } = string.Empty;

        public string Password { get; init; } = string.Empty;

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record EchoInboundRuntimePlan : IInboundProtocolRuntimePlan
    {
        public string Protocol => EchoInboundProtocol;

        public bool RequiresCertificate => false;

        public bool RequiresReality => false;

        public IReadOnlyList<ProxyInboundListenerDefinition> Listeners { get; init; } = Array.Empty<ProxyInboundListenerDefinition>();

        public bool EmitSyntheticEvents { get; init; }

        public EchoInboundPostStartBehavior PostStartBehavior { get; init; }

        public TaskCompletionSource? PostStartReady { get; init; }

        public TaskCompletionSource? PostStartContinue { get; init; }

        public required string TargetHost { get; init; }

        public required int TargetPort { get; init; }
    }

    private enum EchoInboundPostStartBehavior
    {
        None,
        Fault,
        StopUnexpectedly
    }

    private sealed class EchoInboundHandlerFactory : IRuntimeInboundHandlerFactory
    {
        public string Protocol => EchoInboundProtocol;

        public int CountStartupSignals(RuntimePlan plan)
            => TryGetPlan(plan, out var customPlan) ? customPlan.Listeners.Count : 0;

        public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        {
            return TryGetPlan(plan, out var customPlan)
                ? customPlan.Listeners
                    .Select(listener => new RuntimeListenerStatus
                    {
                        Tag = listener.Tag,
                        Protocol = EchoInboundProtocol,
                        Transport = string.Empty,
                        Binding = listener.Binding,
                        State = RuntimeState.Starting,
                        Message = "Starting listener.",
                        UpdatedAt = DateTimeOffset.UtcNow
                    })
                    .ToArray()
                : Array.Empty<RuntimeListenerStatus>();
        }

        public IInboundHandler? Create(RuntimeInboundHandlerContext context)
        {
            if (!TryGetPlan(context.Plan, out var customPlan) ||
                customPlan.Listeners.Count == 0)
            {
                return null;
            }

            var listenerKeys = customPlan.Listeners
                .Select(listener => RuntimeListenerKeys.CreateListenerKey(
                    EchoInboundProtocol,
                    listener.Tag,
                    transport: string.Empty,
                    listener.Binding))
                .ToArray();

            return new RuntimeInboundHandler(
                "echo-inbound",
                EchoInboundProtocol,
                listenerKeys,
                customPlan.Listeners.Count,
                cancellationToken => RunAsync(customPlan, context, cancellationToken));
        }

        private static bool TryGetPlan(RuntimePlan plan, out EchoInboundRuntimePlan customPlan)
            => plan.Plan.Inbounds.TryGet(EchoInboundProtocol, out customPlan);

        private static async Task RunAsync(
            EchoInboundRuntimePlan plan,
            RuntimeInboundHandlerContext context,
            CancellationToken cancellationToken)
        {
            var listeners = new List<(TcpListener Listener, ProxyInboundListenerDefinition Definition)>(plan.Listeners.Count);
            var acceptTasks = new List<Task>(plan.Listeners.Count);

            try
            {
                foreach (var listenerDefinition in plan.Listeners)
                {
                    var listener = new TcpListener(IPAddress.Parse(listenerDefinition.Binding.ListenAddress), listenerDefinition.Binding.Port);
                    listener.Start();
                    listeners.Add((listener, listenerDefinition));

                    context.Callbacks.ReportListenerStarted(
                    [
                        RuntimeListenerKeys.CreateListenerKey(
                            EchoInboundProtocol,
                            listenerDefinition.Tag,
                            transport: string.Empty,
                            listenerDefinition.Binding)
                    ],
                        $"Echo inbound listener '{listenerDefinition.Binding.ListenAddress}:{listenerDefinition.Binding.Port}' is running.");

                    if (plan.EmitSyntheticEvents)
                    {
                        context.Callbacks.ReportConnectionError(
                            new RuntimeInboundConnectionErrorReport
                            {
                                Protocol = EchoInboundProtocol,
                                Tag = listenerDefinition.Tag,
                                RemoteEndPoint = "127.0.0.1:10001",
                                Message = "Echo inbound synthetic failure.",
                                Exception = new InvalidOperationException("Synthetic echo inbound failure.")
                            });
                        context.Callbacks.ReportClientHelloRejected(
                            new RuntimeInboundClientHelloRejectedReport
                            {
                                Protocol = EchoInboundProtocol,
                                RemoteEndPoint = "127.0.0.1:10002",
                                ServerName = "demo.example.com",
                                Ja3Hash = "demo-ja3",
                                Reason = "Synthetic reject."
                            });
                        context.Callbacks.ReportUnknownServerNameRejected(
                            new RuntimeInboundUnknownServerNameRejectedReport
                            {
                                Protocol = EchoInboundProtocol,
                                RemoteEndPoint = "127.0.0.1:10003",
                                RequestedServerName = "blocked.example.com"
                            });
                    }
                }

                if (plan.PostStartBehavior is not EchoInboundPostStartBehavior.None)
                {
                    plan.PostStartReady?.TrySetResult();
                    if (plan.PostStartContinue is not null)
                    {
                        await plan.PostStartContinue.Task.WaitAsync(cancellationToken);
                    }

                    switch (plan.PostStartBehavior)
                    {
                        case EchoInboundPostStartBehavior.Fault:
                            throw new InvalidOperationException("Echo inbound failed after startup.");
                        case EchoInboundPostStartBehavior.StopUnexpectedly:
                            return;
                    }
                }

                foreach (var (listener, listenerDefinition) in listeners)
                {
                    acceptTasks.Add(AcceptLoopAsync(listener, listenerDefinition, plan, context, cancellationToken));
                }

                await Task.WhenAll(acceptTasks);
            }
            finally
            {
                foreach (var (listener, _) in listeners)
                {
                    listener.Stop();
                }
            }
        }

        private static async Task AcceptLoopAsync(
            TcpListener listener,
            ProxyInboundListenerDefinition listenerDefinition,
            EchoInboundRuntimePlan plan,
            RuntimeInboundHandlerContext context,
            CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                _ = Task.Run(
                    () => ProxySafelyAsync(client, listenerDefinition, plan, context, cancellationToken),
                    CancellationToken.None);
            }
        }

        private static async Task ProxySafelyAsync(
            TcpClient client,
            ProxyInboundListenerDefinition listenerDefinition,
            EchoInboundRuntimePlan plan,
            RuntimeInboundHandlerContext context,
            CancellationToken cancellationToken)
        {
            try
            {
                using (client)
                {
                    await using var inboundStream = client.GetStream();
                    await using var outboundStream = await context.Resolver
                        .GetRequired<IRuntimeDispatcherAccessor>()
                        .GetRequiredDispatcher()
                        .DispatchTcpAsync(
                            new DispatchContext
                            {
                                InboundProtocol = EchoInboundProtocol,
                                InboundKind = EchoInboundProtocol,
                                InboundTag = listenerDefinition.Tag,
                                Network = "tcp",
                                ConnectTimeoutSeconds = context.InboundLimits.ConnectTimeoutSeconds,
                                ConnectionIdleSeconds = context.InboundLimits.ConnectionIdleSeconds,
                                UplinkOnlySeconds = context.InboundLimits.UplinkOnlySeconds,
                                DownlinkOnlySeconds = context.InboundLimits.DownlinkOnlySeconds,
                                UseCone = context.Plan.UseCone,
                                SourceEndPoint = client.Client.RemoteEndPoint,
                                LocalEndPoint = client.Client.LocalEndPoint
                            },
                            new DispatchDestination
                            {
                                Host = plan.TargetHost,
                                Port = plan.TargetPort,
                                Network = DispatchNetwork.Tcp
                            },
                            cancellationToken);

                    using var copyCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    var uplink = CopyStreamAsync(inboundStream, outboundStream, copyCts.Token);
                    var downlink = CopyStreamAsync(outboundStream, inboundStream, copyCts.Token);
                    await Task.WhenAny(uplink, downlink);
                    copyCts.Cancel();
                    await AwaitCompletionAsync(uplink);
                    await AwaitCompletionAsync(downlink);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }

        private static async Task CopyStreamAsync(Stream source, Stream destination, CancellationToken cancellationToken)
        {
            try
            {
                await source.CopyToAsync(destination, cancellationToken);
                await destination.FlushAsync(cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }
    }

    private sealed class OverrideSocksInboundHandlerFactory : IRuntimeInboundHandlerFactory
    {
        public string Protocol => ProxyInboundProtocols.Socks;

        public int CountStartupSignals(RuntimePlan plan) => plan.ProxyInbounds.SocksListeners.Count;

        public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        {
            return plan.ProxyInbounds.SocksListeners
                .Select(listener => new RuntimeListenerStatus
                {
                    Tag = listener.Tag,
                    Protocol = ProxyInboundProtocols.Socks,
                    Transport = string.Empty,
                    Binding = listener.Binding,
                    IsProxyInbound = true,
                    State = RuntimeState.Starting,
                    Message = "Starting listener.",
                    UpdatedAt = DateTimeOffset.UtcNow
                })
                .ToArray();
        }

        public IInboundHandler? Create(RuntimeInboundHandlerContext context)
        {
            if (context.Plan.ProxyInbounds.SocksListeners.Count == 0)
            {
                return null;
            }

            var listenerKeys = context.Plan.ProxyInbounds.SocksListeners
                .Select(listener => RuntimeListenerKeys.CreateListenerKey(
                    ProxyInboundProtocols.Socks,
                    listener.Tag,
                    transport: string.Empty,
                    listener.Binding))
                .ToArray();

            return new RuntimeInboundHandler(
                "socks-local-override",
                ProxyInboundProtocols.Socks,
                listenerKeys,
                context.Plan.ProxyInbounds.SocksListeners.Count,
                cancellationToken => RunAsync(context.Plan.ProxyInbounds.SocksListeners, context, cancellationToken));
        }

        private static async Task RunAsync(
            IReadOnlyList<ProxyInboundListenerDefinition> listeners,
            RuntimeInboundHandlerContext context,
            CancellationToken cancellationToken)
        {
            var activeListeners = new List<TcpListener>(listeners.Count);
            var acceptTasks = new List<Task>(listeners.Count);

            try
            {
                foreach (var listenerDefinition in listeners)
                {
                    var listener = new TcpListener(IPAddress.Parse(listenerDefinition.Binding.ListenAddress), listenerDefinition.Binding.Port);
                    listener.Start();
                    activeListeners.Add(listener);

                    context.Callbacks.ReportListenerStarted(
                    [
                        RuntimeListenerKeys.CreateListenerKey(
                            ProxyInboundProtocols.Socks,
                            listenerDefinition.Tag,
                            transport: string.Empty,
                            listenerDefinition.Binding)
                    ],
                        $"Override SOCKS listener '{listenerDefinition.Binding.ListenAddress}:{listenerDefinition.Binding.Port}' is running.");

                    acceptTasks.Add(AcceptLoopAsync(listener, cancellationToken));
                }

                await Task.WhenAll(acceptTasks);
            }
            finally
            {
                foreach (var listener in activeListeners)
                {
                    listener.Stop();
                }
            }
        }

        private static async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (SocketException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                _ = Task.Run(() => EchoAsync(client, cancellationToken), CancellationToken.None);
            }
        }

        private static async Task EchoAsync(TcpClient client, CancellationToken cancellationToken)
        {
            try
            {
                using (client)
                {
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
                        await stream.FlushAsync(cancellationToken);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
            {
            }
        }
    }
}

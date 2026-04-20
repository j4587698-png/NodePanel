using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class DispatcherTests
{
    [Fact]
    public async Task DispatchTcpAsync_opens_freedom_outbound_connection()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = CreateDispatcher();

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();
            var request = new byte[4];
            await stream.ReadExactlyAsync(request.AsMemory(0, request.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            return Encoding.ASCII.GetString(request);
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                UserId = "test-user",
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);
        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        Assert.Equal("ping", await serverTask);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchUdpAsync_uses_freedom_outbound_transport()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = CreateDispatcher();

        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;

        var serverTask = Task.Run(async () =>
        {
            var buffer = new byte[1024];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var received = await udpSocket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                remoteEndPoint,
                cts.Token);

            await udpSocket.SendToAsync(
                buffer.AsMemory(0, received.ReceivedBytes),
                SocketFlags.None,
                received.RemoteEndPoint,
                cts.Token);
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                UserId = "test-user",
                UseCone = true
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("udp"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal("udp", Encoding.ASCII.GetString(datagram!.Payload));
        Assert.Equal(port, datagram.SourcePort);
    }

    [Fact]
    public async Task DispatchTcpAsync_with_scoped_user_tracks_traffic()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var trafficRegistry = new TrafficRegistry();
        var dispatcher = CreateDispatcher(new RateLimiterRegistry(), trafficRegistry);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();
            var request = new byte[4];
            await stream.ReadExactlyAsync(request.AsMemory(0, request.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            return Encoding.ASCII.GetString(request);
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                InboundTag = "demo-inbound",
                UserId = "demo-user",
                ScopedUserId = RuntimeUserKeys.Create("test", "demo-inbound", "demo-user"),
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);
        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        Assert.Equal("ping", await serverTask);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));

        var snapshot = Assert.Single(trafficRegistry.CreateSnapshot());
        Assert.Equal("demo-user", snapshot.UserId);
        Assert.Equal("test", snapshot.Protocol);
        Assert.Equal("demo-inbound", snapshot.InboundTag);
        Assert.Equal(4, snapshot.UploadBytes);
        Assert.Equal(4, snapshot.DownloadBytes);
    }

    [Fact]
    public async Task DispatchInboundTcpAsync_sniffs_before_resolving_outbound_target()
    {
        var handler = new RecordingOutboundHandler();
        var dispatcher = new DefaultDispatcher(
            new DefaultOutboundRouter(
                [handler],
                new StaticOutboundRuntimePlanProvider(new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "capture",
                            Protocol = handler.Protocol
                        }
                    ],
                    DefaultOutboundTag = "capture"
                })),
            rateLimiterRegistry: null,
            trafficRegistry: null,
            new DefaultRuntimeSniffer());
        var inboundDispatcher = Assert.IsAssignableFrom<IRuntimeInboundTcpDispatcher>(dispatcher);
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: sniff.example.com\r\n\r\n");
        await using var inboundStream = new MemoryStream(payload, writable: false);
        var originalDestination = new DispatchDestination
        {
            Host = "198.51.100.10",
            Port = 80,
            Network = DispatchNetwork.Tcp
        };
        var originalContext = DispatchContextTargeting.SetOriginalAndTarget(
            new DispatchContext
            {
                InboundProtocol = "test"
            },
            originalDestination);

        var result = await inboundDispatcher.DispatchInboundTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            inboundStream,
            originalContext,
            originalDestination,
            CancellationToken.None,
            CancellationToken.None,
            allowDestinationOverride: true);

        await using var outboundStream = result.OutboundStream;

        Assert.NotNull(handler.LastContext);
        Assert.NotNull(handler.LastDestination);
        Assert.Equal(RoutingProtocols.Http, handler.LastContext!.DetectedProtocol);
        Assert.Equal("sniff.example.com", handler.LastContext.DetectedDomain);
        Assert.Equal("sniff.example.com", handler.LastContext.TargetHost);
        Assert.Equal("sniff.example.com", handler.LastDestination!.Host);
        Assert.Equal("sniff.example.com", result.Destination.Host);

        var replay = new byte[payload.Length];
        await result.InboundStream.ReadExactlyAsync(replay.AsMemory(0, replay.Length), CancellationToken.None);
        Assert.Equal(payload, replay);
    }

    [Fact]
    public async Task DispatchInboundUdpAsync_applies_fake_dns_metadata_before_opening_transport()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.udp.example", ipv4: true, ipv6: false));
        var handler = new RecordingUdpOutboundHandler();
        var dispatcher = new DefaultDispatcher(
            new DefaultOutboundRouter(
                [handler],
                new StaticOutboundRuntimePlanProvider(new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "capture-udp",
                            Protocol = handler.Protocol
                        }
                    ],
                    DefaultOutboundTag = "capture-udp"
                })),
            rateLimiterRegistry: null,
            trafficRegistry: null,
            new DefaultRuntimeSniffer(fakeDnsEngine));
        var inboundDispatcher = Assert.IsAssignableFrom<IRuntimeInboundUdpDispatcher>(dispatcher);
        var originalDestination = new DispatchDestination
        {
            Host = fakeAddress.ToString(),
            Port = 53,
            Network = DispatchNetwork.Udp
        };
        var originalContext = DispatchContextTargeting.SetOriginalAndTarget(
            new DispatchContext
            {
                InboundProtocol = "test"
            },
            originalDestination);

        var result = await inboundDispatcher.DispatchInboundUdpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                MetadataOnly = true,
                DestinationOverride = [RoutingProtocols.FakeDns]
            },
            Array.Empty<byte>(),
            originalContext,
            originalDestination,
            CancellationToken.None,
            allowDestinationOverride: true);

        await using var transport = result.Transport;

        Assert.NotNull(handler.LastContext);
        Assert.Equal(RoutingProtocols.FakeDns, handler.LastContext!.DetectedProtocol);
        Assert.Equal("mapped.udp.example", handler.LastContext.DetectedDomain);
        Assert.Equal("mapped.udp.example", handler.LastContext.TargetHost);
        Assert.Equal(53, handler.LastContext.TargetPort);
        Assert.Equal("mapped.udp.example", result.Destination.Host);
        Assert.Equal(53, result.Destination.Port);
    }

    [Fact]
    public async Task DispatchTcpAsync_only_tracks_top_level_dispatch_once()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var trafficRegistry = new TrafficRegistry();
        var rateLimiterRegistry = new RateLimiterRegistry();
        var chainedHandler = new ChainedOutboundHandler();
        var dispatcher = CreateDispatcher(
            new IOutboundHandler[]
            {
                chainedHandler,
                new FreedomOutboundHandler()
            },
            new OutboundRuntimePlan
            {
                Outbounds =
                [
                    new OutboundRuntime
                    {
                        Tag = "chain",
                        Protocol = chainedHandler.Protocol
                    },
                    new OutboundRuntime
                    {
                        Tag = "direct",
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                DefaultOutboundTag = "chain"
            },
            rateLimiterRegistry,
            trafficRegistry);
        chainedHandler.Dispatcher = dispatcher;

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();
            var request = new byte[4];
            await stream.ReadExactlyAsync(request.AsMemory(0, request.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            return Encoding.ASCII.GetString(request);
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                InboundTag = "demo-inbound",
                UserId = "demo-user",
                ScopedUserId = RuntimeUserKeys.Create("test", "demo-inbound", "demo-user"),
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);
        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        Assert.Equal("ping", await serverTask);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));

        var snapshot = Assert.Single(trafficRegistry.CreateSnapshot());
        Assert.Equal(4, snapshot.UploadBytes);
        Assert.Equal(4, snapshot.DownloadBytes);
    }

    [Fact]
    public async Task DispatchTcpAsync_with_skip_transport_flow_control_does_not_track_traffic()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var trafficRegistry = new TrafficRegistry();
        var dispatcher = CreateDispatcher(new RateLimiterRegistry(), trafficRegistry);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();
            var request = new byte[4];
            await stream.ReadExactlyAsync(request.AsMemory(0, request.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            return Encoding.ASCII.GetString(request);
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                InboundTag = "demo-inbound",
                UserId = "demo-user",
                ScopedUserId = RuntimeUserKeys.Create("test", "demo-inbound", "demo-user"),
                SkipTransportFlowControl = true,
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);
        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        Assert.Equal("ping", await serverTask);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
        Assert.Empty(trafficRegistry.CreateSnapshot());
    }

    [Fact]
    public async Task DispatchUdpAsync_with_scoped_user_tracks_traffic()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var trafficRegistry = new TrafficRegistry();
        var dispatcher = CreateDispatcher(new RateLimiterRegistry(), trafficRegistry);

        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;

        var serverTask = Task.Run(async () =>
        {
            var buffer = new byte[1024];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var received = await udpSocket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                remoteEndPoint,
                cts.Token);

            await udpSocket.SendToAsync(
                buffer.AsMemory(0, received.ReceivedBytes),
                SocketFlags.None,
                received.RemoteEndPoint,
                cts.Token);
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                InboundTag = "demo-inbound",
                UserId = "demo-user",
                ScopedUserId = RuntimeUserKeys.Create("test", "demo-inbound", "demo-user"),
                UseCone = true
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("udp"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal("udp", Encoding.ASCII.GetString(datagram!.Payload));

        var snapshot = Assert.Single(trafficRegistry.CreateSnapshot());
        Assert.Equal("demo-user", snapshot.UserId);
        Assert.Equal("test", snapshot.Protocol);
        Assert.Equal("demo-inbound", snapshot.InboundTag);
        Assert.Equal(3, snapshot.UploadBytes);
        Assert.Equal(3, snapshot.DownloadBytes);
    }

    [Fact]
    public async Task DispatchUdpAsync_only_tracks_top_level_dispatch_once()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var trafficRegistry = new TrafficRegistry();
        var rateLimiterRegistry = new RateLimiterRegistry();
        var chainedHandler = new ChainedOutboundHandler();
        var dispatcher = CreateDispatcher(
            new IOutboundHandler[]
            {
                chainedHandler,
                new FreedomOutboundHandler()
            },
            new OutboundRuntimePlan
            {
                Outbounds =
                [
                    new OutboundRuntime
                    {
                        Tag = "chain",
                        Protocol = chainedHandler.Protocol
                    },
                    new OutboundRuntime
                    {
                        Tag = "direct",
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                DefaultOutboundTag = "chain"
            },
            rateLimiterRegistry,
            trafficRegistry);
        chainedHandler.Dispatcher = dispatcher;

        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;

        var serverTask = Task.Run(async () =>
        {
            var buffer = new byte[1024];
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            var received = await udpSocket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                remoteEndPoint,
                cts.Token);

            await udpSocket.SendToAsync(
                buffer.AsMemory(0, received.ReceivedBytes),
                SocketFlags.None,
                received.RemoteEndPoint,
                cts.Token);
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                InboundTag = "demo-inbound",
                UserId = "demo-user",
                ScopedUserId = RuntimeUserKeys.Create("test", "demo-inbound", "demo-user"),
                UseCone = true
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("udp"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal("udp", Encoding.ASCII.GetString(datagram!.Payload));

        var snapshot = Assert.Single(trafficRegistry.CreateSnapshot());
        Assert.Equal(3, snapshot.UploadBytes);
        Assert.Equal(3, snapshot.DownloadBytes);
    }

    private static IDispatcher CreateDispatcher(
        IRuntimeRateLimiterRegistry? rateLimiterRegistry = null,
        IRuntimeTrafficRegistry? trafficRegistry = null)
        => CreateDispatcher(
            [
                new FreedomOutboundHandler()
            ],
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
            },
            rateLimiterRegistry,
            trafficRegistry);

    private static IDispatcher CreateDispatcher(
        IEnumerable<IOutboundHandler> handlers,
        OutboundRuntimePlan plan,
        IRuntimeRateLimiterRegistry? rateLimiterRegistry = null,
        IRuntimeTrafficRegistry? trafficRegistry = null)
        => new DefaultDispatcher(
            new DefaultOutboundRouter(
                handlers,
                new StaticOutboundRuntimePlanProvider(plan)),
            rateLimiterRegistry,
            trafficRegistry);

    private static FakeDnsEngine CreateFakeDnsEngine()
        => new(
        [
            new FakeDnsPoolRuntime
            {
                IpPool = FakeDnsDefaults.IPv4Pool,
                LruSize = 256
            }
        ]);

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }

    private sealed class ChainedOutboundHandler : IOutboundHandler
    {
        public string Protocol => "chain";

        public IDispatcher Dispatcher { get; set; } = null!;

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => Dispatcher.DispatchTcpAsync(
                context with
                {
                    OutboundTag = "direct"
                },
                destination,
                cancellationToken);

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => Dispatcher.DispatchUdpAsync(
                context with
                {
                    OutboundTag = "direct"
                },
                cancellationToken);
    }

    private sealed class RecordingOutboundHandler : IOutboundHandler
    {
        public string Protocol => "capture";

        public DispatchContext? LastContext { get; private set; }

        public DispatchDestination? LastDestination { get; private set; }

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            LastContext = context;
            LastDestination = destination;
            return ValueTask.FromResult<Stream>(new MemoryStream());
        }

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class RecordingUdpOutboundHandler : IOutboundHandler
    {
        public string Protocol => "capture-udp";

        public DispatchContext? LastContext { get; private set; }

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
        {
            LastContext = context;
            return ValueTask.FromResult<IOutboundUdpTransport>(new NoopUdpTransport());
        }
    }

    private sealed class NoopUdpTransport : IOutboundUdpTransport
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

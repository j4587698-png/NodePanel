using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanOutboundHandlerTests
{
    [Fact]
    public async Task DispatchTcpAsync_routes_through_trojan_outbound()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new TrojanOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = TrojanOutboundTransports.Tcp,
                Password = "demo-password"
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new TrojanHandshakeReader().ReadAsync(stream, cts.Token);
            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Trojan,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);

        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        var capture = await serverTask;
        Assert.Equal(TrojanCommand.Connect, capture.Request.Command);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchUdpAsync_routes_through_trojan_associate_transport()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new TrojanOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = TrojanOutboundTransports.Tcp,
                Password = "demo-password"
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var handshakeReader = new TrojanHandshakeReader();
            var packetReader = new TrojanUdpPacketReader();
            var packetWriter = new TrojanUdpPacketWriter();

            var request = await handshakeReader.ReadAsync(stream, cts.Token);
            var packet = await packetReader.ReadAsync(stream, cts.Token)
                ?? throw new InvalidDataException("Expected a Trojan UDP packet.");

            await packetWriter.WriteAsync(
                stream,
                new TrojanUdpPacket
                {
                    DestinationHost = "198.51.100.10",
                    DestinationPort = 5300,
                    Payload = Encoding.ASCII.GetBytes("pong")
                },
                cts.Token);
            await stream.FlushAsync(cts.Token);

            return new UdpCapture(request, packet);
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Trojan,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        var capture = await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal(TrojanCommand.Associate, capture.Request.Command);
        Assert.Equal("8.8.8.8", capture.Request.TargetHost);
        Assert.Equal(53, capture.Request.TargetPort);
        Assert.Equal("8.8.8.8", capture.Packet.DestinationHost);
        Assert.Equal(53, capture.Packet.DestinationPort);
        Assert.Equal("ping", Encoding.ASCII.GetString(capture.Packet.Payload));
        Assert.Equal("198.51.100.10", datagram!.SourceHost);
        Assert.Equal(5300, datagram.SourcePort);
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram.Payload));
    }

    [Fact]
    public async Task DispatchTcpAsync_supports_proxy_outbound_tag_chaining()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var chainedHandler = new RecordingTcpForwardOutboundHandler("chain", IPAddress.Loopback.ToString(), port);
        var serviceProvider = new MutableDispatcherServiceProvider();
        var trojanSettings = new TrojanOutboundSettings
        {
            Tag = "proxy",
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = port,
            Transport = TrojanOutboundTransports.Tcp,
            Password = "demo-password",
            ProxyOutboundTag = "chain"
        };
        var trojanHandler = new TrojanOutboundHandler(
            new TrojanOutboundClient(),
            new StaticTrojanOutboundSettingsProvider(trojanSettings),
            new TrojanUdpPacketReader(),
            new TrojanUdpPacketWriter(),
            serviceProvider);
        var dispatcher = new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    chainedHandler,
                    trojanHandler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = "proxy",
                                Protocol = OutboundProtocols.Trojan
                            },
                            new OutboundRuntime
                            {
                                Tag = "chain",
                                Protocol = "chain"
                            }
                        ],
                        DefaultOutboundTag = "proxy"
                    })));
        serviceProvider.Dispatcher = dispatcher;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new TrojanHandshakeReader().ReadAsync(stream, cts.Token);
            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Trojan,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);

        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        var capture = await serverTask;
        Assert.True(chainedHandler.WasOpened);
        Assert.Equal(TrojanCommand.Connect, capture.Request.Command);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    private static IDispatcher CreateDispatcher(TrojanOutboundSettings settings)
        => new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler(),
                    new TrojanOutboundHandler(
                        new TrojanOutboundClient(),
                        new StaticTrojanOutboundSettingsProvider(settings),
                        new TrojanUdpPacketReader(),
                        new TrojanUdpPacketWriter())
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = settings.Tag,
                                Protocol = OutboundProtocols.Trojan
                            }
                        ],
                        DefaultOutboundTag = settings.Tag
                    })));

    private sealed class StaticTrojanOutboundSettingsProvider : ITrojanOutboundSettingsProvider
    {
        private readonly TrojanOutboundSettings _settings;

        public StaticTrojanOutboundSettingsProvider(TrojanOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
        {
            settings = _settings;
            return true;
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

    private sealed record TcpCapture(TrojanRequest Request, string PayloadText);

    private sealed record UdpCapture(TrojanRequest Request, TrojanUdpPacket Packet);

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
}

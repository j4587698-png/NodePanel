using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanMuxRuntimeTests
{
    [Fact]
    public async Task DispatchTcpAsync_uses_mux_target_and_relays_tcp_session()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        using var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        var echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;
        var echoTask = Task.Run(async () =>
        {
            using var client = await echoListener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await stream.FlushAsync(cts.Token);
            return Encoding.ASCII.GetString(payload);
        }, cts.Token);

        var serverOptions = CreateServerOptions();
        var inboundHandler = CreateInboundHandler(new FreedomOutboundHandler());
        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;
        var handshakeTcs = new TaskCompletionSource<TrojanRequest>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = Task.Run(async () =>
        {
            using var client = await frontListener.AcceptTcpClientAsync(cts.Token);
            await using var recordingStream = new RecordingStream(client.GetStream());
            try
            {
                await inboundHandler.HandleAsync(recordingStream, serverOptions, cts.Token);
            }
            finally
            {
                var request = await new TrojanHandshakeReader().ReadAsync(
                    new MemoryStream(recordingStream.CapturedBytes),
                    cts.Token);
                handshakeTcs.TrySetResult(request);
            }
        }, cts.Token);

        await using var clientRuntime = CreateClientRuntime(
            new TrojanOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = frontPort,
                Transport = TrojanOutboundTransports.Tcp,
                Password = "demo-password",
                MultiplexSettings = new OutboundMultiplexRuntime
                {
                    Enabled = true,
                    Concurrency = 4
                }
            });

        await using var outbound = await clientRuntime.Dispatcher.DispatchTcpAsync(
            CreateDispatchContext(),
            new DispatchDestination
            {
                Host = IPAddress.Loopback.ToString(),
                Port = echoPort,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);

        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        Assert.Equal("ping", await echoTask);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));

        await clientRuntime.DisposeAsync();
        await serverTask;

        var handshake = await handshakeTcs.Task.WaitAsync(cts.Token);
        Assert.Equal(TrojanCommand.Connect, handshake.Command);
        Assert.Equal("v1.mux.cool", handshake.TargetHost);
        Assert.Equal(9527, handshake.TargetPort);
    }

    [Fact]
    public async Task DispatchUdpAsync_uses_mux_target_and_relays_udp_packets()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

        var udpHandler = new EchoUdpOutboundHandler();
        var serverOptions = CreateServerOptions();
        var inboundHandler = CreateInboundHandler(udpHandler);
        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;
        var handshakeTcs = new TaskCompletionSource<TrojanRequest>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = Task.Run(async () =>
        {
            using var client = await frontListener.AcceptTcpClientAsync(cts.Token);
            await using var recordingStream = new RecordingStream(client.GetStream());
            try
            {
                await inboundHandler.HandleAsync(recordingStream, serverOptions, cts.Token);
            }
            finally
            {
                var request = await new TrojanHandshakeReader().ReadAsync(
                    new MemoryStream(recordingStream.CapturedBytes),
                    cts.Token);
                handshakeTcs.TrySetResult(request);
            }
        }, cts.Token);

        await using var clientRuntime = CreateClientRuntime(
            new TrojanOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = frontPort,
                Transport = TrojanOutboundTransports.Tcp,
                Password = "demo-password",
                MultiplexSettings = new OutboundMultiplexRuntime
                {
                    Enabled = true,
                    Concurrency = 4,
                    XudpConcurrency = 8,
                    XudpProxyUdp443 = OutboundXudpProxyModes.Allow
                }
            });

        await using var transport = await clientRuntime.Dispatcher.DispatchUdpAsync(
            CreateDispatchContext(),
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
        Assert.NotNull(datagram);
        Assert.Equal("8.8.8.8", datagram!.SourceHost);
        Assert.Equal(53, datagram.SourcePort);
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram.Payload));

        await clientRuntime.DisposeAsync();
        await serverTask;

        var handshake = await handshakeTcs.Task.WaitAsync(cts.Token);
        Assert.Equal(TrojanCommand.Connect, handshake.Command);
        Assert.Equal("v1.mux.cool", handshake.TargetHost);
        Assert.Equal(9527, handshake.TargetPort);

        var capture = await udpHandler.CaptureTcs.Task.WaitAsync(cts.Token);
        Assert.Equal("8.8.8.8", capture.Host);
        Assert.Equal(53, capture.Port);
        Assert.Equal("ping", capture.PayloadText);
    }

    [Fact]
    public async Task DispatchUdpAsync_rejects_udp_443_when_xudp_mode_is_reject()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var clientRuntime = CreateClientRuntime(
            new TrojanOutboundSettings
            {
                Tag = "proxy",
                ServerHost = "127.0.0.1",
                ServerPort = 443,
                Transport = TrojanOutboundTransports.Tcp,
                Password = "demo-password",
                MultiplexSettings = new OutboundMultiplexRuntime
                {
                    Enabled = true,
                    Concurrency = 4,
                    XudpProxyUdp443 = OutboundXudpProxyModes.Reject
                }
            });

        await using var transport = await clientRuntime.Dispatcher.DispatchUdpAsync(
            CreateDispatchContext(),
            cts.Token);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => transport.SendAsync(
            new DispatchDestination
            {
                Host = "1.1.1.1",
                Port = 443,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping"),
            cts.Token).AsTask());
        Assert.Contains("UDP/443", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DispatchUdpAsync_skips_mux_for_udp_443_when_xudp_mode_is_skip()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        await using var clientRuntime = CreateClientRuntime(
            new TrojanOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = TrojanOutboundTransports.Tcp,
                Password = "demo-password",
                MultiplexSettings = new OutboundMultiplexRuntime
                {
                    Enabled = true,
                    Concurrency = 4,
                    XudpConcurrency = 8,
                    XudpProxyUdp443 = OutboundXudpProxyModes.Skip
                }
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
                    DestinationHost = "1.1.1.1",
                    DestinationPort = 443,
                    Payload = Encoding.ASCII.GetBytes("pong")
                },
                cts.Token);
            await stream.FlushAsync(cts.Token);

            return new UdpCapture(request, packet);
        }, cts.Token);

        await using var transport = await clientRuntime.Dispatcher.DispatchUdpAsync(
            CreateDispatchContext(),
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "1.1.1.1",
                Port = 443,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        var capture = await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal(TrojanCommand.Associate, capture.Request.Command);
        Assert.Equal("1.1.1.1", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("1.1.1.1", capture.Packet.DestinationHost);
        Assert.Equal(443, capture.Packet.DestinationPort);
        Assert.Equal("ping", Encoding.ASCII.GetString(capture.Packet.Payload));
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram!.Payload));
    }

    private static TrojanInboundConnectionHandler CreateInboundHandler(IOutboundHandler outboundHandler)
    {
        var planProvider = new StaticOutboundRuntimePlanProvider(
            new OutboundRuntimePlan
            {
                Outbounds =
                [
                    new OutboundRuntime
                    {
                        Tag = "default",
                        Protocol = outboundHandler.Protocol
                    }
                ],
                DefaultOutboundTag = "default"
            });
        var dispatcher = new DefaultDispatcher(
            new DefaultOutboundRouter(
                [outboundHandler],
                planProvider));
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var udpPacketReader = new TrojanUdpPacketReader();
        var udpPacketWriter = new TrojanUdpPacketWriter();
        return new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                udpPacketReader,
                udpPacketWriter),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            new SessionRegistry(),
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);
    }

    private static ClientRuntime CreateClientRuntime(TrojanOutboundSettings settings)
    {
        var trojanHandler = new TrojanOutboundHandler(
            new TrojanOutboundClient(),
            new StaticTrojanOutboundSettingsProvider(settings),
            new TrojanUdpPacketReader(),
            new TrojanUdpPacketWriter());
        return new ClientRuntime(
            new DefaultDispatcher(
                new DefaultOutboundRouter(
                    new IOutboundHandler[]
                    {
                        new FreedomOutboundHandler(),
                        trojanHandler
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
                        }))),
            trojanHandler);
    }

    private static DispatchContext CreateDispatchContext()
        => new()
        {
            InboundProtocol = InboundProtocols.Trojan,
            InboundTag = "edge",
            UserId = "user-1",
            ConnectTimeoutSeconds = 5
        };

    private static TestTrojanConnectionOptions CreateServerOptions()
        => new()
        {
            InboundTag = "server",
            UsersByHash = TestTrojanConnectionOptions.CreateUsers(("user-1", "demo-password", 0))
        };

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

    private sealed class EchoUdpOutboundHandler : IOutboundHandler
    {
        public TaskCompletionSource<UdpSendCapture> CaptureTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Protocol => "udp-echo";

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<IOutboundUdpTransport>(new EchoUdpTransport(CaptureTcs));
    }

    private sealed class EchoUdpTransport : IOutboundUdpTransport
    {
        private readonly TaskCompletionSource<UdpSendCapture> _captureTcs;
        private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>();

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

    private sealed class RecordingStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly MemoryStream _capture = new();

        public RecordingStream(Stream innerStream)
        {
            _innerStream = innerStream;
        }

        public byte[] CapturedBytes => _capture.ToArray();

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _innerStream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _innerStream.Read(buffer, offset, count);
            if (read > 0)
            {
                _capture.Write(buffer, offset, read);
            }

            return read;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _innerStream.ReadAsync(buffer, cancellationToken);
            if (read > 0)
            {
                await _capture.WriteAsync(buffer[..read], cancellationToken);
            }

            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => _innerStream.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask DisposeAsync() => _innerStream.DisposeAsync();
    }

    private sealed record UdpSendCapture(string Host, int Port, string PayloadText);

    private sealed record UdpCapture(TrojanRequest Request, TrojanUdpPacket Packet);

    private sealed class ClientRuntime : IAsyncDisposable
    {
        public ClientRuntime(IDispatcher dispatcher, TrojanOutboundHandler handler)
        {
            Dispatcher = dispatcher;
            Handler = handler;
        }

        public IDispatcher Dispatcher { get; }

        public TrojanOutboundHandler Handler { get; }

        public ValueTask DisposeAsync() => Handler.DisposeAsync();
    }
}

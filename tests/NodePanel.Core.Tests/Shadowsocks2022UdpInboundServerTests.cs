using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class Shadowsocks2022UdpInboundServerTests
{
    [Fact]
    public async Task RunAsync_sniffs_each_udp_send_before_forwarding()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingUdpDispatcher();
        var fakeDnsEngine = new FakeDnsEngine(
        [
            new FakeDnsPoolRuntime
            {
                IpPool = FakeDnsDefaults.IPv4Pool,
                LruSize = 256
            }
        ]);
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.udp.example", ipv4: true, ipv6: false));
        var server = new Shadowsocks2022UdpInboundServer(
            dispatcher,
            new SessionRegistry(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            fakeDnsEngine);

        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var port = AllocateUdpPort();
        var user = new Shadowsocks2022User
        {
            UserId = "udp-user",
            Password = serverKey,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-udp", "udp-user"),
            BytesPerSecond = 0
        };

        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new ShadowsocksInboundServerOptions
            {
                Plan = new ShadowsocksInboundRuntimePlan
                {
                    Inbounds2022 =
                    [
                        new Shadowsocks2022InboundRuntime
                        {
                            RuntimeState = new Shadowsocks2022InboundRuntimeState(
                                method,
                                serverKey,
                                Shadowsocks2022InboundModes.SingleUser,
                                [user]),
                            Tag = "ss-2022-udp",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
                            Method = method,
                            Key = serverKey,
                            Mode = Shadowsocks2022InboundModes.SingleUser,
                            Users = [user],
                            Sniffing = new RuntimeSniffingOptions
                            {
                                Enabled = true,
                                MetadataOnly = true,
                                DestinationOverride = [RoutingProtocols.FakeDns]
                            }
                        }
                    ]
                },
                UseCone = true,
                Callbacks = new ShadowsocksInboundServerCallbacks
                {
                    ListenerStarted = _ => listenerStarted.TrySetResult(true)
                }
            },
            cts.Token);

        await listenerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = new IPEndPoint(IPAddress.Loopback, port);
        var account = Shadowsocks2022Account.Create(method, serverKey);

        var firstResponse = await SendAndReceiveAsync(
            clientSocket,
            serverEndPoint,
            account,
            5301,
            "first",
            cts.Token,
            "127.0.0.1");
        var secondResponse = await SendAndReceiveAsync(
            clientSocket,
            serverEndPoint,
            account,
            5302,
            "second",
            cts.Token,
            fakeAddress.ToString());

        cts.Cancel();
        await serverTask;

        Assert.Equal("first", Encoding(firstResponse.Payload));
        Assert.Equal("127.0.0.1", firstResponse.Host);
        Assert.Equal("second", Encoding(secondResponse.Payload));
        Assert.Equal("mapped.udp.example", secondResponse.Host);
        Assert.Equal(1, dispatcher.DispatchCallCount);
        var transportDestinations = Assert.Single(dispatcher.TransportDestinations);
        Assert.Equal(2, transportDestinations.Count);
        Assert.Equal("127.0.0.1", transportDestinations[0].Host);
        Assert.Equal("mapped.udp.example", transportDestinations[1].Host);
    }

    [Fact]
    public async Task RunAsync_relay_mode_preserves_fixed_destination_when_sniffing_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingUdpDispatcher();
        var fakeDnsEngine = new FakeDnsEngine(
        [
            new FakeDnsPoolRuntime
            {
                IpPool = FakeDnsDefaults.IPv4Pool,
                LruSize = 256
            }
        ]);
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.udp.example", ipv4: true, ipv6: false));
        var server = new Shadowsocks2022UdpInboundServer(
            dispatcher,
            new SessionRegistry(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            fakeDnsEngine);

        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var userKey = CreateShadowsocks2022Key(method, 32);
        var port = AllocateUdpPort();
        var user = new Shadowsocks2022User
        {
            UserId = "relay-user",
            Password = userKey,
            Address = "relay.example.com",
            Port = 5301,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-relay", "relay-user"),
            BytesPerSecond = 0
        };

        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new ShadowsocksInboundServerOptions
            {
                Plan = new ShadowsocksInboundRuntimePlan
                {
                    Inbounds2022 =
                    [
                        new Shadowsocks2022InboundRuntime
                        {
                            RuntimeState = new Shadowsocks2022InboundRuntimeState(
                                method,
                                serverKey,
                                Shadowsocks2022InboundModes.Relay,
                                [user]),
                            Tag = "ss-2022-relay",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
                            Method = method,
                            Key = serverKey,
                            Mode = Shadowsocks2022InboundModes.Relay,
                            Users = [user],
                            Sniffing = new RuntimeSniffingOptions
                            {
                                Enabled = true,
                                MetadataOnly = true,
                                DestinationOverride = [RoutingProtocols.FakeDns]
                            }
                        }
                    ]
                },
                UseCone = true,
                Callbacks = new ShadowsocksInboundServerCallbacks
                {
                    ListenerStarted = _ => listenerStarted.TrySetResult(true)
                }
            },
            cts.Token);

        await listenerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = new IPEndPoint(IPAddress.Loopback, port);
        var account = Shadowsocks2022Account.Create(method, $"{serverKey}:{userKey}");

        var response = await SendAndReceiveAsync(
            clientSocket,
            serverEndPoint,
            account,
            2053,
            "relay",
            cts.Token,
            fakeAddress.ToString());

        cts.Cancel();
        await serverTask;

        Assert.Equal("relay", Encoding(response.Payload));
        Assert.Equal("relay.example.com", response.Host);
        Assert.Equal(5301, response.Port);

        var context = Assert.Single(dispatcher.Contexts);
        Assert.Equal(fakeAddress.ToString(), context.OriginalDestinationHost);
        Assert.Equal(2053, context.OriginalDestinationPort);
        Assert.Equal(string.Empty, context.DetectedProtocol);
        Assert.Equal(string.Empty, context.DetectedDomain);
        Assert.Equal("relay.example.com", context.TargetHost);
        Assert.Equal(5301, context.TargetPort);

        var transportDestinations = Assert.Single(dispatcher.TransportDestinations);
        var destination = Assert.Single(transportDestinations);
        Assert.Equal("relay.example.com", destination.Host);
        Assert.Equal(5301, destination.Port);
    }

    [Fact]
    public async Task RunAsync_relay_mode_reuses_session_when_requested_destination_changes()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingUdpDispatcher();
        var server = new Shadowsocks2022UdpInboundServer(
            dispatcher,
            new SessionRegistry(),
            new RateLimiterRegistry(),
            new TrafficRegistry());

        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var userKey = CreateShadowsocks2022Key(method, 32);
        var port = AllocateUdpPort();
        var user = new Shadowsocks2022User
        {
            UserId = "relay-user",
            Password = userKey,
            Address = "relay.example.com",
            Port = 5301,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-relay", "relay-user"),
            BytesPerSecond = 0
        };

        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new ShadowsocksInboundServerOptions
            {
                Plan = new ShadowsocksInboundRuntimePlan
                {
                    Inbounds2022 =
                    [
                        new Shadowsocks2022InboundRuntime
                        {
                            RuntimeState = new Shadowsocks2022InboundRuntimeState(
                                method,
                                serverKey,
                                Shadowsocks2022InboundModes.Relay,
                                [user]),
                            Tag = "ss-2022-relay",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
                            Method = method,
                            Key = serverKey,
                            Mode = Shadowsocks2022InboundModes.Relay,
                            Users = [user]
                        }
                    ]
                },
                UseCone = false,
                Callbacks = new ShadowsocksInboundServerCallbacks
                {
                    ListenerStarted = _ => listenerStarted.TrySetResult(true)
                }
            },
            cts.Token);

        await listenerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = new IPEndPoint(IPAddress.Loopback, port);
        var account = Shadowsocks2022Account.Create(method, $"{serverKey}:{userKey}");

        var firstResponse = await SendAndReceiveAsync(
            clientSocket,
            serverEndPoint,
            account,
            2053,
            "first",
            cts.Token,
            "first.example.com");
        var secondResponse = await SendAndReceiveAsync(
            clientSocket,
            serverEndPoint,
            account,
            2054,
            "second",
            cts.Token,
            "second.example.com");

        cts.Cancel();
        await serverTask;

        Assert.Equal("first", Encoding(firstResponse.Payload));
        Assert.Equal("relay.example.com", firstResponse.Host);
        Assert.Equal("second", Encoding(secondResponse.Payload));
        Assert.Equal("relay.example.com", secondResponse.Host);
        Assert.Equal(1, dispatcher.DispatchCallCount);
        var transportDestinations = Assert.Single(dispatcher.TransportDestinations);
        Assert.Equal(2, transportDestinations.Count);
        Assert.All(transportDestinations, static destination => Assert.Equal("relay.example.com", destination.Host));
        Assert.All(transportDestinations, static destination => Assert.Equal(5301, destination.Port));
    }

    private static async Task<ShadowsocksUdpPacket> SendAndReceiveAsync(
        Socket clientSocket,
        EndPoint serverEndPoint,
        Shadowsocks2022Account account,
        int destinationPort,
        string payload,
        CancellationToken cancellationToken,
        string destinationHost = "127.0.0.1")
    {
        var encoded = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
            account,
            destinationHost,
            destinationPort,
            System.Text.Encoding.ASCII.GetBytes(payload));
        await clientSocket.SendToAsync(encoded, SocketFlags.None, serverEndPoint, cancellationToken);

        var buffer = new byte[65535];
        var received = await clientSocket.ReceiveFromAsync(
            buffer.AsMemory(0, buffer.Length),
            SocketFlags.None,
            new IPEndPoint(IPAddress.Any, 0),
            cancellationToken);
        return Shadowsocks2022ProtocolCodec.DecodeUdpPacket(account, buffer.AsSpan(0, received.ReceivedBytes));
    }

    private static int AllocateUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static string Encoding(byte[] payload)
        => System.Text.Encoding.ASCII.GetString(payload);

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

    private sealed class RecordingUdpDispatcher : IDispatcher
    {
        private readonly Lock _sync = new();
        private readonly List<DispatchContext> _contexts = [];
        private readonly List<EchoUdpTransport> _transports = [];
        private int _dispatchCallCount;

        public int DispatchCallCount => _dispatchCallCount;

        public IReadOnlyList<DispatchContext> Contexts
        {
            get
            {
                lock (_sync)
                {
                    return _contexts.ToArray();
                }
            }
        }

        public IReadOnlyList<IReadOnlyList<DispatchDestination>> TransportDestinations
        {
            get
            {
                lock (_sync)
                {
                    return _transports
                        .Select(static transport => (IReadOnlyList<DispatchDestination>)transport.Destinations.ToArray())
                        .ToArray();
                }
            }
        }

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(DispatchContext context, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _dispatchCallCount);
            var transport = new EchoUdpTransport();
            lock (_sync)
            {
                _contexts.Add(context);
                _transports.Add(transport);
            }

            return ValueTask.FromResult<IOutboundUdpTransport>(transport);
        }
    }

    private sealed class EchoUdpTransport : IOutboundUdpTransport
    {
        private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>();

        public ConcurrentQueue<DispatchDestination> Destinations { get; } = new();

        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            Destinations.Enqueue(destination);
            return _responses.Writer.WriteAsync(
                new DispatchDatagram
                {
                    SourceHost = destination.Host,
                    SourcePort = destination.Port,
                    Payload = payload.ToArray()
                },
                cancellationToken);
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            while (await _responses.Reader.WaitToReadAsync(cancellationToken))
            {
                if (_responses.Reader.TryRead(out var datagram))
                {
                    return datagram;
                }
            }

            return null;
        }

        public ValueTask DisposeAsync()
        {
            _responses.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }
}

using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ShadowsocksUdpInboundServerTests
{
    [Theory]
    [InlineData(true, 1)]
    [InlineData(false, 2)]
    public async Task RunAsync_tracks_udp_sessions_by_cone_policy(bool useCone, int expectedDispatchCalls)
    {
        var result = await RunScenarioAsync(useCone);

        Assert.Equal("one", result.FirstResponsePayload);
        Assert.Equal(5301, result.FirstResponsePort);
        Assert.Equal("two", result.SecondResponsePayload);
        Assert.Equal(5302, result.SecondResponsePort);
        Assert.Equal(expectedDispatchCalls, result.DispatchCallCount);
        Assert.Equal(expectedDispatchCalls, result.Contexts.Count);
        Assert.Equal(expectedDispatchCalls, result.TransportCount);

        var firstContext = result.Contexts[0];
        Assert.Equal("udp-user", firstContext.UserId);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-udp", "udp-user"), firstContext.ScopedUserId);
        Assert.Equal(RoutingNetworks.Udp, firstContext.InboundSourceNetwork);
        Assert.Equal("127.0.0.1", firstContext.OriginalDestinationHost);
        Assert.Equal(5301, firstContext.OriginalDestinationPort);

        if (useCone)
        {
            Assert.Equal(2, result.TransportDestinations[0].Count);
            Assert.Equal([5301, 5302], result.TransportDestinations[0].Select(static destination => destination.Port));
        }
        else
        {
            Assert.Equal(5302, result.Contexts[1].OriginalDestinationPort);
            Assert.All(result.TransportDestinations, static destinations => Assert.Single(destinations));
            Assert.Equal(5301, result.TransportDestinations[0][0].Port);
            Assert.Equal(5302, result.TransportDestinations[1][0].Port);
        }
    }

    [Fact]
    public async Task RunAsync_uses_fake_dns_metadata_to_override_udp_destination()
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
        var server = new ShadowsocksUdpInboundServer(
            dispatcher,
            new SessionRegistry(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            fakeDnsEngine);

        var port = AllocateUdpPort();
        var user = new ShadowsocksUser
        {
            UserId = "udp-user",
            Cipher = ShadowsocksCipherTypes.XChaCha20Poly1305,
            Password = "secret-x",
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-udp", "udp-user"),
            BytesPerSecond = 0
        };

        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new ShadowsocksInboundServerOptions
            {
                Plan = new ShadowsocksInboundRuntimePlan
                {
                    Inbounds =
                    [
                        new ShadowsocksInboundRuntime
                        {
                            RuntimeState = new ShadowsocksInboundRuntimeState([user]),
                            Tag = "ss-udp",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
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
        var account = ShadowsocksAccount.Create(ShadowsocksCipherTypes.XChaCha20Poly1305, "secret-x");

        var response = await SendAndReceiveAsync(
            clientSocket,
            serverEndPoint,
            account,
            5301,
            "payload",
            cts.Token,
            fakeAddress.ToString());

        cts.Cancel();
        await serverTask;

        Assert.Equal("payload", Encoding(response.Payload));
        var context = Assert.Single(dispatcher.Contexts);
        Assert.Equal(RoutingProtocols.FakeDns, context.DetectedProtocol);
        Assert.Equal("mapped.udp.example", context.DetectedDomain);
        var transportDestinations = Assert.Single(dispatcher.TransportDestinations);
        var destination = Assert.Single(transportDestinations);
        Assert.Equal("mapped.udp.example", destination.Host);
        Assert.Equal(5301, destination.Port);
    }

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
        var server = new ShadowsocksUdpInboundServer(
            dispatcher,
            new SessionRegistry(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            fakeDnsEngine);

        var port = AllocateUdpPort();
        var user = new ShadowsocksUser
        {
            UserId = "udp-user",
            Cipher = ShadowsocksCipherTypes.XChaCha20Poly1305,
            Password = "secret-x",
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-udp", "udp-user"),
            BytesPerSecond = 0
        };

        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new ShadowsocksInboundServerOptions
            {
                Plan = new ShadowsocksInboundRuntimePlan
                {
                    Inbounds =
                    [
                        new ShadowsocksInboundRuntime
                        {
                            RuntimeState = new ShadowsocksInboundRuntimeState([user]),
                            Tag = "ss-udp",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
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
        var account = ShadowsocksAccount.Create(ShadowsocksCipherTypes.XChaCha20Poly1305, "secret-x");

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

    private static async Task<UdpInboundScenarioResult> RunScenarioAsync(bool useCone)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingUdpDispatcher();
        var server = new ShadowsocksUdpInboundServer(
            dispatcher,
            new SessionRegistry(),
            new RateLimiterRegistry(),
            new TrafficRegistry());

        var port = AllocateUdpPort();
        var user = new ShadowsocksUser
        {
            UserId = "udp-user",
            Cipher = ShadowsocksCipherTypes.XChaCha20Poly1305,
            Password = "secret-x",
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-udp", "udp-user"),
            BytesPerSecond = 0
        };

        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new ShadowsocksInboundServerOptions
            {
                Plan = new ShadowsocksInboundRuntimePlan
                {
                    Inbounds =
                    [
                        new ShadowsocksInboundRuntime
                        {
                            RuntimeState = new ShadowsocksInboundRuntimeState([user]),
                            Tag = "ss-udp",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
                            Users = [user]
                        }
                    ]
                },
                UseCone = useCone,
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
        var account = ShadowsocksAccount.Create(ShadowsocksCipherTypes.XChaCha20Poly1305, "secret-x");

        var firstResponse = await SendAndReceiveAsync(clientSocket, serverEndPoint, account, 5301, "one", cts.Token);
        var secondResponse = await SendAndReceiveAsync(clientSocket, serverEndPoint, account, 5302, "two", cts.Token);

        cts.Cancel();
        await serverTask;

        return new UdpInboundScenarioResult(
            Encoding(firstResponse.Payload),
            firstResponse.Port,
            Encoding(secondResponse.Payload),
            secondResponse.Port,
            dispatcher.DispatchCallCount,
            dispatcher.Contexts,
            dispatcher.TransportDestinations,
            dispatcher.TransportCount);
    }

    private static async Task<ShadowsocksUdpPacket> SendAndReceiveAsync(
        Socket clientSocket,
        EndPoint serverEndPoint,
        ShadowsocksAccount account,
        int destinationPort,
        string payload,
        CancellationToken cancellationToken,
        string destinationHost = "127.0.0.1")
    {
        var encoded = ShadowsocksProtocolCodec.EncodeUdpPacket(
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
        return ShadowsocksProtocolCodec.DecodeUdpPacket(account, buffer.AsSpan(0, received.ReceivedBytes));
    }

    private static int AllocateUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static string Encoding(byte[] payload)
        => System.Text.Encoding.ASCII.GetString(payload);

    private sealed record UdpInboundScenarioResult(
        string FirstResponsePayload,
        int FirstResponsePort,
        string SecondResponsePayload,
        int SecondResponsePort,
        int DispatchCallCount,
        IReadOnlyList<DispatchContext> Contexts,
        IReadOnlyList<IReadOnlyList<DispatchDestination>> TransportDestinations,
        int TransportCount);

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

        public int TransportCount
        {
            get
            {
                lock (_sync)
                {
                    return _transports.Count;
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

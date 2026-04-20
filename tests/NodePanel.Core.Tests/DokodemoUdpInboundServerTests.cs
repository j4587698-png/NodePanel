using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading.Channels;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class DokodemoUdpInboundServerTests
{
    [Fact]
    public async Task RunAsync_relays_udp_packets_to_fixed_target_and_reuses_session()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingUdpDispatcher();
        var server = new DokodemoUdpInboundServer(dispatcher);
        var port = AllocateUdpPort();
        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var targetPort = 5353;
        var serverTask = server.RunAsync(
            new DokodemoInboundServerOptions
            {
                Plan = new DokodemoInboundRuntimePlan
                {
                    Inbounds =
                    [
                        new DokodemoInboundRuntime
                        {
                            Tag = "dokodemo",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            DestinationHost = "example.org",
                            DestinationPort = 53,
                            Networks = [RoutingNetworks.Udp],
                            PortMap = new Dictionary<string, string>(StringComparer.Ordinal)
                            {
                                [port.ToString()] = $"127.0.0.1:{targetPort}"
                            }
                        }
                    ]
                },
                Callbacks = new DokodemoInboundServerCallbacks
                {
                    ListenerStarted = _ => listenerStarted.TrySetResult(true)
                }
            },
            cts.Token);

        await listenerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = new IPEndPoint(IPAddress.Loopback, port);

        var firstResponse = await SendAndReceiveAsync(clientSocket, serverEndPoint, "one", cts.Token);
        var secondResponse = await SendAndReceiveAsync(clientSocket, serverEndPoint, "two", cts.Token);

        Assert.Equal("one", firstResponse);
        Assert.Equal("two", secondResponse);
        Assert.Equal(1, dispatcher.DispatchCallCount);

        var context = Assert.Single(dispatcher.Contexts);
        Assert.Equal(InboundProtocols.DokodemoDoor, context.InboundProtocol);
        Assert.Equal("dokodemo", context.InboundTag);
        Assert.Equal(RoutingNetworks.Udp, context.InboundSourceNetwork);
        Assert.Equal("127.0.0.1", context.OriginalDestinationHost);
        Assert.Equal(targetPort, context.OriginalDestinationPort);

        var destinations = Assert.Single(dispatcher.TransportDestinations);
        Assert.Equal(2, destinations.Count);
        Assert.All(destinations, destination =>
        {
            Assert.Equal("127.0.0.1", destination.Host);
            Assert.Equal(targetPort, destination.Port);
            Assert.Equal(DispatchNetwork.Udp, destination.Network);
        });

        cts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task RunAsync_uses_fake_dns_metadata_to_override_udp_destination_on_first_packet()
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
        var server = new DokodemoUdpInboundServer(dispatcher, fakeDnsEngine);
        var port = AllocateUdpPort();
        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new DokodemoInboundServerOptions
            {
                Plan = new DokodemoInboundRuntimePlan
                {
                    Inbounds =
                    [
                        new DokodemoInboundRuntime
                        {
                            Tag = "dokodemo",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            DestinationHost = fakeAddress.ToString(),
                            DestinationPort = 5353,
                            Networks = [RoutingNetworks.Udp],
                            Sniffing = new RuntimeSniffingOptions
                            {
                                Enabled = true,
                                MetadataOnly = true,
                                DestinationOverride = [RoutingProtocols.FakeDns]
                            }
                        }
                    ]
                },
                Callbacks = new DokodemoInboundServerCallbacks
                {
                    ListenerStarted = _ => listenerStarted.TrySetResult(true)
                }
            },
            cts.Token);

        await listenerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = new IPEndPoint(IPAddress.Loopback, port);

        var response = await SendAndReceiveAsync(clientSocket, serverEndPoint, "payload", cts.Token);

        Assert.Equal("payload", response);
        Assert.Equal(1, dispatcher.DispatchCallCount);

        var context = Assert.Single(dispatcher.Contexts);
        Assert.Equal(RoutingProtocols.FakeDns, context.DetectedProtocol);
        Assert.Equal("mapped.udp.example", context.DetectedDomain);
        Assert.Equal("mapped.udp.example", context.TargetHost);
        Assert.Equal(5353, context.TargetPort);

        var destinations = Assert.Single(dispatcher.TransportDestinations);
        var destination = Assert.Single(destinations);
        Assert.Equal("mapped.udp.example", destination.Host);
        Assert.Equal(5353, destination.Port);
        Assert.Equal(DispatchNetwork.Udp, destination.Network);

        cts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task RunAsync_resolves_follow_redirect_destination_per_datagram_and_uses_redirect_writer()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingUdpDispatcher();
        var responseCapture = new RedirectResponseCapture();
        var redirectSupport = new TestDokodemoUdpRedirectSupport(
            new IPEndPoint(IPAddress.Parse("203.0.113.7"), 5353),
            responseCapture);
        var server = new DokodemoUdpInboundServer(
            dispatcher,
            fakeDnsEngine: null,
            redirectSupport: redirectSupport);
        var port = AllocateUdpPort();
        var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = server.RunAsync(
            new DokodemoInboundServerOptions
            {
                Plan = new DokodemoInboundRuntimePlan
                {
                    Inbounds =
                    [
                        new DokodemoInboundRuntime
                        {
                            Tag = "dokodemo",
                            Binding = new ListenerBinding("127.0.0.1", port),
                            Networks = [RoutingNetworks.Udp],
                            FollowRedirect = true,
                            UserLevel = 9,
                            Mark = 77
                        }
                    ]
                },
                SessionPolicies = new RuntimeSessionPolicyCatalog
                {
                    DefaultPolicy = new RuntimeSessionPolicy
                    {
                        Timeout = new RuntimeSessionPolicyTimeouts
                        {
                            ConnectionIdleSeconds = 300,
                            UplinkOnlySeconds = 1,
                            DownlinkOnlySeconds = 1
                        }
                    },
                    Levels = new Dictionary<int, RuntimeSessionPolicy>
                    {
                        [9] = new()
                        {
                            Timeout = new RuntimeSessionPolicyTimeouts
                            {
                                ConnectionIdleSeconds = 42,
                                UplinkOnlySeconds = 7,
                                DownlinkOnlySeconds = 8
                            }
                        }
                    }
                },
                Callbacks = new DokodemoInboundServerCallbacks
                {
                    ListenerStarted = _ => listenerStarted.TrySetResult(true)
                }
            },
            cts.Token);

        await listenerStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        using var clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        clientSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEndPoint = new IPEndPoint(IPAddress.Loopback, port);

        var response = await SendAndReceiveAsync(clientSocket, serverEndPoint, "redirect", cts.Token);

        Assert.Equal("redirect", response);
        Assert.Equal(1, dispatcher.DispatchCallCount);

        var context = Assert.Single(dispatcher.Contexts);
        Assert.Equal(InboundProtocols.DokodemoDoor, context.InboundProtocol);
        Assert.Equal("dokodemo", context.InboundTag);
        Assert.Equal(9, context.InboundUserLevel);
        Assert.Equal(RoutingNetworks.Udp, context.InboundSourceNetwork);
        Assert.Equal("203.0.113.7", context.OriginalDestinationHost);
        Assert.Equal(5353, context.OriginalDestinationPort);
        Assert.Equal("203.0.113.7", context.InboundOriginalDestinationHost);
        Assert.Equal(5353, context.InboundOriginalDestinationPort);
        Assert.Equal(42, context.ConnectionIdleSeconds);
        Assert.Equal(7, context.UplinkOnlySeconds);
        Assert.Equal(8, context.DownlinkOnlySeconds);

        var destinations = Assert.Single(dispatcher.TransportDestinations);
        var destination = Assert.Single(destinations);
        Assert.Equal("203.0.113.7", destination.Host);
        Assert.Equal(5353, destination.Port);
        Assert.Equal(DispatchNetwork.Udp, destination.Network);

        var creation = Assert.Single(responseCapture.CreatedWriters);
        Assert.Equal("127.0.0.1", creation.ListenerLocalEndPoint.Address.ToString());
        Assert.Equal(port, creation.ListenerLocalEndPoint.Port);
        Assert.Equal("203.0.113.7", creation.OriginalDestinationEndPoint.Address.ToString());
        Assert.Equal(5353, creation.OriginalDestinationEndPoint.Port);
        Assert.Equal(77, creation.Mark);

        var datagram = Assert.Single(responseCapture.Datagrams);
        Assert.Equal("203.0.113.7", datagram.SourceHost);
        Assert.Equal(5353, datagram.SourcePort);
        Assert.Equal("redirect", Encoding.ASCII.GetString(datagram.Payload));

        cts.Cancel();
        await serverTask;
    }

    [Fact]
    public async Task DefaultDokodemoUdpResponseWriter_invalidates_failed_cached_socket_and_recreates_it()
    {
        using var listenerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        listenerSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var listenerLocalEndPoint = (IPEndPoint)listenerSocket.LocalEndPoint!;

        using var remoteSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        remoteSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var remoteEndPoint = (IPEndPoint)remoteSocket.LocalEndPoint!;

        var alternatePort = AllocateUdpPort();
        await using var writer = new DefaultDokodemoUdpResponseWriter(
            listenerSocket,
            listenerLocalEndPoint,
            remoteEndPoint,
            listenerLocalEndPoint,
            mark: 0);

        await writer.SendAsync(
            new DispatchDatagram
            {
                SourceHost = IPAddress.Loopback.ToString(),
                SourcePort = alternatePort,
                Payload = Encoding.ASCII.GetBytes("first")
            },
            CancellationToken.None);

        var firstReceived = await ReceiveStringAsync(remoteSocket, CancellationToken.None);
        Assert.Equal("first", firstReceived);

        var cachedSocket = GetCachedSocket(writer, new IPEndPoint(IPAddress.Loopback, alternatePort));
        Assert.NotNull(cachedSocket);
        cachedSocket!.Dispose();

        await writer.SendAsync(
            new DispatchDatagram
            {
                SourceHost = IPAddress.Loopback.ToString(),
                SourcePort = alternatePort,
                Payload = Encoding.ASCII.GetBytes("second")
            },
            CancellationToken.None);

        var replacementSocket = GetCachedSocket(writer, new IPEndPoint(IPAddress.Loopback, alternatePort));
        Assert.Null(replacementSocket);

        await writer.SendAsync(
            new DispatchDatagram
            {
                SourceHost = IPAddress.Loopback.ToString(),
                SourcePort = alternatePort,
                Payload = Encoding.ASCII.GetBytes("third")
            },
            CancellationToken.None);

        var thirdReceived = await ReceiveStringAsync(remoteSocket, CancellationToken.None);
        Assert.Equal("third", thirdReceived);

        replacementSocket = GetCachedSocket(writer, new IPEndPoint(IPAddress.Loopback, alternatePort));
        Assert.NotNull(replacementSocket);
        Assert.False(ReferenceEquals(cachedSocket, replacementSocket));
    }

    private static async Task<string> SendAndReceiveAsync(
        Socket clientSocket,
        EndPoint serverEndPoint,
        string payload,
        CancellationToken cancellationToken)
    {
        var buffer = Encoding.ASCII.GetBytes(payload);
        await clientSocket.SendToAsync(buffer, SocketFlags.None, serverEndPoint, cancellationToken);

        var receiveBuffer = new byte[65535];
        var received = await clientSocket.ReceiveFromAsync(
            receiveBuffer.AsMemory(0, receiveBuffer.Length),
            SocketFlags.None,
            new IPEndPoint(IPAddress.Any, 0),
            cancellationToken);
        return Encoding.ASCII.GetString(receiveBuffer, 0, received.ReceivedBytes);
    }

    private static async Task<string> ReceiveStringAsync(Socket socket, CancellationToken cancellationToken)
    {
        var receiveBuffer = new byte[65535];
        var received = await socket.ReceiveFromAsync(
            receiveBuffer.AsMemory(0, receiveBuffer.Length),
            SocketFlags.None,
            new IPEndPoint(IPAddress.Any, 0),
            cancellationToken);
        return Encoding.ASCII.GetString(receiveBuffer, 0, received.ReceivedBytes);
    }

    private static int AllocateUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static Socket? GetCachedSocket(DefaultDokodemoUdpResponseWriter writer, IPEndPoint localEndPoint)
    {
        var field = typeof(DefaultDokodemoUdpResponseWriter)
            .GetField("_sockets", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);

        var dictionary = field!.GetValue(writer) as IReadOnlyDictionary<string, Socket>;
        Assert.NotNull(dictionary);

        return dictionary!.TryGetValue(localEndPoint.Address + ":" + localEndPoint.Port.ToString(), out var socket)
            ? socket
            : null;
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

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
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

    private sealed class TestDokodemoUdpRedirectSupport : IDokodemoUdpRedirectSupport
    {
        private readonly IPEndPoint _originalDestinationEndPoint;
        private readonly RedirectResponseCapture _capture;

        public TestDokodemoUdpRedirectSupport(
            IPEndPoint originalDestinationEndPoint,
            RedirectResponseCapture capture)
        {
            _originalDestinationEndPoint = Normalize(originalDestinationEndPoint);
            _capture = capture;
        }

        public void ConfigureListener(Socket socket)
        {
        }

        public async ValueTask<DokodemoUdpReceiveResult> ReceiveAsync(
            Socket socket,
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            var received = await socket.ReceiveFromAsync(
                buffer,
                SocketFlags.None,
                CreateReceivePlaceholder(socket.AddressFamily),
                cancellationToken);
            if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint)
            {
                throw new InvalidOperationException("Dokodemo-door UDP inbound requires an IP remote endpoint.");
            }

            return new DokodemoUdpReceiveResult(
                received.ReceivedBytes,
                Normalize(remoteEndPoint),
                _originalDestinationEndPoint,
                _originalDestinationEndPoint);
        }

        public IDokodemoUdpResponseWriter CreateResponseWriter(
            Socket listenerSocket,
            IPEndPoint listenerLocalEndPoint,
            IPEndPoint remoteEndPoint,
            IPEndPoint originalDestinationEndPoint,
            int mark)
        {
            _capture.RecordCreation(
                Normalize(listenerLocalEndPoint),
                Normalize(remoteEndPoint),
                Normalize(originalDestinationEndPoint),
                mark);
            return new TestDokodemoUdpResponseWriter(listenerSocket, Normalize(remoteEndPoint), _capture);
        }

        private static EndPoint CreateReceivePlaceholder(AddressFamily addressFamily)
            => addressFamily == AddressFamily.InterNetworkV6
                ? new IPEndPoint(IPAddress.IPv6Any, 0)
                : new IPEndPoint(IPAddress.Any, 0);

        private static IPEndPoint Normalize(IPEndPoint endPoint)
            => new(Normalize(endPoint.Address), endPoint.Port);

        private static IPAddress Normalize(IPAddress address)
            => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    private sealed class TestDokodemoUdpResponseWriter : IDokodemoUdpResponseWriter
    {
        private readonly Socket _listenerSocket;
        private readonly IPEndPoint _remoteEndPoint;
        private readonly RedirectResponseCapture _capture;

        public TestDokodemoUdpResponseWriter(
            Socket listenerSocket,
            IPEndPoint remoteEndPoint,
            RedirectResponseCapture capture)
        {
            _listenerSocket = listenerSocket;
            _remoteEndPoint = remoteEndPoint;
            _capture = capture;
        }

        public async ValueTask SendAsync(DispatchDatagram datagram, CancellationToken cancellationToken)
        {
            _capture.RecordDatagram(datagram);
            await _listenerSocket.SendToAsync(
                datagram.Payload,
                SocketFlags.None,
                _remoteEndPoint,
                cancellationToken);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RedirectResponseCapture
    {
        private readonly Lock _sync = new();
        private readonly List<RedirectWriterCreation> _createdWriters = [];
        private readonly List<DispatchDatagram> _datagrams = [];

        public IReadOnlyList<RedirectWriterCreation> CreatedWriters
        {
            get
            {
                lock (_sync)
                {
                    return _createdWriters.ToArray();
                }
            }
        }

        public IReadOnlyList<DispatchDatagram> Datagrams
        {
            get
            {
                lock (_sync)
                {
                    return _datagrams.ToArray();
                }
            }
        }

        public void RecordCreation(
            IPEndPoint listenerLocalEndPoint,
            IPEndPoint remoteEndPoint,
            IPEndPoint originalDestinationEndPoint,
            int mark)
        {
            lock (_sync)
            {
                _createdWriters.Add(
                    new RedirectWriterCreation(
                        listenerLocalEndPoint,
                        remoteEndPoint,
                        originalDestinationEndPoint,
                        mark));
            }
        }

        public void RecordDatagram(DispatchDatagram datagram)
        {
            ArgumentNullException.ThrowIfNull(datagram);

            lock (_sync)
            {
                _datagrams.Add(
                    new DispatchDatagram
                    {
                        SourceHost = datagram.SourceHost,
                        SourcePort = datagram.SourcePort,
                        Payload = datagram.Payload.ToArray()
                    });
            }
        }
    }

    private sealed record RedirectWriterCreation(
        IPEndPoint ListenerLocalEndPoint,
        IPEndPoint RemoteEndPoint,
        IPEndPoint OriginalDestinationEndPoint,
        int Mark);
}

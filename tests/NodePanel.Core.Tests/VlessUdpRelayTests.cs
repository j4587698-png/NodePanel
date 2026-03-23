using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessUdpRelayTests
{
    [Fact]
    public async Task RelayAsync_writes_response_header_and_relays_packets()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relay = new VlessUdpRelay(
            CreateDispatcher(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            new VlessUdpPacketReader(),
            new VlessUdpPacketWriter());
        var user = new VlessUser
        {
            UserId = "demo-user",
            Uuid = Guid.NewGuid().ToString("D"),
            BytesPerSecond = 0
        };

        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;
        var serverTask = RunUdpEchoServerAsync(udpSocket, cts.Token);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var request = new VlessRequest
        {
            Version = 0,
            UserUuid = user.Uuid,
            Command = VlessCommand.Udp,
            TargetHost = "127.0.0.1",
            TargetPort = udpPort
        };

        var relayTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var acceptedStream = accepted.GetStream();
            await relay.RelayAsync(
                acceptedStream,
                request,
                user,
                new VlessInboundSessionOptions(),
                cts.Token);
        }, cts.Token);

        using var client = new TcpClient
        {
            NoDelay = true
        };
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();

        var responseHeader = new byte[2];
        await stream.ReadExactlyAsync(responseHeader, cts.Token);
        Assert.Equal([0x00, 0x00], responseHeader);

        var packetWriter = new VlessUdpPacketWriter();
        var packetReader = new VlessUdpPacketReader();
        await packetWriter.WriteAsync(stream, Encoding.ASCII.GetBytes("ping"), cts.Token);
        await stream.FlushAsync(cts.Token);

        var response = await packetReader.ReadAsync(stream, cts.Token);
        Assert.NotNull(response);
        Assert.Equal("ping", Encoding.ASCII.GetString(response!));

        stream.Close();
        client.Close();

        await relayTask;
        await serverTask;
    }

    [Fact]
    public async Task RelayAsync_closes_idle_association_after_connection_idle_timeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relay = new VlessUdpRelay(
            CreateDispatcher(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            new VlessUdpPacketReader(),
            new VlessUdpPacketWriter());
        var user = new VlessUser
        {
            UserId = "demo-user",
            Uuid = Guid.NewGuid().ToString("D"),
            BytesPerSecond = 0
        };

        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;
        var serverTask = RunUdpEchoServerAsync(udpSocket, cts.Token);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var request = new VlessRequest
        {
            Version = 0,
            UserUuid = user.Uuid,
            Command = VlessCommand.Udp,
            TargetHost = "127.0.0.1",
            TargetPort = udpPort
        };

        var relayTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var acceptedStream = accepted.GetStream();
            await relay.RelayAsync(
                acceptedStream,
                request,
                user,
                new VlessInboundSessionOptions
                {
                    ConnectionIdleSeconds = 1
                },
                cts.Token);
        }, cts.Token);

        using var client = new TcpClient
        {
            NoDelay = true
        };
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();

        var responseHeader = new byte[2];
        await stream.ReadExactlyAsync(responseHeader, cts.Token);
        Assert.Equal([0x00, 0x00], responseHeader);

        var packetWriter = new VlessUdpPacketWriter();
        var packetReader = new VlessUdpPacketReader();
        await packetWriter.WriteAsync(stream, Encoding.ASCII.GetBytes("idle"), cts.Token);
        await stream.FlushAsync(cts.Token);

        var response = await packetReader.ReadAsync(stream, cts.Token);
        Assert.NotNull(response);
        Assert.Equal("idle", Encoding.ASCII.GetString(response!));

        var stopwatch = Stopwatch.StartNew();
        await relayTask;
        stopwatch.Stop();

        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(4));
        var eofBuffer = new byte[1];
        var eofRead = await stream.ReadAsync(eofBuffer.AsMemory(0, 1), cts.Token);
        Assert.Equal(0, eofRead);

        await serverTask;
    }

    private static async Task RunUdpEchoServerAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
        var received = await socket.ReceiveFromAsync(buffer.AsMemory(0, buffer.Length), SocketFlags.None, remoteEndPoint, cancellationToken);
        await socket.SendToAsync(
            buffer.AsMemory(0, received.ReceivedBytes),
            SocketFlags.None,
            received.RemoteEndPoint,
            cancellationToken);
    }

    private static IDispatcher CreateDispatcher()
        => new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler()
                },
                new StaticOutboundRuntimePlanProvider(
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
                    })));

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }
}

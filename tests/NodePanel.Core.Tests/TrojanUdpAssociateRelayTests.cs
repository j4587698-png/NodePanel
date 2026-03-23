using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanUdpAssociateRelayTests
{
    [Fact]
    public async Task RelayAsync_uses_distinct_udp_source_ports_when_cone_is_disabled()
    {
        var result = await RunScenarioAsync(useCone: false);

        Assert.Equal("one", result.FirstResponsePayload);
        Assert.Equal("two", result.SecondResponsePayload);
        Assert.NotEqual(result.FirstServerRemotePort, result.SecondServerRemotePort);
    }

    [Fact]
    public async Task RelayAsync_reuses_udp_source_port_when_cone_is_enabled()
    {
        var result = await RunScenarioAsync(useCone: true);

        Assert.Equal("one", result.FirstResponsePayload);
        Assert.Equal("two", result.SecondResponsePayload);
        Assert.Equal(result.FirstServerRemotePort, result.SecondServerRemotePort);
    }

    [Fact]
    public async Task RelayAsync_closes_idle_association_after_connection_idle_timeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relay = new TrojanUdpAssociateRelay(
            CreateDispatcher(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            new TrojanUdpPacketReader(),
            new TrojanUdpPacketWriter());
        var user = new TrojanUser
        {
            UserId = "demo-user",
            PasswordHash = "demo-hash",
            BytesPerSecond = 0
        };

        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;
        var serverTask = RunUdpEchoServerAsync(udpSocket, cts.Token);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var relayTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var acceptedStream = accepted.GetStream();
            await relay.RelayAsync(
                acceptedStream,
                user,
                new TestTrojanConnectionOptions
                {
                    UseCone = true,
                    ConnectionIdleSeconds = 1
                },
                cts.Token).ConfigureAwait(false);
        }, cts.Token);

        using var client = new TcpClient
        {
            NoDelay = true
        };
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token).ConfigureAwait(false);
        await using var stream = client.GetStream();

        var packetWriter = new TrojanUdpPacketWriter();
        var packetReader = new TrojanUdpPacketReader();
        await packetWriter.WriteAsync(
            stream,
            new TrojanUdpPacket
            {
                DestinationHost = "127.0.0.1",
                DestinationPort = udpPort,
                Payload = Encoding.ASCII.GetBytes("idle")
            },
            cts.Token).ConfigureAwait(false);
        await stream.FlushAsync(cts.Token).ConfigureAwait(false);

        var response = await packetReader.ReadAsync(stream, cts.Token).ConfigureAwait(false);
        Assert.NotNull(response);
        Assert.Equal("idle", Encoding.ASCII.GetString(response!.Payload));

        var stopwatch = Stopwatch.StartNew();
        await relayTask.ConfigureAwait(false);
        stopwatch.Stop();

        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(4));
        var eofBuffer = new byte[1];
        var eofRead = await stream.ReadAsync(eofBuffer.AsMemory(0, 1), cts.Token).ConfigureAwait(false);
        Assert.Equal(0, eofRead);

        await serverTask.ConfigureAwait(false);
    }

    private static async Task<UdpAssociateScenarioResult> RunScenarioAsync(bool useCone)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relay = new TrojanUdpAssociateRelay(
            CreateDispatcher(),
            new RateLimiterRegistry(),
            new TrafficRegistry(),
            new TrojanUdpPacketReader(),
            new TrojanUdpPacketWriter());
        var user = new TrojanUser
        {
            UserId = "demo-user",
            PasswordHash = "demo-hash",
            BytesPerSecond = 0
        };

        using var udpSocket1 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket1.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort1 = ((IPEndPoint)udpSocket1.LocalEndPoint!).Port;

        using var udpSocket2 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket2.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpPort2 = ((IPEndPoint)udpSocket2.LocalEndPoint!).Port;

        var server1Task = RunUdpEchoServerAsync(udpSocket1, cts.Token);
        var server2Task = RunUdpEchoServerAsync(udpSocket2, cts.Token);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var relayTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var acceptedStream = accepted.GetStream();
            await relay.RelayAsync(
                acceptedStream,
                user,
                new TestTrojanConnectionOptions
                {
                    UseCone = useCone
                },
                cts.Token).ConfigureAwait(false);
        }, cts.Token);

        using var client = new TcpClient
        {
            NoDelay = true
        };
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token).ConfigureAwait(false);
        await using var stream = client.GetStream();

        var packetWriter = new TrojanUdpPacketWriter();
        var packetReader = new TrojanUdpPacketReader();

        await packetWriter.WriteAsync(
            stream,
            new TrojanUdpPacket
            {
                DestinationHost = "127.0.0.1",
                DestinationPort = udpPort1,
                Payload = Encoding.ASCII.GetBytes("one")
            },
            cts.Token).ConfigureAwait(false);
        await stream.FlushAsync(cts.Token).ConfigureAwait(false);

        var firstResponse = await packetReader.ReadAsync(stream, cts.Token).ConfigureAwait(false);

        await packetWriter.WriteAsync(
            stream,
            new TrojanUdpPacket
            {
                DestinationHost = "127.0.0.1",
                DestinationPort = udpPort2,
                Payload = Encoding.ASCII.GetBytes("two")
            },
            cts.Token).ConfigureAwait(false);
        await stream.FlushAsync(cts.Token).ConfigureAwait(false);

        var secondResponse = await packetReader.ReadAsync(stream, cts.Token).ConfigureAwait(false);

        stream.Close();
        client.Close();

        await relayTask.ConfigureAwait(false);
        var server1 = await server1Task.ConfigureAwait(false);
        var server2 = await server2Task.ConfigureAwait(false);

        Assert.NotNull(firstResponse);
        Assert.NotNull(secondResponse);

        return new UdpAssociateScenarioResult(
            Encoding.ASCII.GetString(firstResponse!.Payload),
            Encoding.ASCII.GetString(secondResponse!.Payload),
            server1.RemotePort,
            server2.RemotePort);
    }

    private static async Task<UdpEchoObservation> RunUdpEchoServerAsync(Socket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
        var received = await socket.ReceiveFromAsync(buffer.AsMemory(0, buffer.Length), SocketFlags.None, remoteEndPoint, cancellationToken).ConfigureAwait(false);
        await socket.SendToAsync(
            buffer.AsMemory(0, received.ReceivedBytes),
            SocketFlags.None,
            received.RemoteEndPoint,
            cancellationToken).ConfigureAwait(false);

        var remote = (IPEndPoint)received.RemoteEndPoint;
        return new UdpEchoObservation(remote.Port);
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

    private sealed record UdpAssociateScenarioResult(
        string FirstResponsePayload,
        string SecondResponsePayload,
        int FirstServerRemotePort,
        int SecondServerRemotePort);

    private sealed record UdpEchoObservation(int RemotePort);

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

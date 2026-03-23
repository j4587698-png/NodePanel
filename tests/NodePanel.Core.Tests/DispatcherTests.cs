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
            using var client = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();
            var request = new byte[4];
            await stream.ReadExactlyAsync(request.AsMemory(0, request.Length), cts.Token).ConfigureAwait(false);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token).ConfigureAwait(false);
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
            cts.Token).ConfigureAwait(false);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token).ConfigureAwait(false);
        await outbound.FlushAsync(cts.Token).ConfigureAwait(false);
        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token).ConfigureAwait(false);

        Assert.Equal("ping", await serverTask.ConfigureAwait(false));
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
                cts.Token).ConfigureAwait(false);

            await udpSocket.SendToAsync(
                buffer.AsMemory(0, received.ReceivedBytes),
                SocketFlags.None,
                received.RemoteEndPoint,
                cts.Token).ConfigureAwait(false);
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = "test",
                UserId = "test-user",
                UseCone = true
            },
            cts.Token).ConfigureAwait(false);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = port,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("udp"),
            cts.Token).ConfigureAwait(false);

        var datagram = await transport.ReceiveAsync(cts.Token).ConfigureAwait(false);
        await serverTask.ConfigureAwait(false);

        Assert.NotNull(datagram);
        Assert.Equal("udp", Encoding.ASCII.GetString(datagram!.Payload));
        Assert.Equal(port, datagram.SourcePort);
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

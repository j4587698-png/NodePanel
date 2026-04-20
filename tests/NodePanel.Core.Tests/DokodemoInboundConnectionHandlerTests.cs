using System.Net;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class DokodemoInboundConnectionHandlerTests
{
    [Fact]
    public async Task HandleAsync_populates_http_sniffing_content_in_dispatch_context()
    {
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var handler = new DokodemoInboundConnectionHandler(
            dispatcher,
            new RelayService());
        var payload = Encoding.ASCII.GetBytes("GET /dokodemo HTTP/1.1\r\nHost: edge.example.com\r\nX-Test: value\r\n\r\n");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new DokodemoInboundSessionOptions
            {
                InboundTag = "dokodemo",
                UserLevel = 5,
                Network = RoutingNetworks.Tcp,
                DestinationHost = "198.51.100.10",
                DestinationPort = 80,
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 18080),
                Sniffing = new RuntimeSniffingOptions
                {
                    Enabled = true,
                    DestinationOverride = [RoutingProtocols.Http]
                }
            },
            cts.Token);

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var destination = await dispatcher.DispatchDestination.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(InboundProtocols.DokodemoDoor, context.InboundProtocol);
        Assert.Equal("dokodemo", context.InboundTag);
        Assert.Equal(5, context.InboundUserLevel);
        Assert.Equal(RoutingProtocols.Http, context.DetectedProtocol);
        Assert.Equal("edge.example.com", context.DetectedDomain);
        Assert.Equal(RoutingProtocols.Http, context.Content.Protocol);
        Assert.True(context.Content.Attributes.TryGetValue(":method", out var method));
        Assert.Equal("GET", method);
        Assert.True(context.Content.Attributes.TryGetValue(":path", out var path));
        Assert.Equal("/dokodemo", path);
        Assert.True(context.Content.Attributes.TryGetValue("host", out var host));
        Assert.Equal("edge.example.com", host);
        Assert.True(context.Content.Attributes.TryGetValue("x-test", out var testHeader));
        Assert.Equal("value", testHeader);
        Assert.Equal("edge.example.com", destination.Host);
        Assert.Equal(80, destination.Port);

        cts.Cancel();
        await task;
    }
}

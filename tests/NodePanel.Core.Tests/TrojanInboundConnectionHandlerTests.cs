using System.Net;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanInboundConnectionHandlerTests
{
    [Fact]
    public async Task HandleAsync_rejects_new_ip_when_device_limit_is_reached()
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var handler = new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new TrojanUdpPacketReader(),
                new TrojanUdpPacketWriter()),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            sessionRegistry,
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);

        var payload = new TrojanHandshakeWriter().Build("demo-password", TrojanCommand.Connect, "example.com", 443);
        var usersByHash = TestTrojanConnectionOptions.CreateUsersWithDeviceLimit(("user-a", "demo-password", 0, 1));

        using var firstConnectionCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var firstTask = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                UsersByHash = usersByHash
            },
            firstConnectionCts.Token);

        await dispatcher.DispatchCalled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, sessionRegistry.ActiveSessions);

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => handler.HandleAsync(
            new MemoryStream(payload, writable: false),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.11"), 50002),
                UsersByHash = usersByHash
            },
            CancellationToken.None));

        Assert.Contains("device limit", exception.Message, StringComparison.OrdinalIgnoreCase);

        firstConnectionCts.Cancel();
        await firstTask;

        Assert.Equal(0, sessionRegistry.ActiveSessions);
    }

    [Fact]
    public async Task HandleAsync_populates_http_sniffing_content_in_dispatch_context()
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var handler = new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new TrojanUdpPacketReader(),
                new TrojanUdpPacketWriter()),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            sessionRegistry,
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);

        var handshake = new TrojanHandshakeWriter().Build("demo-password", TrojanCommand.Connect, "198.51.100.10", 80);
        var sniffPayload = Encoding.ASCII.GetBytes("GET /api?query=1 HTTP/1.1\r\nHost: edge.example.com\r\nX-Test: value\r\n\r\n");
        var payload = new byte[handshake.Length + sniffPayload.Length];
        handshake.CopyTo(payload, 0);
        sniffPayload.CopyTo(payload, handshake.Length);
        var usersByHash = TestTrojanConnectionOptions.CreateUsers(("user-a", "demo-password", 0));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                UsersByHash = usersByHash,
                Sniffing = new RuntimeSniffingOptions
                {
                    Enabled = true,
                    DestinationOverride = [RoutingProtocols.Http]
                }
            },
            cts.Token);

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var destination = await dispatcher.DispatchDestination.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("user-a", context.UserId);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Trojan, string.Empty, "user-a"), context.ScopedUserId);
        Assert.Equal(RoutingProtocols.Http, context.DetectedProtocol);
        Assert.Equal("edge.example.com", context.DetectedDomain);
        Assert.Equal(RoutingProtocols.Http, context.Content.Protocol);
        Assert.True(context.Content.Attributes.TryGetValue(":method", out var method));
        Assert.Equal("GET", method);
        Assert.True(context.Content.Attributes.TryGetValue(":path", out var path));
        Assert.Equal("/api?query=1", path);
        Assert.True(context.Content.Attributes.TryGetValue("host", out var host));
        Assert.Equal("edge.example.com", host);
        Assert.True(context.Content.Attributes.TryGetValue("x-test", out var testHeader));
        Assert.Equal("value", testHeader);
        Assert.Equal("edge.example.com", destination.Host);
        Assert.Equal(80, destination.Port);

        cts.Cancel();
        await task;
    }

    [Fact]
    public async Task HandleAsync_keeps_original_destination_and_sets_route_target_when_sniffing_is_route_only()
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var handler = new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new TrojanUdpPacketReader(),
                new TrojanUdpPacketWriter()),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            sessionRegistry,
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);

        var handshake = new TrojanHandshakeWriter().Build("demo-password", TrojanCommand.Connect, "198.51.100.10", 80);
        var sniffPayload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: route.example.com\r\n\r\n");
        var payload = new byte[handshake.Length + sniffPayload.Length];
        handshake.CopyTo(payload, 0);
        sniffPayload.CopyTo(payload, handshake.Length);
        var usersByHash = TestTrojanConnectionOptions.CreateUsers(("user-a", "demo-password", 0));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                UsersByHash = usersByHash,
                Sniffing = new RuntimeSniffingOptions
                {
                    Enabled = true,
                    RouteOnly = true,
                    DestinationOverride = [RoutingProtocols.Http]
                }
            },
            cts.Token);

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var destination = await dispatcher.DispatchDestination.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(RoutingProtocols.Http, context.DetectedProtocol);
        Assert.Equal("route.example.com", context.DetectedDomain);
        Assert.Equal("198.51.100.10", context.TargetHost);
        Assert.Equal(80, context.TargetPort);
        Assert.Equal("route.example.com", context.RouteTargetHost);
        Assert.Equal(80, context.RouteTargetPort);
        Assert.Equal("198.51.100.10", destination.Host);
        Assert.Equal(80, destination.Port);

        cts.Cancel();
        await task;
    }

    [Fact]
    public async Task HandleAsync_sniffs_fragmented_http_host_across_multiple_reads()
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var handler = new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new TrojanUdpPacketReader(),
                new TrojanUdpPacketWriter()),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            sessionRegistry,
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);

        var handshake = new TrojanHandshakeWriter().Build("demo-password", TrojanCommand.Connect, "198.51.100.10", 80);
        var firstSniffChunk = Encoding.ASCII.GetBytes("GET /api?query=1 HTTP/1.1\r\nHo");
        var secondSniffChunk = Encoding.ASCII.GetBytes("st: edge.example.com\r\nX-Test: value\r\n\r\n");
        var sniffPayload = firstSniffChunk.Concat(secondSniffChunk).ToArray();
        var firstSegment = new byte[handshake.Length + firstSniffChunk.Length];
        handshake.CopyTo(firstSegment, 0);
        firstSniffChunk.CopyTo(firstSegment, handshake.Length);
        var usersByHash = TestTrojanConnectionOptions.CreateUsers(("user-a", "demo-password", 0));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new SegmentedPayloadThenPendingStream(firstSegment, secondSniffChunk),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                UsersByHash = usersByHash,
                Sniffing = new RuntimeSniffingOptions
                {
                    Enabled = true,
                    DestinationOverride = [RoutingProtocols.Http]
                }
            },
            cts.Token);

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var destination = await dispatcher.DispatchDestination.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(RoutingProtocols.Http, context.DetectedProtocol);
        Assert.Equal("edge.example.com", context.DetectedDomain);
        Assert.Equal(sniffPayload, context.InitialPayload);
        Assert.Equal("edge.example.com", destination.Host);
        Assert.Equal(80, destination.Port);

        cts.Cancel();
        await task;
    }

    [Fact]
    public async Task HandleAsync_uses_fake_dns_metadata_to_override_fake_ip_destination()
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        var fakeDnsEngine = new FakeDnsEngine(
        [
            new FakeDnsPoolRuntime
            {
                IpPool = FakeDnsDefaults.IPv4Pool,
                LruSize = 256
            }
        ]);
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.example.com", ipv4: true, ipv6: false));
        var handler = new TrojanInboundConnectionHandler(
            dispatcher,
            new TrojanHandshakeReader(),
            new TrojanUdpAssociateRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new TrojanUdpPacketReader(),
                new TrojanUdpPacketWriter(),
                fakeDnsEngine),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new TrojanFallbackRelayService(new RelayService()),
            sessionRegistry,
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry,
            fakeDnsEngine);

        var payload = new TrojanHandshakeWriter().Build("demo-password", TrojanCommand.Connect, fakeAddress.ToString(), 443);
        var usersByHash = TestTrojanConnectionOptions.CreateUsers(("user-a", "demo-password", 0));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new TestTrojanConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                UsersByHash = usersByHash,
                Sniffing = new RuntimeSniffingOptions
                {
                    Enabled = true,
                    MetadataOnly = true,
                    DestinationOverride = [RoutingProtocols.FakeDns]
                }
            },
            cts.Token);

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var destination = await dispatcher.DispatchDestination.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(RoutingProtocols.FakeDns, context.DetectedProtocol);
        Assert.Equal("mapped.example.com", context.DetectedDomain);
        Assert.Equal("mapped.example.com", destination.Host);
        Assert.Equal(443, destination.Port);

        cts.Cancel();
        await task;
    }
}

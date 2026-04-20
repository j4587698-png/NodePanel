using System.Net;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ShadowsocksInboundConnectionHandlerTests
{
    [Theory]
    [InlineData(ShadowsocksCipherTypes.Aes128Gcm, "demo-secret")]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305, "demo-secret-x")]
    public async Task HandleAsync_rejects_new_ip_when_device_limit_is_reached(string cipher, string password)
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var handler = new ShadowsocksInboundConnectionHandler(
            dispatcher,
            sessionRegistry,
            new RelayService(),
            new RateLimiterRegistry(),
            new TrafficRegistry());

        var user = CreateUser("ss-entry", "user-a", cipher, password, deviceLimit: 1);
        var payload = await CreateTcpClientPayloadAsync(
            cipher,
            password,
            "example.com",
            443,
            Encoding.ASCII.GetBytes("hello-ss-connect"));

        using var firstConnectionCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var firstTask = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            CreateOptions(
                user,
                new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001)),
            firstConnectionCts.Token);

        var firstCompletion = await Task.WhenAny(
            firstTask,
            dispatcher.DispatchCalled.Task).WaitAsync(TimeSpan.FromSeconds(5));
        if (ReferenceEquals(firstCompletion, firstTask))
        {
            await firstTask;
        }

        Assert.Equal(1, sessionRegistry.ActiveSessions);

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => handler.HandleAsync(
            new MemoryStream(payload, writable: false),
            CreateOptions(
                user,
                new IPEndPoint(IPAddress.Parse("203.0.113.11"), 50002)),
            CancellationToken.None));

        Assert.Contains("device limit", exception.Message, StringComparison.OrdinalIgnoreCase);

        firstConnectionCts.Cancel();
        try
        {
            await firstTask;
        }
        catch (OperationCanceledException)
        {
        }

        Assert.Equal(0, sessionRegistry.ActiveSessions);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Aes128Gcm, "demo-secret")]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305, "demo-secret-x")]
    public async Task HandleAsync_populates_http_sniffing_content_in_dispatch_context(string cipher, string password)
    {
        var sessionRegistry = new SessionRegistry();
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var handler = new ShadowsocksInboundConnectionHandler(
            dispatcher,
            sessionRegistry,
            new RelayService(),
            new RateLimiterRegistry(),
            new TrafficRegistry());

        var user = CreateUser("ss-entry", "user-a", cipher, password);
        var sniffPayload = Encoding.ASCII.GetBytes(
            "GET /api?query=1 HTTP/1.1\r\nHost: edge.example.com\r\nX-Test: value\r\n\r\n");
        var payload = await CreateTcpClientPayloadAsync(
            cipher,
            password,
            "198.51.100.10",
            80,
            sniffPayload);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            CreateOptions(
                user,
                new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
                new RuntimeSniffingOptions
                {
                    Enabled = true,
                    DestinationOverride = [RoutingProtocols.Http]
                }),
            cts.Token);

        var firstCompletion = await Task.WhenAny(
            task,
            dispatcher.DispatchContext.Task).WaitAsync(TimeSpan.FromSeconds(5));
        if (ReferenceEquals(firstCompletion, task))
        {
            await task;
        }

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var destination = await dispatcher.DispatchDestination.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("user-a", context.UserId);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-entry", "user-a"), context.ScopedUserId);
        Assert.Equal(RoutingNetworks.Tcp, context.InboundSourceNetwork);
        Assert.Equal("198.51.100.10", context.OriginalDestinationHost);
        Assert.Equal(80, context.OriginalDestinationPort);
        Assert.Equal(RoutingProtocols.Http, context.DetectedProtocol);
        Assert.Equal("edge.example.com", context.DetectedDomain);
        Assert.Equal(sniffPayload, context.InitialPayload);
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
        Assert.Equal(DispatchNetwork.Tcp, destination.Network);

        cts.Cancel();
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static ShadowsocksUser CreateUser(
        string inboundTag,
        string userId,
        string cipher,
        string password,
        int deviceLimit = 0)
        => new()
        {
            UserId = userId,
            Cipher = cipher,
            Password = password,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, inboundTag, userId),
            BytesPerSecond = 0,
            DeviceLimit = deviceLimit
        };

    private static ShadowsocksInboundSessionOptions CreateOptions(
        ShadowsocksUser user,
        EndPoint remoteEndPoint,
        IRuntimeSniffingDefinition? sniffing = null)
        => new()
        {
            RuntimeState = new ShadowsocksInboundRuntimeState([user]),
            InboundTag = "ss-entry",
            Network = RoutingNetworks.Tcp,
            RemoteEndPoint = remoteEndPoint,
            Sniffing = sniffing ?? RuntimeSniffingOptions.Disabled
        };

    private static async Task<byte[]> CreateTcpClientPayloadAsync(
        string cipher,
        string password,
        string host,
        int port,
        byte[] payload)
    {
        var account = ShadowsocksAccount.Create(cipher, password);
        await using var transport = new MemoryStream();
        await using var stream = await ShadowsocksProtocolCodec.OpenClientTcpStreamAsync(
            transport,
            account,
            host,
            port,
            CancellationToken.None);

        await stream.WriteAsync(payload, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
        return transport.ToArray();
    }
}

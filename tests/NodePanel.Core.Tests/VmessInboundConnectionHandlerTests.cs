using System.Net;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessInboundConnectionHandlerTests
{
    [Fact]
    public async Task HandleAsync_applies_user_level_policy_to_dispatch_context()
    {
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var handler = CreateHandler(dispatcher);
        var user = new VmessUser
        {
            UserId = "vmess-user",
            Uuid = "11111111-1111-1111-1111-111111111111",
            CmdKey = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray(),
            Level = 8,
            BytesPerSecond = 0
        };
        var request = CreateConnectRequest(user);
        var payload = VmessTestRequestEncoder.BuildRequestHeader(user, request);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new VmessInboundSessionOptions
            {
                InboundTag = "vmess-in",
                Users = [user],
                RuntimeState = new VmessInboundRuntimeState([user]),
                SessionPolicies = RuntimeSessionPolicyTestHelper.CreateCatalog(
                    level: 8,
                    connectionIdleSeconds: 45,
                    uplinkOnlySeconds: 6,
                    downlinkOnlySeconds: 7),
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001)
            },
            cts.Token);

        var firstCompletion = await Task.WhenAny(
            task,
            dispatcher.DispatchContext.Task).WaitAsync(TimeSpan.FromSeconds(5));
        if (ReferenceEquals(firstCompletion, task))
        {
            await task;
        }

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(8, context.InboundUserLevel);
        Assert.Equal(45, context.ConnectionIdleSeconds);
        Assert.Equal(6, context.UplinkOnlySeconds);
        Assert.Equal(7, context.DownlinkOnlySeconds);

        cts.Cancel();
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static VmessInboundConnectionHandler CreateHandler(IDispatcher dispatcher)
    {
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new VmessInboundConnectionHandler(
            dispatcher,
            new VmessHandshakeReader(),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new VmessUdpRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new SessionRegistry(),
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);
    }

    private static VmessRequest CreateConnectRequest(VmessUser user)
        => new()
        {
            Version = 1,
            User = user,
            RequestBodyKey = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray(),
            RequestBodyIv = Enumerable.Range(0x80, 16).Select(static value => (byte)value).ToArray(),
            ResponseHeader = 0x5A,
            Option = VmessRequestOptions.ChunkStream |
                     VmessRequestOptions.ChunkMasking |
                     VmessRequestOptions.GlobalPadding |
                     VmessRequestOptions.AuthenticatedLength,
            Security = VmessSecurityType.Aes128Gcm,
            Command = VmessCommand.Connect,
            TargetHost = "example.com",
            TargetPort = 443
        };
}

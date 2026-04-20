using System.Net;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class Shadowsocks2022InboundConnectionHandlerTests
{
    [Fact]
    public async Task HandleAsync_applies_user_level_policy_to_dispatch_context()
    {
        var dispatcher = new BlockingDispatcher(new PendingDuplexStream());
        var handler = new Shadowsocks2022InboundConnectionHandler(
            dispatcher,
            new SessionRegistry(),
            new RelayService(),
            new RateLimiterRegistry(),
            new TrafficRegistry());

        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var user = new Shadowsocks2022User
        {
            UserId = "ss-2022-user",
            Password = serverKey,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-in", "ss-2022-user"),
            Level = 9,
            BytesPerSecond = 0
        };
        var payload = await CreateTcpClientPayloadAsync(
            method,
            serverKey,
            "example.com",
            443,
            Encoding.ASCII.GetBytes("hello-ss-2022"));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var task = handler.HandleAsync(
            new PayloadThenPendingStream(payload),
            new Shadowsocks2022InboundSessionOptions
            {
                RuntimeState = new Shadowsocks2022InboundRuntimeState(
                    method,
                    serverKey,
                    Shadowsocks2022InboundModes.SingleUser,
                    [user]),
                SessionPolicies = RuntimeSessionPolicyTestHelper.CreateCatalog(
                    level: 9,
                    connectionIdleSeconds: 46,
                    uplinkOnlySeconds: 7,
                    downlinkOnlySeconds: 8),
                InboundTag = "ss-2022-in",
                Network = RoutingNetworks.Tcp,
                RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001)
            },
            cts.Token);

        var context = await dispatcher.DispatchContext.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(9, context.InboundUserLevel);
        Assert.Equal(46, context.ConnectionIdleSeconds);
        Assert.Equal(7, context.UplinkOnlySeconds);
        Assert.Equal(8, context.DownlinkOnlySeconds);

        cts.Cancel();
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static async Task<byte[]> CreateTcpClientPayloadAsync(
        string method,
        string key,
        string host,
        int port,
        byte[] payload)
    {
        var account = Shadowsocks2022Account.Create(method, key);
        await using var transport = new MemoryStream();
        await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
            transport,
            account,
            host,
            port,
            CancellationToken.None);

        await stream.WriteAsync(payload, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
        return transport.ToArray();
    }

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
}

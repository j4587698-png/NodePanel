using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RelayServiceTests
{
    [Fact]
    public async Task RelayAsync_preserves_downlink_after_client_half_close()
    {
        var result = await RunRelayScenarioAsync(trackTraffic: false, clientHalfClose: true);

        Assert.Equal("ping", result.RemoteRequest);
        Assert.Equal("pong", result.ClientResponse);
        Assert.Empty(result.TrafficSnapshots);
    }

    [Fact]
    public async Task RelayAsync_with_accounting_preserves_downlink_after_client_half_close()
    {
        var result = await RunRelayScenarioAsync(trackTraffic: true, clientHalfClose: true);

        Assert.Equal("ping", result.RemoteRequest);
        Assert.Equal("pong", result.ClientResponse);

        var snapshot = Assert.Single(result.TrafficSnapshots);
        Assert.Equal("demo-user", snapshot.UserId);
        Assert.Equal(4, snapshot.UploadBytes);
        Assert.Equal(4, snapshot.DownloadBytes);
    }

    [Fact]
    public async Task RelayAsync_completes_when_remote_finishes_first()
    {
        var result = await RunRelayScenarioAsync(trackTraffic: false, clientHalfClose: false);

        Assert.Equal("ping", result.RemoteRequest);
        Assert.Equal("pong", result.ClientResponse);
        Assert.Empty(result.TrafficSnapshots);
    }

    [Fact]
    public async Task RelayAsync_with_accounting_completes_when_remote_finishes_first()
    {
        var result = await RunRelayScenarioAsync(trackTraffic: true, clientHalfClose: false);

        Assert.Equal("ping", result.RemoteRequest);
        Assert.Equal("pong", result.ClientResponse);

        var snapshot = Assert.Single(result.TrafficSnapshots);
        Assert.Equal("demo-user", snapshot.UserId);
        Assert.Equal(4, snapshot.UploadBytes);
        Assert.Equal(4, snapshot.DownloadBytes);
    }

    [Fact]
    public async Task RelayAsync_cancels_idle_connection_after_connection_idle_timeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relayService = new RelayService();

        using var remoteListener = new TcpListener(IPAddress.Loopback, 0);
        remoteListener.Start();
        var remotePort = ((IPEndPoint)remoteListener.LocalEndpoint).Port;

        var remoteServerTask = Task.Run(async () =>
        {
            using var serverClient = await remoteListener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var serverStream = serverClient.GetStream();
            await ReadToEndAsync(serverStream, cts.Token).ConfigureAwait(false);
        }, cts.Token);

        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;

        var relayTask = Task.Run(async () =>
        {
            using var inboundClient = await frontListener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var inboundStream = inboundClient.GetStream();

            using var outboundClient = new TcpClient
            {
                NoDelay = true
            };

            await outboundClient.ConnectAsync(IPAddress.Loopback, remotePort, cts.Token).ConfigureAwait(false);
            await using var outboundStream = outboundClient.GetStream();
            await relayService.RelayAsync(
                inboundStream,
                outboundStream,
                new TestTrojanConnectionOptions
                {
                    ConnectionIdleSeconds = 1,
                    UplinkOnlySeconds = 1,
                    DownlinkOnlySeconds = 1
                },
                cts.Token).ConfigureAwait(false);
        }, cts.Token);

        using var frontClient = new TcpClient
        {
            NoDelay = true
        };
        await frontClient.ConnectAsync(IPAddress.Loopback, frontPort, cts.Token).ConfigureAwait(false);

        var stopwatch = Stopwatch.StartNew();
        await relayTask.ConfigureAwait(false);
        stopwatch.Stop();

        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(4));
        await remoteServerTask.ConfigureAwait(false);
    }

    [Fact]
    public async Task RelayAsync_honors_downlink_only_timeout_after_client_half_close()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relayService = new RelayService();
        var requestPayload = Encoding.ASCII.GetBytes("ping");

        using var remoteListener = new TcpListener(IPAddress.Loopback, 0);
        remoteListener.Start();
        var remotePort = ((IPEndPoint)remoteListener.LocalEndpoint).Port;

        var remoteServerTask = Task.Run(async () =>
        {
            using var serverClient = await remoteListener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var serverStream = serverClient.GetStream();

            var request = await ReadToEndAsync(serverStream, cts.Token).ConfigureAwait(false);
            await Task.Delay(TimeSpan.FromSeconds(3), cts.Token).ConfigureAwait(false);
            return Encoding.ASCII.GetString(request);
        }, cts.Token);

        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;

        var relayTask = Task.Run(async () =>
        {
            using var inboundClient = await frontListener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var inboundStream = inboundClient.GetStream();

            using var outboundClient = new TcpClient
            {
                NoDelay = true
            };

            await outboundClient.ConnectAsync(IPAddress.Loopback, remotePort, cts.Token).ConfigureAwait(false);
            await using var outboundStream = outboundClient.GetStream();
            await relayService.RelayAsync(
                inboundStream,
                outboundStream,
                new TestTrojanConnectionOptions
                {
                    ConnectionIdleSeconds = 30,
                    UplinkOnlySeconds = 1,
                    DownlinkOnlySeconds = 1
                },
                cts.Token).ConfigureAwait(false);
        }, cts.Token);

        using var frontClient = new TcpClient
        {
            NoDelay = true
        };
        await frontClient.ConnectAsync(IPAddress.Loopback, frontPort, cts.Token).ConfigureAwait(false);
        await using var frontStream = frontClient.GetStream();
        await frontStream.WriteAsync(requestPayload, cts.Token).ConfigureAwait(false);
        await frontStream.FlushAsync(cts.Token).ConfigureAwait(false);
        frontClient.Client.Shutdown(SocketShutdown.Send);

        var stopwatch = Stopwatch.StartNew();
        await relayTask.ConfigureAwait(false);
        stopwatch.Stop();

        Assert.Equal("ping", await remoteServerTask.ConfigureAwait(false));
        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2.5));
    }

    private static async Task<RelayScenarioResult> RunRelayScenarioAsync(bool trackTraffic, bool clientHalfClose)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var relayService = new RelayService();
        var trafficRegistry = new TrafficRegistry();
        var requestPayload = Encoding.ASCII.GetBytes("ping");
        var responsePayload = Encoding.ASCII.GetBytes("pong");

        using var remoteListener = new TcpListener(IPAddress.Loopback, 0);
        remoteListener.Start();
        var remotePort = ((IPEndPoint)remoteListener.LocalEndpoint).Port;

        var remoteServerTask = Task.Run(async () =>
        {
            using var serverClient = await remoteListener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var serverStream = serverClient.GetStream();

            byte[] request;
            if (clientHalfClose)
            {
                request = await ReadToEndAsync(serverStream, cts.Token).ConfigureAwait(false);
            }
            else
            {
                request = new byte[requestPayload.Length];
                await serverStream.ReadExactlyAsync(request.AsMemory(0, request.Length), cts.Token).ConfigureAwait(false);
            }

            await serverStream.WriteAsync(responsePayload, cts.Token).ConfigureAwait(false);
            await serverStream.FlushAsync(cts.Token).ConfigureAwait(false);
            return Encoding.ASCII.GetString(request);
        }, cts.Token);

        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;

        var relayTask = Task.Run(async () =>
        {
            using var inboundClient = await frontListener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var inboundStream = inboundClient.GetStream();

            using var outboundClient = new TcpClient
            {
                NoDelay = true
            };

            await outboundClient.ConnectAsync(IPAddress.Loopback, remotePort, cts.Token).ConfigureAwait(false);
            await using var outboundStream = outboundClient.GetStream();

            if (!trackTraffic)
            {
                await relayService.RelayAsync(inboundStream, outboundStream, cts.Token).ConfigureAwait(false);
                return;
            }

            var user = new TrojanUser
            {
                UserId = "demo-user",
                PasswordHash = "demo-hash",
                BytesPerSecond = 0
            };

            await relayService.RelayAsync(
                inboundStream,
                outboundStream,
                user,
                new ByteRateGate(0),
                new ByteRateGate(0),
                trafficRegistry,
                cts.Token).ConfigureAwait(false);
        }, cts.Token);

        using var frontClient = new TcpClient
        {
            NoDelay = true
        };

        await frontClient.ConnectAsync(IPAddress.Loopback, frontPort, cts.Token).ConfigureAwait(false);
        await using var frontStream = frontClient.GetStream();
        await frontStream.WriteAsync(requestPayload, cts.Token).ConfigureAwait(false);
        await frontStream.FlushAsync(cts.Token).ConfigureAwait(false);
        if (clientHalfClose)
        {
            frontClient.Client.Shutdown(SocketShutdown.Send);
        }

        var clientResponseBytes = await ReadToEndAsync(frontStream, cts.Token).ConfigureAwait(false);

        await relayTask.ConfigureAwait(false);
        var remoteRequest = await remoteServerTask.ConfigureAwait(false);

        return new RelayScenarioResult(
            remoteRequest,
            Encoding.ASCII.GetString(clientResponseBytes),
            trafficRegistry.CreateSnapshot());
    }

    private static async Task<byte[]> ReadToEndAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[1024];

        while (true)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return buffer.ToArray();
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed record RelayScenarioResult(
        string RemoteRequest,
        string ClientResponse,
        IReadOnlyList<UserTrafficSnapshot> TrafficSnapshots);
}

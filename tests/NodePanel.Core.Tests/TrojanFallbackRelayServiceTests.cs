using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanFallbackRelayServiceTests
{
    [Fact]
    public async Task TryHandleAsync_retries_tcp_fallback_until_destination_is_ready()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fallbackRelayService = new TrojanFallbackRelayService(new RelayService());
        var initialPayload = Encoding.ASCII.GetBytes("GET /retry HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var fallbackPort = ReserveTcpPort();

        var remoteServerTask = Task.Run(async () =>
        {
            await Task.Delay(250, cts.Token).ConfigureAwait(false);

            using var listener = new TcpListener(IPAddress.Loopback, fallbackPort);
            listener.Start();

            using var client = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();
            var requestBytes = new byte[initialPayload.Length];
            await stream.ReadExactlyAsync(requestBytes.AsMemory(0, requestBytes.Length), cts.Token).ConfigureAwait(false);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("fallback-retry-ok"), cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);
            return Encoding.ASCII.GetString(requestBytes);
        }, cts.Token);

        var relayResult = await RunFallbackScenarioAsync(
            fallbackRelayService,
            initialPayload,
            CreateOptions(
                fallbackPort,
                path: "/retry",
                proxyProtocolVersion: 0),
            cts.Token);

        Assert.True(relayResult.Handled);
        Assert.Equal(Encoding.ASCII.GetString(initialPayload), await remoteServerTask);
        Assert.Equal("fallback-retry-ok", relayResult.ClientResponseText);
    }

    [Fact]
    public async Task TryHandleAsync_supports_port_only_tcp_fallback_destination()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fallbackRelayService = new TrojanFallbackRelayService(new RelayService());
        var initialPayload = Encoding.ASCII.GetBytes("GET /port-only HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var fallbackPort = ReserveTcpPort();

        using var listener = new TcpListener(IPAddress.Loopback, fallbackPort);
        listener.Start();

        var remoteServerTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();
            var requestBytes = new byte[initialPayload.Length];
            await stream.ReadExactlyAsync(requestBytes.AsMemory(0, requestBytes.Length), cts.Token).ConfigureAwait(false);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("fallback-port-ok"), cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);
            return Encoding.ASCII.GetString(requestBytes);
        }, cts.Token);

        var relayResult = await RunFallbackScenarioAsync(
            fallbackRelayService,
            initialPayload,
            CreateOptions(
                fallbackPort,
                path: "/port-only",
                proxyProtocolVersion: 0,
                destination: fallbackPort.ToString(),
                networkType: string.Empty),
            cts.Token);

        Assert.True(relayResult.Handled);
        Assert.Equal(Encoding.ASCII.GetString(initialPayload), await remoteServerTask);
        Assert.Equal("fallback-port-ok", relayResult.ClientResponseText);
    }

    [Fact]
    public async Task TryHandleAsync_writes_proxy_protocol_header_before_forwarding_payload()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fallbackRelayService = new TrojanFallbackRelayService(new RelayService());
        var initialPayload = Encoding.ASCII.GetBytes("GET /proxy HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var fallbackPort = ReserveTcpPort();

        using var listener = new TcpListener(IPAddress.Loopback, fallbackPort);
        listener.Start();

        var remoteServerTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token).ConfigureAwait(false);
            await using var stream = client.GetStream();

            var proxyHeader = await ReadLineAsync(stream, cts.Token).ConfigureAwait(false);
            var requestBytes = new byte[initialPayload.Length];
            await stream.ReadExactlyAsync(requestBytes.AsMemory(0, requestBytes.Length), cts.Token).ConfigureAwait(false);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("fallback-proxy-ok"), cts.Token).ConfigureAwait(false);
            await stream.FlushAsync(cts.Token).ConfigureAwait(false);

            return new RemoteFallbackCapture(
                proxyHeader,
                Encoding.ASCII.GetString(requestBytes));
        }, cts.Token);

        var relayResult = await RunFallbackScenarioAsync(
            fallbackRelayService,
            initialPayload,
            CreateOptions(
                fallbackPort,
                path: "/proxy",
                proxyProtocolVersion: 1,
                remoteEndPoint: new IPEndPoint(IPAddress.Parse("203.0.113.10"), 54321),
                localEndPoint: new IPEndPoint(IPAddress.Parse("198.51.100.20"), 8443)),
            cts.Token);

        var capture = await remoteServerTask;

        Assert.True(relayResult.Handled);
        Assert.Equal("PROXY TCP4 203.0.113.10 198.51.100.20 54321 8443", capture.ProxyHeader);
        Assert.Equal(Encoding.ASCII.GetString(initialPayload), capture.RequestText);
        Assert.Equal("fallback-proxy-ok", relayResult.ClientResponseText);
    }

    [Fact]
    public async Task TryHandleAsync_rejects_serve_ws_none_runtime_fallback()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fallbackRelayService = new TrojanFallbackRelayService(new RelayService());
        var initialPayload = Encoding.ASCII.GetBytes("GET /serve HTTP/1.1\r\nHost: example.com\r\n\r\n");

        var exception = await Assert.ThrowsAsync<NotSupportedException>(() => fallbackRelayService.TryHandleAsync(
            new MemoryStream(),
            initialPayload,
            CreateOptions(
                fallbackPort: 443,
                path: "/serve",
                proxyProtocolVersion: 0,
                destination: TrojanFallbackCompatibility.ServeWsNoneDestination,
                networkType: TrojanFallbackCompatibility.ServeNetworkType),
            cts.Token));

        Assert.Contains("serve", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<FallbackScenarioResult> RunFallbackScenarioAsync(
        TrojanFallbackRelayService fallbackRelayService,
        byte[] initialPayload,
        ITrojanInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;

        var relayTask = Task.Run(async () =>
        {
            using var inboundClient = await frontListener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            await using var inboundStream = inboundClient.GetStream();
            return await fallbackRelayService.TryHandleAsync(inboundStream, initialPayload, options, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

        using var frontClient = new TcpClient
        {
            NoDelay = true
        };

        await frontClient.ConnectAsync(IPAddress.Loopback, frontPort, cancellationToken).ConfigureAwait(false);
        await using var frontStream = frontClient.GetStream();
        var responseBytes = await ReadToEndAsync(frontStream, cancellationToken).ConfigureAwait(false);

        return new FallbackScenarioResult(
            await relayTask.ConfigureAwait(false),
            Encoding.ASCII.GetString(responseBytes));
    }

    private static TestTrojanConnectionOptions CreateOptions(
        int fallbackPort,
        string path,
        int proxyProtocolVersion,
        string? destination = null,
        string? networkType = null,
        EndPoint? remoteEndPoint = null,
        EndPoint? localEndPoint = null)
        => new()
        {
            HandshakeTimeoutSeconds = 10,
            ConnectTimeoutSeconds = 5,
            ServerName = string.Empty,
            Alpn = string.Empty,
            RemoteEndPoint = remoteEndPoint,
            LocalEndPoint = localEndPoint,
            UseCone = true,
            Fallbacks =
            [
                new TestTrojanFallback
                {
                    Path = path,
                    Type = networkType ?? "tcp",
                    Dest = destination ?? $"127.0.0.1:{fallbackPort}",
                    ProxyProtocolVersion = proxyProtocolVersion
                }
            ]
        };

    private static int ReserveTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
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

    private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var oneByte = new byte[1];

        while (true)
        {
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading a CRLF-delimited line.");
            }

            if (oneByte[0] == '\n')
            {
                var lineBytes = buffer.ToArray();
                if (lineBytes.Length > 0 && lineBytes[^1] == '\r')
                {
                    Array.Resize(ref lineBytes, lineBytes.Length - 1);
                }

                return Encoding.ASCII.GetString(lineBytes);
            }

            buffer.WriteByte(oneByte[0]);
        }
    }

    private sealed record FallbackScenarioResult(bool Handled, string ClientResponseText);

    private sealed record RemoteFallbackCapture(string ProxyHeader, string RequestText);
}

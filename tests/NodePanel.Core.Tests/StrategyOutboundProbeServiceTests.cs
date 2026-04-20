using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class StrategyOutboundProbeServiceTests
{
    [Fact]
    public async Task ProbeAsync_supports_https_candidates_via_runtime_internet_profile()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = RunProbeServerAsync(listener, CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var service = new DefaultStrategyOutboundProbeService(
            new DispatcherServiceProvider(new DirectTcpDispatcher()),
            TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory));

        var results = await service.ProbeAsync(
            new StrategyOutboundSettings
            {
                Tag = "auto",
                Protocol = OutboundProtocols.UrlTest,
                CandidateTags = ["direct"],
                ProbeUrl = $"https://localhost:{port}/health",
                ProbeIntervalSeconds = 60,
                ProbeTimeoutSeconds = 5
            },
            CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal("direct", result.Tag);
        Assert.True(result.Success);
        Assert.True(result.LatencyMilliseconds >= 0);

        var capture = await serverTask;
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("http/1.1", tlsSecurityFactory.NegotiatedApplicationProtocol);
        Assert.Contains("HEAD /health HTTP/1.1", capture.RequestText, StringComparison.Ordinal);
        Assert.Contains("Host: localhost", capture.RequestText, StringComparison.Ordinal);
        Assert.Contains("User-Agent: NodePanel-StrategyProbe/1.0", capture.RequestText, StringComparison.Ordinal);
    }

    private static async Task<CapturedProbeRequest> RunProbeServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var requestText = await ReadHttpHeadersAsync(stream, cancellationToken);
        var response =
            "HTTP/1.1 204 No Content\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        return new CapturedProbeRequest(requestText);
    }

    private static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(
            stream,
            Encoding.ASCII,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: true);
        var lines = new List<string>();

        while (true)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                break;
            }

            lines.Add(line);
            if (line.Length == 0)
            {
                break;
            }
        }

        return string.Join("\r\n", lines);
    }

    private sealed record CapturedProbeRequest(string RequestText);

    private sealed class DispatcherServiceProvider : IServiceProvider
    {
        private readonly IDispatcher _dispatcher;

        public DispatcherServiceProvider(IDispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public object? GetService(Type serviceType)
            => serviceType == typeof(IDispatcher) ? _dispatcher : null;
    }

    private sealed class DirectTcpDispatcher : IDispatcher
    {
        public async ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            var client = new TcpClient();
            await client.ConnectAsync(destination.Host, destination.Port, cancellationToken);
            return client.GetStream();
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<IOutboundUdpTransport>(new NullOutboundUdpTransport());
    }

    private sealed class NullOutboundUdpTransport : IOutboundUdpTransport
    {
        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;

        public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult<DispatchDatagram?>(null);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

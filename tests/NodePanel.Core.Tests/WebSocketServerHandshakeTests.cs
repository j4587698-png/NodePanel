using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Tests;

public sealed class WebSocketServerHandshakeTests
{
    [Fact]
    public async Task AcceptAsync_returns_404_when_path_does_not_match()
    {
        await using var scenario = await WebSocketHandshakeScenario.CreateAsync();
        var response = await scenario.ExecuteAsync(
            BuildRequest(
                path: "/unexpected",
                host: "example.com"),
            new WebSocketServerHandshakeOptions
            {
                Host = "example.com",
                Path = "/ws"
            });

        Assert.StartsWith("HTTP/1.1 404 Not Found", response.ResponseText, StringComparison.Ordinal);
        Assert.IsType<InvalidDataException>(response.ServerException);
    }

    [Fact]
    public async Task AcceptAsync_returns_404_when_host_does_not_match()
    {
        await using var scenario = await WebSocketHandshakeScenario.CreateAsync();
        var response = await scenario.ExecuteAsync(
            BuildRequest(
                path: "/ws",
                host: "invalid.example.com"),
            new WebSocketServerHandshakeOptions
            {
                Host = "example.com",
                Path = "/ws"
            });

        Assert.StartsWith("HTTP/1.1 404 Not Found", response.ResponseText, StringComparison.Ordinal);
        Assert.IsType<InvalidDataException>(response.ServerException);
    }

    [Fact]
    public async Task AcceptAsync_exposes_websocket_early_data_as_prefixed_payload()
    {
        await using var scenario = await WebSocketHandshakeScenario.CreateAsync();
        var earlyData = Encoding.ASCII.GetBytes("trojan-header");
        var protocolHeader = Convert.ToBase64String(earlyData)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        var response = await scenario.ExecuteAsync(
            BuildRequest(
                path: "/ws",
                host: "example.com",
                secWebSocketProtocol: protocolHeader),
            new WebSocketServerHandshakeOptions
            {
                Host = "example.com",
                Path = "/ws",
                EarlyDataBytes = 2048
            },
            static async acceptedStream =>
            {
                var buffer = new byte["trojan-header".Length];
                var read = await acceptedStream.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
                return Encoding.ASCII.GetString(buffer.AsSpan(0, read));
            });

        Assert.StartsWith("HTTP/1.1 101 Switching Protocols", response.ResponseText, StringComparison.Ordinal);
        Assert.Contains($"Sec-WebSocket-Protocol: {protocolHeader}", response.ResponseText, StringComparison.Ordinal);
        Assert.Null(response.ServerException);
        Assert.Equal("trojan-header", response.AcceptedPayload);
    }

    private static string BuildRequest(string path, string host, string? secWebSocketProtocol = null)
    {
        var builder = new StringBuilder();
        builder.Append("GET ");
        builder.Append(path);
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(host);
        builder.Append("\r\n");
        builder.Append("Upgrade: websocket\r\n");
        builder.Append("Connection: Upgrade\r\n");
        builder.Append("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
        builder.Append("Sec-WebSocket-Version: 13\r\n");
        if (!string.IsNullOrWhiteSpace(secWebSocketProtocol))
        {
            builder.Append("Sec-WebSocket-Protocol: ");
            builder.Append(secWebSocketProtocol);
            builder.Append("\r\n");
        }

        builder.Append("\r\n");
        return builder.ToString();
    }

    private sealed class WebSocketHandshakeScenario : IAsyncDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _clientStream;
        private readonly TcpClient _serverClient;
        private readonly NetworkStream _serverStream;

        private WebSocketHandshakeScenario(TcpClient client, TcpClient serverClient)
        {
            _client = client;
            _serverClient = serverClient;
            _clientStream = client.GetStream();
            _serverStream = serverClient.GetStream();
        }

        public static async Task<WebSocketHandshakeScenario> CreateAsync()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var client = new TcpClient
            {
                NoDelay = true
            };
            var connectTask = client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            var serverClientTask = listener.AcceptTcpClientAsync();

            await Task.WhenAll(connectTask, serverClientTask).ConfigureAwait(false);
            return new WebSocketHandshakeScenario(client, serverClientTask.Result);
        }

        public async Task<WebSocketHandshakeResult> ExecuteAsync(
            string request,
            WebSocketServerHandshakeOptions options,
            Func<Stream, Task<string>>? onAccepted = null)
        {
            await _clientStream.WriteAsync(Encoding.ASCII.GetBytes(request), CancellationToken.None).ConfigureAwait(false);
            await _clientStream.FlushAsync(CancellationToken.None).ConfigureAwait(false);

            Exception? serverException = null;
            string? acceptedPayload = null;

            var serverTask = Task.Run(async () =>
            {
                try
                {
                    await using var acceptedStream = await WebSocketServerHandshake.AcceptAsync(
                        _serverStream,
                        options,
                        CancellationToken.None).ConfigureAwait(false);

                    if (onAccepted is not null)
                    {
                        acceptedPayload = await onAccepted(acceptedStream).ConfigureAwait(false);
                    }
                }
                catch (Exception ex)
                {
                    serverException = ex;
                }
            });

            var responseText = await ReadHttpHeadersAsync(_clientStream, CancellationToken.None).ConfigureAwait(false);
            await serverTask.ConfigureAwait(false);

            return new WebSocketHandshakeResult(responseText, acceptedPayload, serverException);
        }

        public async ValueTask DisposeAsync()
        {
            await _clientStream.DisposeAsync().ConfigureAwait(false);
            await _serverStream.DisposeAsync().ConfigureAwait(false);
            _client.Dispose();
            _serverClient.Dispose();
        }

        private static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
        {
            using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
            var lines = new List<string>();

            while (true)
            {
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
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
    }

    private sealed record WebSocketHandshakeResult(string ResponseText, string? AcceptedPayload, Exception? ServerException);
}

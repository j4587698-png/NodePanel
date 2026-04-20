using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Tests;

public sealed class HttpUpgradeServerHandshakeTests
{
    [Fact]
    public async Task AcceptAsync_returns_404_when_path_does_not_match()
    {
        await using var scenario = await HttpUpgradeHandshakeScenario.CreateAsync();
        var response = await scenario.ExecuteAsync(
            BuildRequest(
                path: "/unexpected",
                host: "example.com"),
            new HttpUpgradeServerHandshakeOptions
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
        await using var scenario = await HttpUpgradeHandshakeScenario.CreateAsync();
        var response = await scenario.ExecuteAsync(
            BuildRequest(
                path: "/ws",
                host: "invalid.example.com"),
            new HttpUpgradeServerHandshakeOptions
            {
                Host = "example.com",
                Path = "/ws"
            });

        Assert.StartsWith("HTTP/1.1 404 Not Found", response.ResponseText, StringComparison.Ordinal);
        Assert.IsType<InvalidDataException>(response.ServerException);
    }

    [Fact]
    public async Task AcceptAsync_exposes_payload_after_headers_as_readable_stream()
    {
        await using var scenario = await HttpUpgradeHandshakeScenario.CreateAsync();
        var response = await scenario.ExecuteAsync(
            BuildRequest(
                path: "/ws",
                host: "example.com",
                trailingPayload: "vless-header"),
            new HttpUpgradeServerHandshakeOptions
            {
                Host = "example.com",
                Path = "/ws"
            },
            static async acceptedStream =>
            {
                var buffer = new byte["vless-header".Length];
                var read = await acceptedStream.ReadAsync(buffer, CancellationToken.None);
                return Encoding.ASCII.GetString(buffer.AsSpan(0, read));
            });

        Assert.StartsWith("HTTP/1.1 101 Switching Protocols", response.ResponseText, StringComparison.Ordinal);
        Assert.Null(response.ServerException);
        Assert.Equal("vless-header", response.AcceptedPayload);
    }

    private static string BuildRequest(string path, string host, string? trailingPayload = null)
    {
        var builder = new StringBuilder();
        builder.Append("GET ");
        builder.Append(path);
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(host);
        builder.Append("\r\n");
        builder.Append("Connection: Upgrade\r\n");
        builder.Append("Upgrade: websocket\r\n");
        builder.Append("User-Agent: unit-test\r\n");
        builder.Append("\r\n");

        if (!string.IsNullOrWhiteSpace(trailingPayload))
        {
            builder.Append(trailingPayload);
        }

        return builder.ToString();
    }

    private sealed class HttpUpgradeHandshakeScenario : IAsyncDisposable
    {
        private readonly TcpClient _client;
        private readonly NetworkStream _clientStream;
        private readonly TcpClient _serverClient;
        private readonly NetworkStream _serverStream;

        private HttpUpgradeHandshakeScenario(TcpClient client, TcpClient serverClient)
        {
            _client = client;
            _serverClient = serverClient;
            _clientStream = client.GetStream();
            _serverStream = serverClient.GetStream();
        }

        public static async Task<HttpUpgradeHandshakeScenario> CreateAsync()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            var client = new TcpClient
            {
                NoDelay = true
            };
            var connectTask = client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            var serverClientTask = listener.AcceptTcpClientAsync();

            await Task.WhenAll(connectTask, serverClientTask);
            return new HttpUpgradeHandshakeScenario(client, serverClientTask.Result);
        }

        public async Task<HttpUpgradeHandshakeResult> ExecuteAsync(
            string request,
            HttpUpgradeServerHandshakeOptions options,
            Func<Stream, Task<string>>? onAccepted = null)
        {
            await _clientStream.WriteAsync(Encoding.ASCII.GetBytes(request), CancellationToken.None);
            await _clientStream.FlushAsync(CancellationToken.None);

            Exception? serverException = null;
            string? acceptedPayload = null;

            var serverTask = Task.Run(async () =>
            {
                try
                {
                    var acceptedStream = await HttpUpgradeServerHandshake.AcceptAsync(
                        _serverStream,
                        options,
                        CancellationToken.None);

                    if (onAccepted is not null)
                    {
                        acceptedPayload = await onAccepted(acceptedStream);
                    }
                }
                catch (Exception ex)
                {
                    serverException = ex;
                }
            });

            var responseText = await ReadHttpHeadersAsync(_clientStream, CancellationToken.None);
            await serverTask;

            return new HttpUpgradeHandshakeResult(responseText, acceptedPayload, serverException);
        }

        public async ValueTask DisposeAsync()
        {
            await _clientStream.DisposeAsync();
            await _serverStream.DisposeAsync();
            _client.Dispose();
            _serverClient.Dispose();
        }

        private static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
        {
            using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
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
    }

    private sealed record HttpUpgradeHandshakeResult(string ResponseText, string? AcceptedPayload, Exception? ServerException);
}


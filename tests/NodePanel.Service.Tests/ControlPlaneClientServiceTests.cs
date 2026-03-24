using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;
using NodePanel.Service.Services;

namespace NodePanel.Service.Tests;

public sealed class ControlPlaneClientServiceTests
{
    [Fact]
    public async Task StartAsync_reconnects_after_server_drops_websocket_without_close_handshake()
    {
        await using var server = new AbruptWebSocketServer();
        using var tempRoot = new TemporaryDirectory();

        var options = new NodePanelOptions
        {
            PanelUrl = server.Url,
            CachedConfigPath = Path.Combine(tempRoot.Path, "node-runtime-config.json"),
            Identity = new NodeIdentityOptions
            {
                NodeId = "node-001"
            },
            ControlPlane = new ControlPlaneOptions
            {
                Enabled = true,
                Url = server.Url,
                ConnectTimeoutSeconds = 2,
                HeartbeatIntervalSeconds = 1,
                ReconnectDelaySeconds = 1
            }
        };

        var runtimeConfigStore = new RuntimeConfigStore();
        var persistedNodeConfigStore = new PersistedNodeConfigStore(options, NullLogger<PersistedNodeConfigStore>.Instance);
        var orchestrator = new ConfigOrchestrator(
            runtimeConfigStore,
            new UserStore(),
            new RateLimiterRegistry(),
            Array.Empty<IOutboundHandler>(),
            Array.Empty<IInboundProtocolRuntimeCompiler>(),
            persistedNodeConfigStore,
            NullLogger<ConfigOrchestrator>.Instance);

        using var service = new ControlPlaneClientService(
            options,
            new CertificateRenewalSignal(),
            orchestrator,
            runtimeConfigStore,
            NullLogger<ControlPlaneClientService>.Instance);

        await service.StartAsync(CancellationToken.None);
        try
        {
            await server.WaitForConnectionCountAsync(2, TimeSpan.FromSeconds(8));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    private sealed class AbruptWebSocketServer : IAsyncDisposable
    {
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Task _acceptLoopTask;
        private readonly Dictionary<int, TaskCompletionSource<int>> _connectionSignals = new();
        private readonly TcpListener _listener;
        private int _connectionCount;

        public AbruptWebSocketServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            _acceptLoopTask = AcceptLoopAsync(_disposeCts.Token);
        }

        public string Url => $"ws://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}/control/ws";

        public Task WaitForConnectionCountAsync(int expectedCount, TimeSpan timeout)
        {
            TaskCompletionSource<int> signal;
            lock (_connectionSignals)
            {
                if (_connectionCount >= expectedCount)
                {
                    return Task.CompletedTask;
                }

                if (!_connectionSignals.TryGetValue(expectedCount, out signal!))
                {
                    signal = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _connectionSignals[expectedCount] = signal;
                }
            }

            return signal.Task.WaitAsync(timeout);
        }

        public async ValueTask DisposeAsync()
        {
            _disposeCts.Cancel();
            _listener.Stop();
            try
            {
                await _acceptLoopTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            _disposeCts.Dispose();
        }

        private async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var currentCount = Interlocked.Increment(ref _connectionCount);
                CompleteSignals(currentCount);
                _ = HandleClientAsync(client);
            }
        }

        private void CompleteSignals(int currentCount)
        {
            lock (_connectionSignals)
            {
                foreach (var expectedCount in _connectionSignals.Keys.Where(key => key <= currentCount).ToArray())
                {
                    _connectionSignals[expectedCount].TrySetResult(currentCount);
                    _connectionSignals.Remove(expectedCount);
                }
            }
        }

        private static async Task HandleClientAsync(TcpClient client)
        {
            using (client)
            {
                try
                {
                    using var stream = client.GetStream();
                    var requestText = await ReadHttpRequestAsync(stream).ConfigureAwait(false);
                    var key = GetHeaderValue(requestText, "Sec-WebSocket-Key");
                    if (string.IsNullOrWhiteSpace(key))
                    {
                        return;
                    }

                    var responseText =
                        "HTTP/1.1 101 Switching Protocols\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Upgrade: websocket\r\n" +
                        $"Sec-WebSocket-Accept: {ComputeWebSocketAccept(key)}\r\n" +
                        "\r\n";
                    var responseBytes = Encoding.ASCII.GetBytes(responseText);
                    await stream.WriteAsync(responseBytes).ConfigureAwait(false);
                    await stream.FlushAsync().ConfigureAwait(false);

                    await Task.Delay(TimeSpan.FromMilliseconds(200)).ConfigureAwait(false);
                    client.Client.LingerState = new LingerOption(true, 0);
                }
                catch (IOException)
                {
                }
                catch (SocketException)
                {
                }
            }
        }

        private static async Task<string> ReadHttpRequestAsync(NetworkStream stream)
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[1024];
            while (true)
            {
                var read = await stream.ReadAsync(chunk).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                buffer.Write(chunk, 0, read);
                if (HasHttpRequestTerminator(buffer))
                {
                    break;
                }
            }

            return Encoding.ASCII.GetString(buffer.ToArray());
        }

        private static bool HasHttpRequestTerminator(MemoryStream stream)
        {
            if (stream.Length < 4)
            {
                return false;
            }

            var buffer = stream.GetBuffer();
            var length = (int)stream.Length;
            return buffer[length - 4] == '\r' &&
                   buffer[length - 3] == '\n' &&
                   buffer[length - 2] == '\r' &&
                   buffer[length - 1] == '\n';
        }

        private static string GetHeaderValue(string requestText, string name)
        {
            foreach (var line in requestText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
            {
                var separatorIndex = line.IndexOf(':');
                if (separatorIndex <= 0)
                {
                    continue;
                }

                var headerName = line[..separatorIndex].Trim();
                if (!string.Equals(headerName, name, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                return line[(separatorIndex + 1)..].Trim();
            }

            return string.Empty;
        }

        private static string ComputeWebSocketAccept(string key)
        {
            const string webSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            var input = Encoding.ASCII.GetBytes(key + webSocketGuid);
            return Convert.ToBase64String(SHA1.HashData(input));
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "np-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}

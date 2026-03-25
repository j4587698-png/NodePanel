using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class LocalProxyServerTests
{
    [Fact]
    public async Task Socks5LocalProxyServer_relays_connect_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new Socks5LocalProxyServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new Socks5LocalProxyServerOptions
            {
                Listeners =
                [
                    new LocalProxyListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new LocalProxyServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, lifetimeCts.Token);
            var greeting = new byte[2];
            await ReadExactAsync(stream, greeting, lifetimeCts.Token);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            var request = new List<byte>
            {
                0x05, 0x01, 0x00, 0x01
            };
            request.AddRange(IPAddress.Loopback.GetAddressBytes());
            request.Add((byte)(echoPort >> 8));
            request.Add((byte)(echoPort & 0xFF));
            await stream.WriteAsync(request.ToArray(), lifetimeCts.Token);

            var reply = new byte[10];
            await ReadExactAsync(stream, reply, lifetimeCts.Token);
            Assert.Equal(0x00, reply[1]);

            var payload = Encoding.ASCII.GetBytes("hello-socks");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    [Fact]
    public async Task HttpLocalProxyServer_relays_connect_traffic()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var proxyPort = GetAvailableTcpPort();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var server = new HttpLocalProxyServer(new DirectTcpDispatcher(), new RelayService());
        var serverTask = server.RunAsync(
            new HttpLocalProxyServerOptions
            {
                Listeners =
                [
                    new LocalProxyListenerDefinition
                    {
                        Tag = "http-local",
                        Binding = new ListenerBinding("127.0.0.1", proxyPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ],
                Callbacks = new LocalProxyServerCallbacks
                {
                    ListenerStarted = _ => started.TrySetResult()
                }
            },
            lifetimeCts.Token);

        try
        {
            await started.Task.WaitAsync(lifetimeCts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, lifetimeCts.Token);
            await using var stream = client.GetStream();

            var request = $"CONNECT 127.0.0.1:{echoPort} HTTP/1.1\r\nHost: 127.0.0.1:{echoPort}\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), lifetimeCts.Token);

            var response = await ReadHeaderAsync(stream, lifetimeCts.Token);
            Assert.Contains("200 Connection Established", response, StringComparison.Ordinal);

            var payload = Encoding.ASCII.GetBytes("hello-http");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);
        }
        finally
        {
            lifetimeCts.Cancel();
            await AwaitCompletionAsync(serverTask);
            await AwaitCompletionAsync(echoTask);
            echoListener.Stop();
        }
    }

    private static (TcpListener Listener, Task Task, int Port) StartEchoServer(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var task = RunEchoServerAsync(listener, cancellationToken);
        return (listener, task, port);
    }

    private static async Task RunEchoServerAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = client.GetStream();
            var buffer = new byte[4096];

            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private static int GetAvailableTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream.");
            }

            offset += read;
        }
    }

    private static async Task<string> ReadHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();
        var single = new byte[1];

        while (buffer.Count < 8192)
        {
            var read = await stream.ReadAsync(single.AsMemory(0, 1), cancellationToken);
            if (read == 0)
            {
                break;
            }

            buffer.Add(single[0]);
            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' &&
                buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' &&
                buffer[^1] == (byte)'\n')
            {
                break;
            }
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static async Task AwaitCompletionAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
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
            => throw new NotSupportedException();
    }
}

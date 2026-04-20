using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanOutboundClientTests
{
    [Fact]
    public async Task ConnectAsync_sends_websocket_early_data_without_writing_duplicate_trojan_header()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureWebSocketRequestAsync(listener, CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        var expectedHandshake = new TrojanHandshakeWriter().Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);

        TrojanClientConnection? connection = null;
        try
        {
            connection = await client.ConnectAsync(
                new TrojanClientOptions
                {
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerPort = port,
                    ServerName = "edge.example.com",
                    Transport = TrojanClientTransportType.Wss,
                    WebSocketPath = "/ws",
                    Password = "demo-password",
                    Command = TrojanCommand.Connect,
                    TargetHost = "example.org",
                    TargetPort = 443,
                    WebSocketEarlyDataBytes = 4096,
                    SkipCertificateValidation = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                },
                CancellationToken.None);
        }
        catch (Exception ex)
        {
            var serverException = await GetBackgroundExceptionAsync(captureTask);
            throw new InvalidOperationException(
                $"Client connect failed. Server exception: {serverException?.ToString() ?? "<none>"}",
                ex);
        }

        await using var _ = connection;

        var captured = await captureTask;
        var expectedEarlyData = Convert.ToBase64String(expectedHandshake)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        Assert.Contains("GET /ws HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains("Host: edge.example.com", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains("User-Agent: Mozilla/5.0", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains($"Sec-WebSocket-Protocol: {expectedEarlyData}", captured.RequestText, StringComparison.Ordinal);
        Assert.Empty(captured.ExtraBytes);
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task ConnectAsync_sends_websocket_handshake_payload_after_upgrade_when_early_data_limit_is_too_small()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureWebSocketRequestAsync(listener, CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        var expectedHandshake = new TrojanHandshakeWriter().Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);

        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = TrojanClientTransportType.Wss,
                WebSocketPath = "/ws",
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                WebSocketEarlyDataBytes = 1,
                SkipCertificateValidation = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            CancellationToken.None);

        var captured = await captureTask;
        Assert.DoesNotContain("Sec-WebSocket-Protocol:", captured.RequestText, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expectedHandshake, DecodeWebSocketClientBinaryFrame(captured.ExtraBytes));
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task ConnectAsync_forces_http11_alpn_for_wss_transport()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureWebSocketRequestAsync(listener, CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = TrojanClientTransportType.Wss,
                WebSocketPath = "/ws",
                ApplicationProtocols = ["h2"],
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                SkipCertificateValidation = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            CancellationToken.None);

        var captured = await captureTask;
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("http/1.1", tlsSecurityFactory.NegotiatedApplicationProtocol);
        Assert.Contains("GET /ws HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConnectAsync_supports_explicit_transport_and_security_names()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureWebSocketRequestAsync(listener, CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                TransportProtocol = TrojanClientTransportProtocols.Ws,
                SecurityType = TrojanClientSecurityTypes.Tls,
                WebSocketPath = "/ws",
                ApplicationProtocols = ["h2"],
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                SkipCertificateValidation = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            CancellationToken.None);

        var captured = await captureTask;
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("http/1.1", tlsSecurityFactory.NegotiatedApplicationProtocol);
        Assert.Contains("GET /ws HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConnectAsync_uses_browser_dialer_for_websocket_early_data_without_opening_base_stream()
    {
        const string serverPayload = "browser-server";
        const string clientPayload = "browser-client";
        var handshakeWriter = new TrojanHandshakeWriter();
        var expectedHandshake = handshakeWriter.Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);
        var expectedEarlyData = Convert.ToBase64String(expectedHandshake)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        var browserStream = new RecordingBrowserWebSocketStream(Encoding.ASCII.GetBytes(serverPayload));
        var browserDialer = new RecordingBrowserDialer(
            (_, _) => ValueTask.FromResult<Stream>(browserStream));
        var client = CreateClient(RuntimeInternetProfile.FromDefault(browserDialer: browserDialer));

        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = 443,
                ServerName = "edge.example.com",
                Transport = TrojanClientTransportType.Wss,
                WebSocketPath = " browser?route=1 ",
                WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Host"] = "cdn.example.com"
                },
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                WebSocketEarlyDataBytes = 4096,
                TransportStreamFactory = static _ => throw new InvalidOperationException("Browser websocket dialing should bypass base transport creation.")
            },
            CancellationToken.None);

        var request = Assert.Single(browserDialer.WebSocketRequests);
        Assert.Equal("wss://127.0.0.1/browser?route=1", request.Url);
        Assert.Equal(expectedEarlyData, request.SubProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, connection.SecurityType);
        Assert.Equal(SslProtocols.None, connection.NegotiatedSslProtocol);
        Assert.Null(connection.SslStream);
        Assert.Empty(browserStream.WrittenBytes);

        var responseBuffer = new byte[serverPayload.Length];
        var read = await connection.Stream.ReadAsync(responseBuffer.AsMemory(0, responseBuffer.Length), CancellationToken.None);
        Assert.Equal(responseBuffer.Length, read);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        await connection.Stream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), CancellationToken.None);
        Assert.Equal(clientPayload, Encoding.ASCII.GetString(browserStream.WrittenBytes));
    }

    [Fact]
    public async Task ConnectAsync_uses_browser_dialer_for_websocket_without_early_data_and_writes_handshake_to_stream()
    {
        var expectedHandshake = new TrojanHandshakeWriter().Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);
        var browserStream = new RecordingBrowserWebSocketStream();
        var browserDialer = new RecordingBrowserDialer(
            (_, _) => ValueTask.FromResult<Stream>(browserStream));
        var client = CreateClient(RuntimeInternetProfile.FromDefault(browserDialer: browserDialer));

        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = 8080,
                Transport = TrojanClientTransportType.Ws,
                WebSocketPath = "/ws",
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                WebSocketEarlyDataBytes = 1,
                TransportStreamFactory = static _ => throw new InvalidOperationException("Browser websocket dialing should bypass base transport creation.")
            },
            CancellationToken.None);

        var request = Assert.Single(browserDialer.WebSocketRequests);
        Assert.Equal("ws://127.0.0.1:8080/ws", request.Url);
        Assert.Null(request.SubProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, connection.SecurityType);
        Assert.Null(connection.SslStream);
        Assert.Equal(expectedHandshake, browserStream.WrittenBytes);
    }

    [Fact]
    public async Task ConnectAsync_sends_httpupgrade_request_and_payload_after_101()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureHttpUpgradeRequestAsync(
            listener,
            captureEarlyDataBeforeResponse: false,
            CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = TrojanClientTransportType.HttpUpgradeTls,
                WebSocketPath = "/upgrade",
                ApplicationProtocols = ["h2"],
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                SkipCertificateValidation = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            CancellationToken.None);

        var captured = await captureTask;
        var expectedHandshake = new TrojanHandshakeWriter().Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);

        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("http/1.1", tlsSecurityFactory.NegotiatedApplicationProtocol);
        Assert.Contains("GET /upgrade HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains("Host: edge.example.com", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains("Connection: Upgrade", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains("Upgrade: websocket", captured.RequestText, StringComparison.Ordinal);
        Assert.DoesNotContain("Sec-WebSocket-Key:", captured.RequestText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Sec-WebSocket-Protocol:", captured.RequestText, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(captured.EarlyDataBytes);
        Assert.Equal(expectedHandshake, captured.PostResponseBytes);
    }

    [Fact]
    public async Task ConnectAsync_prefers_splithttp_host_and_path_for_httpupgrade_transport()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureHttpUpgradeRequestAsync(
            listener,
            captureEarlyDataBeforeResponse: false,
            CancellationToken.None);
        var client = CreateClient(RuntimeInternetProfile.FromDefault());
        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                TransportProtocol = TrojanClientTransportProtocols.HttpUpgrade,
                SecurityType = TrojanClientSecurityTypes.None,
                WebSocketPath = "/ignored",
                WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Host"] = "ignored.example.com"
                },
                SplitHttpHost = "edge.example.com",
                SplitHttpPath = "/upgrade",
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443
            },
            CancellationToken.None);

        var captured = await captureTask;
        var expectedHandshake = new TrojanHandshakeWriter().Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);

        Assert.Contains("GET /upgrade HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
        Assert.Contains("Host: edge.example.com", captured.RequestText, StringComparison.Ordinal);
        Assert.DoesNotContain("GET /ignored HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
        Assert.DoesNotContain("Host: ignored.example.com", captured.RequestText, StringComparison.Ordinal);
        Assert.Equal(expectedHandshake, captured.PostResponseBytes);
    }

    [Fact]
    public async Task ConnectAsync_sends_httpupgrade_early_data_without_duplicate_trojan_header()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureHttpUpgradeRequestAsync(
            listener,
            captureEarlyDataBeforeResponse: true,
            CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                TransportProtocol = TrojanClientTransportProtocols.HttpUpgrade,
                SecurityType = TrojanClientSecurityTypes.Tls,
                WebSocketPath = "/upgrade",
                WebSocketEarlyDataBytes = 4096,
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                SkipCertificateValidation = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            CancellationToken.None);

        var captured = await captureTask;
        var expectedHandshake = new TrojanHandshakeWriter().Build(
            "demo-password",
            TrojanCommand.Connect,
            "example.org",
            443);

        Assert.Contains("GET /upgrade HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
        Assert.Equal(expectedHandshake, captured.EarlyDataBytes);
        Assert.Empty(captured.PostResponseBytes);
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task ConnectAsync_uses_default_tls_alpn_for_tcp_transport()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CapturePayloadAsync(listener, CancellationToken.None);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var client = CreateClient(tlsSecurityFactory);
        await using var connection = await client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = TrojanClientTransportType.Tls,
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                SkipCertificateValidation = true,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            CancellationToken.None);

        var captured = await captureTask;
        Assert.Equal(["h2", "http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
        Assert.NotEmpty(captured.Payload);
    }

    [Fact]
    public async Task ConnectAsync_rejects_unknown_transport_protocol()
    {
        var client = new TrojanOutboundClient();

        var exception = await Assert.ThrowsAsync<NotSupportedException>(() => client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = 443,
                TransportProtocol = "quic",
                SecurityType = TrojanClientSecurityTypes.None,
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443
            },
            CancellationToken.None));

        Assert.Contains("QUIC transport", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SplitHTTP", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ConnectAsync_sends_builtin_reality_client_hello_before_waiting_for_serverhello()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = RealityClientHelloCaptureServer.AcceptOnceAsync(listener, cts.Token);
        var client = new TrojanOutboundClient();

        var exception = await Record.ExceptionAsync(() => client.ConnectAsync(
            new TrojanClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "localhost",
                TransportProtocol = TrojanClientTransportProtocols.Tcp,
                SecurityType = TrojanClientSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    Fingerprint = "chrome",
                    PublicKey = EncodeBase64Url(32, 0x55)
                },
                Password = "demo-password",
                Command = TrojanCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443
            },
            cts.Token));

        Assert.NotNull(exception);
        Assert.True(exception is EndOfStreamException or IOException, exception.ToString());

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal("localhost", capture.Metadata!.ServerName);
        Assert.Contains("h2", capture.Metadata.ApplicationProtocols);
        Assert.Contains("http/1.1", capture.Metadata.ApplicationProtocols);
    }

    private static TrojanOutboundClient CreateClient(
        RuntimeInternetProfile internetProfile)
        => new(
            new TrojanHandshakeWriter(),
            dnsResolver: null,
            internetProfile);

    private static TrojanOutboundClient CreateClient(
        TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory tlsSecurityFactory)
        => CreateClient(TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory));

    private static async Task<CapturedWebSocketRequest> CaptureWebSocketRequestAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var requestText = await ReadHttpHeadersAsync(stream, cancellationToken);
        var webSocketKey = GetHeaderValue(requestText, "Sec-WebSocket-Key");
        var response =
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {ComputeWebSocketAccept(webSocketKey)}\r\n" +
            "\r\n";

        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var extraBytes = await ReadWithTimeoutAsync(stream, TimeSpan.FromMilliseconds(200));
        return new CapturedWebSocketRequest(requestText, extraBytes);
    }

    private static async Task<CapturedHttpUpgradeRequest> CaptureHttpUpgradeRequestAsync(
        TcpListener listener,
        bool captureEarlyDataBeforeResponse,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var requestText = await ReadHttpHeadersBytewiseAsync(stream, cancellationToken);
        var earlyDataBytes = captureEarlyDataBeforeResponse
            ? await ReadWithTimeoutAsync(stream, TimeSpan.FromMilliseconds(200))
            : Array.Empty<byte>();

        var response =
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Connection: Upgrade\r\n" +
            "Upgrade: websocket\r\n" +
            "\r\n";

        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var postResponseBytes = await ReadWithTimeoutAsync(stream, TimeSpan.FromMilliseconds(200));
        return new CapturedHttpUpgradeRequest(requestText, earlyDataBytes, postResponseBytes);
    }

    private static async Task<CapturedPayload> CapturePayloadAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var payload = await ReadWithTimeoutAsync(stream, TimeSpan.FromSeconds(1));
        return new CapturedPayload(payload);
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

    private static async Task<string> ReadHttpHeadersBytewiseAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(512);
        var oneByte = new byte[1];
        var terminator = "\r\n\r\n"u8.ToArray();
        var matched = 0;

        while (buffer.Length < 16 * 1024)
        {
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading HTTP headers.");
            }

            buffer.WriteByte(oneByte[0]);
            if (oneByte[0] == terminator[matched])
            {
                matched++;
                if (matched == terminator.Length)
                {
                    return Encoding.ASCII.GetString(buffer.ToArray());
                }

                continue;
            }

            matched = oneByte[0] == terminator[0] ? 1 : 0;
        }

        throw new InvalidOperationException("HTTP headers exceeded the configured limit.");
    }

    private static async Task<byte[]> ReadWithTimeoutAsync(Stream stream, TimeSpan timeout)
    {
        using var timeoutCts = new CancellationTokenSource(timeout);
        var buffer = new byte[256];

        try
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), timeoutCts.Token);
            return read == 0 ? Array.Empty<byte>() : buffer.AsSpan(0, read).ToArray();
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            return Array.Empty<byte>();
        }
    }

    private static async Task<Exception?> GetBackgroundExceptionAsync(Task task)
    {
        try
        {
            await task.WaitAsync(TimeSpan.FromSeconds(1));
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    private static string GetHeaderValue(string requestText, string name)
    {
        var prefix = name + ":";
        foreach (var line in requestText.Split("\r\n", StringSplitOptions.None))
        {
            if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return line[prefix.Length..].Trim();
            }
        }

        throw new InvalidDataException($"Missing header: {name}.");
    }

    private static string ComputeWebSocketAccept(string key)
    {
        const string webSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var input = Encoding.ASCII.GetBytes(key + webSocketGuid);
        return Convert.ToBase64String(SHA1.HashData(input));
    }

    private static byte[] DecodeWebSocketClientBinaryFrame(byte[] frame)
    {
        if (frame.Length < 6)
        {
            throw new InvalidDataException("WebSocket frame is incomplete.");
        }

        var opcode = frame[0] & 0x0f;
        if (opcode != 0x02)
        {
            throw new InvalidDataException($"Unexpected WebSocket opcode: 0x{opcode:x2}.");
        }

        var masked = (frame[1] & 0x80) != 0;
        if (!masked)
        {
            throw new InvalidDataException("Client WebSocket frame must be masked.");
        }

        var payloadLength = frame[1] & 0x7f;
        var offset = 2;
        ulong payloadLength64 = (ulong)payloadLength;
        if (payloadLength == 126)
        {
            if (frame.Length < offset + 2)
            {
                throw new InvalidDataException("WebSocket frame length is incomplete.");
            }

            payloadLength64 = ((ulong)frame[offset] << 8) | frame[offset + 1];
            offset += 2;
        }
        else if (payloadLength == 127)
        {
            if (frame.Length < offset + 8)
            {
                throw new InvalidDataException("WebSocket frame length is incomplete.");
            }

            payloadLength64 = 0;
            for (var index = 0; index < 8; index++)
            {
                payloadLength64 = (payloadLength64 << 8) | frame[offset + index];
            }

            offset += 8;
        }

        if (payloadLength64 > int.MaxValue)
        {
            throw new InvalidDataException("WebSocket frame payload is too large for this test helper.");
        }

        if (frame.Length < offset + 4 + (int)payloadLength64)
        {
            throw new InvalidDataException("WebSocket frame payload is incomplete.");
        }

        var maskingKey = frame.AsSpan(offset, 4);
        offset += 4;
        var payload = frame.AsSpan(offset, (int)payloadLength64).ToArray();
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] ^= maskingKey[index % 4];
        }

        return payload;
    }

    private static string EncodeBase64Url(int length, byte value)
        => Convert.ToBase64String(Enumerable.Repeat(value, length).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed record BrowserDialerWebSocketCall(
        string Url,
        string? SubProtocol);

    private sealed class RecordingBrowserDialer : IRuntimeInternetBrowserDialer
    {
        private readonly Func<RuntimeInternetBrowserWebSocketRequest, CancellationToken, ValueTask<Stream>> _webSocketFactory;

        public RecordingBrowserDialer(
            Func<RuntimeInternetBrowserWebSocketRequest, CancellationToken, ValueTask<Stream>>? webSocketFactory = null)
        {
            _webSocketFactory = webSocketFactory ?? CreateEmptyWebSocketStreamAsync;
        }

        public ConcurrentQueue<BrowserDialerWebSocketCall> WebSocketRequests { get; } = new();

        public ValueTask<Stream> OpenStreamAsync(
            RuntimeInternetBrowserStreamRequest request,
            CancellationToken cancellationToken)
            => ValueTask.FromException<Stream>(new NotSupportedException("HTTP browser dialing is not expected in this test."));

        public async ValueTask<Stream> OpenWebSocketStreamAsync(
            RuntimeInternetBrowserWebSocketRequest request,
            CancellationToken cancellationToken)
        {
            WebSocketRequests.Enqueue(new BrowserDialerWebSocketCall(request.Url, request.SubProtocol));
            return await _webSocketFactory(request, cancellationToken);
        }

        public ValueTask SendPacketAsync(
            RuntimeInternetBrowserPacketRequest request,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
            => ValueTask.FromException(new NotSupportedException("HTTP packet browser dialing is not expected in this test."));

        private static ValueTask<Stream> CreateEmptyWebSocketStreamAsync(
            RuntimeInternetBrowserWebSocketRequest request,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<Stream>(new RecordingBrowserWebSocketStream());
    }

    private sealed class RecordingBrowserWebSocketStream : Stream
    {
        private readonly byte[] _readBuffer;
        private readonly MemoryStream _writeBuffer = new();
        private int _readOffset;

        public RecordingBrowserWebSocketStream(byte[]? readBuffer = null)
        {
            _readBuffer = readBuffer ?? Array.Empty<byte>();
        }

        public byte[] WrittenBytes => _writeBuffer.ToArray();

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override int Read(Span<byte> buffer)
        {
            var remaining = _readBuffer.Length - _readOffset;
            if (remaining <= 0)
            {
                return 0;
            }

            var count = Math.Min(buffer.Length, remaining);
            _readBuffer.AsSpan(_readOffset, count).CopyTo(buffer);
            _readOffset += count;
            return count;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = _readBuffer.Length - _readOffset;
            if (remaining <= 0)
            {
                return ValueTask.FromResult(0);
            }

            var count = Math.Min(buffer.Length, remaining);
            _readBuffer.AsMemory(_readOffset, count).CopyTo(buffer);
            _readOffset += count;
            return ValueTask.FromResult(count);
        }

        public override void Write(byte[] buffer, int offset, int count)
            => _writeBuffer.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer)
            => _writeBuffer.Write(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return _writeBuffer.WriteAsync(buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _writeBuffer.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            _writeBuffer.Dispose();
            await base.DisposeAsync();
        }
    }

    private sealed record CapturedWebSocketRequest(
        string RequestText,
        byte[] ExtraBytes);

    private sealed record CapturedHttpUpgradeRequest(
        string RequestText,
        byte[] EarlyDataBytes,
        byte[] PostResponseBytes);

    private sealed record CapturedPayload(byte[] Payload);
}

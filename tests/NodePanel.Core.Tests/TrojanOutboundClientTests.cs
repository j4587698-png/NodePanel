using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanOutboundClientTests
{
    [Fact]
    public async Task ConnectAsync_sends_websocket_early_data_without_writing_duplicate_trojan_header()
    {
        using var certificate = CreateSelfSignedCertificate();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureTlsWebSocketRequestAsync(listener, certificate, null, CancellationToken.None);

        var client = new TrojanOutboundClient();
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
    }

    [Fact]
    public async Task ConnectAsync_forces_http11_alpn_for_wss_transport()
    {
        using var certificate = CreateSelfSignedCertificate();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var captureTask = CaptureTlsWebSocketRequestAsync(
            listener,
            certificate,
            [new SslApplicationProtocol("http/1.1"), new SslApplicationProtocol("h2")],
            CancellationToken.None);

        var client = new TrojanOutboundClient();
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
        Assert.Equal("http/1.1", captured.NegotiatedApplicationProtocol);
        Assert.Contains("GET /ws HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
    }

    private static async Task<CapturedWebSocketRequest> CaptureTlsWebSocketRequestAsync(
        TcpListener listener,
        X509Certificate2 certificate,
        IReadOnlyList<SslApplicationProtocol>? applicationProtocols,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
        await using var networkStream = client.GetStream();
        await using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

        var authenticationOptions = new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ClientCertificateRequired = false
        };

        if (applicationProtocols is not null && applicationProtocols.Count > 0)
        {
            authenticationOptions.ApplicationProtocols = applicationProtocols.ToList();
        }

        await sslStream.AuthenticateAsServerAsync(authenticationOptions, cancellationToken).ConfigureAwait(false);

        var requestText = await ReadHttpHeadersAsync(sslStream, cancellationToken).ConfigureAwait(false);
        var webSocketKey = GetHeaderValue(requestText, "Sec-WebSocket-Key");
        var response =
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {ComputeWebSocketAccept(webSocketKey)}\r\n" +
            "\r\n";

        await sslStream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken).ConfigureAwait(false);
        await sslStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var extraBytes = await ReadWithTimeoutAsync(sslStream, TimeSpan.FromMilliseconds(200)).ConfigureAwait(false);
        var negotiatedApplicationProtocol = Encoding.ASCII.GetString(sslStream.NegotiatedApplicationProtocol.Protocol.Span);
        return new CapturedWebSocketRequest(requestText, extraBytes, negotiatedApplicationProtocol);
    }

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=edge.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
        subjectAlternativeNameBuilder.AddDnsName("edge.example.com");

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new("1.3.6.1.5.5.7.3.1")
            },
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
#pragma warning disable SYSLIB0057
        return new X509Certificate2(
            certificate.Export(X509ContentType.Pfx),
            password: (string?)null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
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

    private static async Task<byte[]> ReadWithTimeoutAsync(Stream stream, TimeSpan timeout)
    {
        using var timeoutCts = new CancellationTokenSource(timeout);
        var buffer = new byte[256];

        try
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), timeoutCts.Token).ConfigureAwait(false);
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
            await task.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
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

    private sealed record CapturedWebSocketRequest(
        string RequestText,
        byte[] ExtraBytes,
        string NegotiatedApplicationProtocol);
}

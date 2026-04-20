using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeRealityServerAcceptorTests
{
    [Fact]
    public async Task AcceptAsync_completes_builtin_reality_tls13_handshake_and_exchanges_application_data()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var keyLogPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.reality.keys.log");

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var endPoint = (IPEndPoint)listener.LocalEndpoint;
            var serverTask = Task.Run(async () =>
            {
                using var serverSocket = await listener.AcceptSocketAsync(cts.Token);
                await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
                var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                    acceptedConnection,
                    new RuntimeRealityServerOptions
                    {
                        ServerNames = ["edge.example.com"],
                        PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                        ShortIds = ["a1b2c3d4"],
                        MasterKeyLog = keyLogPath,
                        ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                    },
                    acceptProxyProtocol: false,
                    receiveOriginalDestination: false,
                    applicationProtocols: ["h2"],
                    onClientHelloRejected: null,
                    onUnknownServerNameRejected: null,
                    onEffectiveRemoteEndPointChanged: null,
                    cts.Token);
                Assert.NotNull(accepted);

                await using var acceptedContext = accepted!;
                Assert.Equal("edge.example.com", acceptedContext.ServerName);
                Assert.Equal("h2", acceptedContext.NegotiatedAlpn);
                Assert.Equal(System.Security.Authentication.SslProtocols.Tls13, acceptedContext.NegotiatedSslProtocol);

                var request = new byte[4];
                await acceptedContext.Stream.ReadExactlyAsync(request, cts.Token);
                Assert.Equal("ping", Encoding.ASCII.GetString(request));

                await acceptedContext.Stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
                await acceptedContext.Stream.FlushAsync(cts.Token);
            }, cts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, endPoint.Port, cts.Token);
            await using var clientStream = client.GetStream();
            var handshakeResult = await RuntimeRealityHandshakeProviders.Default.SecureAsync(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = clientStream,
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = new RuntimeRealityOptions
                    {
                        Fingerprint = "chrome",
                        PublicKey = ToBase64Url(realityKeyPair.PublicKey),
                        ShortId = "a1b2c3d4"
                    }
                },
                cts.Token);

            await using var securedClientStream = handshakeResult.TransportStream;
            await securedClientStream.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
            await securedClientStream.FlushAsync(cts.Token);

            var response = new byte[4];
            await securedClientStream.ReadExactlyAsync(response, cts.Token);
            Assert.Equal("pong", Encoding.ASCII.GetString(response));

            await serverTask;

            var keyLogLines = await File.ReadAllLinesAsync(keyLogPath, cts.Token);
            Assert.Contains(keyLogLines, static line => line.StartsWith("CLIENT_HANDSHAKE_TRAFFIC_SECRET ", StringComparison.Ordinal));
            Assert.Contains(keyLogLines, static line => line.StartsWith("SERVER_HANDSHAKE_TRAFFIC_SECRET ", StringComparison.Ordinal));
            Assert.Contains(keyLogLines, static line => line.StartsWith("CLIENT_TRAFFIC_SECRET_0 ", StringComparison.Ordinal));
            Assert.Contains(keyLogLines, static line => line.StartsWith("SERVER_TRAFFIC_SECRET_0 ", StringComparison.Ordinal));
        }
        finally
        {
            if (File.Exists(keyLogPath))
            {
                File.Delete(keyLogPath);
            }
        }
    }

    [Fact]
    public async Task AcceptAsync_completes_builtin_reality_tls13_handshake_after_hello_retry_request()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var endPoint = (IPEndPoint)listener.LocalEndpoint;
        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await listener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                new RuntimeRealityServerOptions
                {
                    ServerNames = ["edge.example.com"],
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    ShortIds = ["a1b2c3d4"],
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
            Assert.NotNull(accepted);

            await using var acceptedContext = accepted!;
            var request = new byte[4];
            await acceptedContext.Stream.ReadExactlyAsync(request, cts.Token);
            Assert.Equal("ping", Encoding.ASCII.GetString(request));

            await acceptedContext.Stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await acceptedContext.Stream.FlushAsync(cts.Token);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, endPoint.Port, cts.Token);
        await using var clientStream = client.GetStream();
        var baseProfile = RuntimeRealityTls13ClientHelloProfileCatalog.Resolve("hellochrome_120");
        var retryProfile = baseProfile with
        {
            SupportedGroups =
            [
                RuntimeTlsNamedGroups.X25519MLKem768,
                RuntimeTlsNamedGroups.X25519,
                RuntimeTlsNamedGroups.Secp256r1
            ],
            KeyShareGroups =
            [
                RuntimeTlsNamedGroups.X25519
            ]
        };
        var handshakeResult = await new RuntimeRealityTls13Client(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = clientStream,
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = new RuntimeRealityOptions
                    {
                        Fingerprint = "hellochrome_120",
                        PublicKey = ToBase64Url(realityKeyPair.PublicKey),
                        ShortId = "a1b2c3d4"
                    }
                },
                retryProfile)
            .ConnectAsync(cts.Token);

        await using var securedClientStream = handshakeResult.TransportStream;
        await securedClientStream.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await securedClientStream.FlushAsync(cts.Token);

        var response = new byte[4];
        await securedClientStream.ReadExactlyAsync(response, cts.Token);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));

        await serverTask;
    }

    [Fact]
    public async Task SecureAsync_writes_client_master_key_log_when_configured()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var keyLogPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.reality.client.keys.log");

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var endPoint = (IPEndPoint)listener.LocalEndpoint;
            var serverTask = Task.Run(async () =>
            {
                using var serverSocket = await listener.AcceptSocketAsync(cts.Token);
                await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
                var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                    acceptedConnection,
                    new RuntimeRealityServerOptions
                    {
                        ServerNames = ["edge.example.com"],
                        PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                        ShortIds = ["a1b2c3d4"],
                        ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                    },
                    acceptProxyProtocol: false,
                    receiveOriginalDestination: false,
                    applicationProtocols: ["h2"],
                    onClientHelloRejected: null,
                    onUnknownServerNameRejected: null,
                    onEffectiveRemoteEndPointChanged: null,
                    cts.Token);
                Assert.NotNull(accepted);

                await using var acceptedContext = accepted!;
                var request = new byte[4];
                await acceptedContext.Stream.ReadExactlyAsync(request, cts.Token);
                Assert.Equal("ping", Encoding.ASCII.GetString(request));

                await acceptedContext.Stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
                await acceptedContext.Stream.FlushAsync(cts.Token);
            }, cts.Token);

            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, endPoint.Port, cts.Token);
            await using var clientStream = client.GetStream();
            var handshakeResult = await RuntimeRealityHandshakeProviders.Default.SecureAsync(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = clientStream,
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = new RuntimeRealityOptions
                    {
                        Fingerprint = "chrome",
                        PublicKey = ToBase64Url(realityKeyPair.PublicKey),
                        ShortId = "a1b2c3d4",
                        MasterKeyLog = keyLogPath
                    }
                },
                cts.Token);

            await using var securedClientStream = handshakeResult.TransportStream;
            await securedClientStream.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
            await securedClientStream.FlushAsync(cts.Token);

            var response = new byte[4];
            await securedClientStream.ReadExactlyAsync(response, cts.Token);
            Assert.Equal("pong", Encoding.ASCII.GetString(response));

            await serverTask;

            var keyLogLines = await File.ReadAllLinesAsync(keyLogPath, cts.Token);
            Assert.Contains(keyLogLines, static line => line.StartsWith("CLIENT_HANDSHAKE_TRAFFIC_SECRET ", StringComparison.Ordinal));
            Assert.Contains(keyLogLines, static line => line.StartsWith("SERVER_HANDSHAKE_TRAFFIC_SECRET ", StringComparison.Ordinal));
            Assert.Contains(keyLogLines, static line => line.StartsWith("CLIENT_TRAFFIC_SECRET_0 ", StringComparison.Ordinal));
            Assert.Contains(keyLogLines, static line => line.StartsWith("SERVER_TRAFFIC_SECRET_0 ", StringComparison.Ordinal));
        }
        finally
        {
            if (File.Exists(keyLogPath))
            {
                File.Delete(keyLogPath);
            }
        }
    }

    [Fact]
    public async Task AcceptAsync_invalid_short_id_relays_connection_to_configured_fallback()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var realityListener = new TcpListener(IPAddress.Loopback, 0);
        using var fallbackListener = new TcpListener(IPAddress.Loopback, 0);
        realityListener.Start();
        fallbackListener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var realityEndPoint = (IPEndPoint)realityListener.LocalEndpoint;
        var fallbackEndPoint = (IPEndPoint)fallbackListener.LocalEndpoint;

        var fallbackTask = Task.Run(async () =>
        {
            using var fallbackSocket = await fallbackListener.AcceptSocketAsync(cts.Token);
            await using var fallbackConnection = AcceptedConnection.FromTcpSocket(fallbackSocket);
            return await ReadFallbackPayloadAsync(fallbackConnection.Stream, cts.Token);
        }, cts.Token);

        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await realityListener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                new RuntimeRealityServerOptions
                {
                    ServerNames = ["edge.example.com"],
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    ShortIds = ["a1b2c3d4"],
                    Dest = $"127.0.0.1:{fallbackEndPoint.Port}",
                    Type = "tcp",
                    Xver = 1,
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
            Assert.Null(accepted);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, realityEndPoint.Port, cts.Token);
        await using var clientStream = client.GetStream();
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await RuntimeRealityHandshakeProviders.Default.SecureAsync(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = clientStream,
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = new RuntimeRealityOptions
                    {
                        Fingerprint = "chrome",
                        PublicKey = ToBase64Url(realityKeyPair.PublicKey),
                        ShortId = "deadbeef"
                    }
                },
                cts.Token));

        var fallbackPayload = await fallbackTask;
        await serverTask;

        var payloadText = Encoding.ASCII.GetString(fallbackPayload);
        Assert.StartsWith("PROXY TCP4 ", payloadText, StringComparison.Ordinal);

        var headerEnd = payloadText.IndexOf("\r\n", StringComparison.Ordinal);
        Assert.True(headerEnd >= 0);
        Assert.True(fallbackPayload.Length > headerEnd + 2);
        Assert.Equal(0x16, fallbackPayload[headerEnd + 2]);
    }

    [Fact]
    public async Task AcceptAsync_unknown_server_name_relays_connection_to_configured_fallback()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var realityListener = new TcpListener(IPAddress.Loopback, 0);
        using var fallbackListener = new TcpListener(IPAddress.Loopback, 0);
        realityListener.Start();
        fallbackListener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var realityEndPoint = (IPEndPoint)realityListener.LocalEndpoint;
        var fallbackEndPoint = (IPEndPoint)fallbackListener.LocalEndpoint;

        var fallbackTask = Task.Run(async () =>
        {
            using var fallbackSocket = await fallbackListener.AcceptSocketAsync(cts.Token);
            await using var fallbackConnection = AcceptedConnection.FromTcpSocket(fallbackSocket);
            return await ReadFallbackPayloadAsync(fallbackConnection.Stream, cts.Token);
        }, cts.Token);

        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await realityListener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                new RuntimeRealityServerOptions
                {
                    ServerNames = ["edge.example.com"],
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    ShortIds = ["a1b2c3d4"],
                    Dest = $"127.0.0.1:{fallbackEndPoint.Port}",
                    Type = "tcp",
                    Xver = 1,
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
            Assert.Null(accepted);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, realityEndPoint.Port, cts.Token);
        await using var clientStream = client.GetStream();
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await RuntimeRealityHandshakeProviders.Default.SecureAsync(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = clientStream,
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerName = "mismatch.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = new RuntimeRealityOptions
                    {
                        Fingerprint = "chrome",
                        PublicKey = ToBase64Url(realityKeyPair.PublicKey),
                        ShortId = "a1b2c3d4"
                    }
                },
                cts.Token));

        var fallbackPayload = await fallbackTask;
        await serverTask;

        var payloadText = Encoding.ASCII.GetString(fallbackPayload);
        Assert.StartsWith("PROXY TCP4 ", payloadText, StringComparison.Ordinal);

        var headerEnd = payloadText.IndexOf("\r\n", StringComparison.Ordinal);
        Assert.True(headerEnd >= 0);
        Assert.True(fallbackPayload.Length > headerEnd + 2);
        Assert.Equal(0x16, fallbackPayload[headerEnd + 2]);
    }

    [Fact]
    public async Task AcceptAsync_does_not_treat_wildcard_server_name_as_match_like_xtls_reality()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var realityListener = new TcpListener(IPAddress.Loopback, 0);
        using var fallbackListener = new TcpListener(IPAddress.Loopback, 0);
        realityListener.Start();
        fallbackListener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var realityEndPoint = (IPEndPoint)realityListener.LocalEndpoint;
        var fallbackEndPoint = (IPEndPoint)fallbackListener.LocalEndpoint;

        var fallbackTask = Task.Run(async () =>
        {
            using var fallbackSocket = await fallbackListener.AcceptSocketAsync(cts.Token);
            await using var fallbackConnection = AcceptedConnection.FromTcpSocket(fallbackSocket);
            return await ReadFallbackPayloadAsync(fallbackConnection.Stream, cts.Token);
        }, cts.Token);

        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await realityListener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                new RuntimeRealityServerOptions
                {
                    ServerNames = ["*.example.com"],
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    ShortIds = ["a1b2c3d4"],
                    Dest = $"127.0.0.1:{fallbackEndPoint.Port}",
                    Type = "tcp",
                    Xver = 1,
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
            Assert.Null(accepted);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, realityEndPoint.Port, cts.Token);
        await using var clientStream = client.GetStream();
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await RuntimeRealityHandshakeProviders.Default.SecureAsync(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = clientStream,
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = new RuntimeRealityOptions
                    {
                        Fingerprint = "chrome",
                        PublicKey = ToBase64Url(realityKeyPair.PublicKey),
                        ShortId = "a1b2c3d4"
                    }
                },
                cts.Token));

        var fallbackPayload = await fallbackTask;
        await serverTask;

        var payloadText = Encoding.ASCII.GetString(fallbackPayload);
        Assert.StartsWith("PROXY TCP4 ", payloadText, StringComparison.Ordinal);

        var headerEnd = payloadText.IndexOf("\r\n", StringComparison.Ordinal);
        Assert.True(headerEnd >= 0);
        Assert.True(fallbackPayload.Length > headerEnd + 2);
        Assert.Equal(0x16, fallbackPayload[headerEnd + 2]);
    }

    [Fact]
    public async Task AcceptAsync_plain_http_request_relays_connection_to_configured_fallback()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var realityListener = new TcpListener(IPAddress.Loopback, 0);
        using var fallbackListener = new TcpListener(IPAddress.Loopback, 0);
        realityListener.Start();
        fallbackListener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var realityEndPoint = (IPEndPoint)realityListener.LocalEndpoint;
        var fallbackEndPoint = (IPEndPoint)fallbackListener.LocalEndpoint;
        var plainHttpRequest = Encoding.ASCII.GetBytes(
            "GET / HTTP/1.1\r\nHost: edge.example.com\r\nConnection: close\r\n\r\n");

        var fallbackTask = Task.Run(async () =>
        {
            using var fallbackSocket = await fallbackListener.AcceptSocketAsync(cts.Token);
            await using var fallbackConnection = AcceptedConnection.FromTcpSocket(fallbackSocket);
            return await ReadFallbackPayloadUntilContainsAsync(
                fallbackConnection.Stream,
                plainHttpRequest,
                cts.Token);
        }, cts.Token);

        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await realityListener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            var accepted = await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                new RuntimeRealityServerOptions
                {
                    ServerNames = ["edge.example.com"],
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    ShortIds = ["a1b2c3d4"],
                    Dest = $"127.0.0.1:{fallbackEndPoint.Port}",
                    Type = "tcp",
                    Xver = 1,
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
            Assert.Null(accepted);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, realityEndPoint.Port, cts.Token);
        await using (var clientStream = client.GetStream())
        {
            await clientStream.WriteAsync(plainHttpRequest, cts.Token);
            await clientStream.FlushAsync(cts.Token);
        }

        var fallbackPayload = await fallbackTask;
        await serverTask;

        var headerText = Encoding.ASCII.GetString(fallbackPayload);
        Assert.StartsWith("PROXY TCP4 ", headerText, StringComparison.Ordinal);
        Assert.Contains("GET / HTTP/1.1", headerText, StringComparison.Ordinal);
        Assert.Contains("Host: edge.example.com", headerText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AcceptAsync_rejects_client_timestamp_exceeding_configured_max_time_diff()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var endPoint = (IPEndPoint)listener.LocalEndpoint;
        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await listener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                CreateValidServerOptions() with
                {
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    MaxTimeDiffMilliseconds = 1_000,
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, endPoint.Port, cts.Token);
        await using (var clientStream = client.GetStream())
        {
            var protectedClientHello = CreateProtectedClientHello(
                realityKeyPair.PublicKey,
                "a1b2c3d4",
                DateTimeOffset.UtcNow.AddMinutes(-10));
            await clientStream.WriteAsync(protectedClientHello, cts.Token);
            await clientStream.FlushAsync(cts.Token);
        }

        var exception = await Assert.ThrowsAsync<AuthenticationException>(async () => await serverTask);
        Assert.Contains("maxTimeDiff", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AcceptAsync_rejects_client_version_below_configured_minimum()
    {
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var endPoint = (IPEndPoint)listener.LocalEndpoint;
        var serverTask = Task.Run(async () =>
        {
            using var serverSocket = await listener.AcceptSocketAsync(cts.Token);
            await using var acceptedConnection = AcceptedConnection.FromTcpSocket(serverSocket);
            await RealityInboundConnectionAcceptor.AcceptAsync(
                acceptedConnection,
                CreateValidServerOptions() with
                {
                    PrivateKey = ToBase64Url(realityKeyPair.PrivateKey),
                    MinClientVersion = "1.0.0",
                    ClientHelloPolicy = RuntimeTlsClientHelloPolicyOptions.Disabled
                },
                acceptProxyProtocol: false,
                receiveOriginalDestination: false,
                applicationProtocols: ["h2"],
                onClientHelloRejected: null,
                onUnknownServerNameRejected: null,
                onEffectiveRemoteEndPointChanged: null,
                cts.Token);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, endPoint.Port, cts.Token);
        await using (var clientStream = client.GetStream())
        {
            var protectedClientHello = CreateProtectedClientHello(
                realityKeyPair.PublicKey,
                "a1b2c3d4",
                DateTimeOffset.UtcNow,
                plainSessionId =>
                {
                    plainSessionId[0] = 0;
                    plainSessionId[1] = 0;
                    plainSessionId[2] = 0;
                });
            await clientStream.WriteAsync(protectedClientHello, cts.Token);
            await clientStream.FlushAsync(cts.Token);
        }

        var exception = await Assert.ThrowsAsync<AuthenticationException>(async () => await serverTask);
        Assert.Contains("below the configured minimum", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_requires_at_least_one_server_name()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                ServerNames = [" ", "."]
            });

        Assert.Contains("server name", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_requires_valid_private_key()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                PrivateKey = "invalid"
            });

        Assert.Contains("private key", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_requires_at_least_one_short_id()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                ShortIds = []
            });

        Assert.Contains("short id", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_too_long_short_id()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                ShortIds = ["001122334455667788"]
            });

        Assert.Contains("shortIds[0]", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_rejects_invalid_short_id_hex()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                ShortIds = ["zz"]
            });

        Assert.Contains("shortIds[0]", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Create_rejects_matching_mldsa65_seed_and_private_key()
    {
        var options = CreateValidServerOptions();
        var exception = AssertCreateThrows(
            options with
            {
                Mldsa65Seed = options.PrivateKey
            });

        Assert.Contains("ML-DSA-65 seed", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_invalid_mldsa65_seed()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                Mldsa65Seed = "invalid"
            });

        Assert.Contains("ML-DSA-65 seed", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(true, "1.2.3.4")]
    [InlineData(true, "1.256")]
    [InlineData(false, "1.2.3.4")]
    [InlineData(false, "1.256")]
    public void Create_rejects_invalid_client_version(bool minClientVersion, string value)
    {
        var options = minClientVersion
            ? CreateValidServerOptions() with { MinClientVersion = value }
            : CreateValidServerOptions() with { MaxClientVersion = value };

        var exception = AssertCreateThrows(options);
        Assert.Contains(
            minClientVersion
                ? nameof(RuntimeRealityServerOptions.MinClientVersion)
                : nameof(RuntimeRealityServerOptions.MaxClientVersion),
            exception.Message,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Create_rejects_invalid_fallback_xver()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                Dest = "443",
                Xver = 3
            });

        Assert.Contains("xver", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_unsupported_fallback_type()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                Dest = "443",
                Type = "udp"
            });

        Assert.Contains("not supported", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_invalid_fallback_destination()
    {
        var exception = AssertCreateThrows(
            CreateValidServerOptions() with
            {
                Dest = "/tmp/reality.sock",
                Type = "tcp"
            });

        Assert.Contains("destination", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_normalizes_profile_fields_like_xray_core()
    {
        var profile = RuntimeRealityInboundServerProfile.Create(
            CreateValidServerOptions() with
            {
                Show = true,
                MasterKeyLog = "  reality.keys.log  ",
                Dest = "443",
                ServerNames = [" Edge.Example.Com. ", "edge.example.com"],
                MinClientVersion = "1.2",
                MaxClientVersion = "3.4.5",
                ShortIds = ["A1B2C3D4", ""],
                Mldsa65Seed = CreateBase64UrlSeed(101),
                LimitFallbackUpload = new RuntimeFallbackLimitOptions
                {
                    AfterBytes = -1,
                    BytesPerSecond = -2,
                    BurstBytesPerSecond = 3
                },
                LimitFallbackDownload = new RuntimeFallbackLimitOptions
                {
                    AfterBytes = 4,
                    BytesPerSecond = 5,
                    BurstBytesPerSecond = -6
                },
                Xver = 1
            });

        Assert.True(profile.Show);
        Assert.Equal("reality.keys.log", profile.MasterKeyLog);
        Assert.NotNull(profile.Fallback);
        Assert.Equal("tcp", profile.Fallback!.Type);
        Assert.Equal("localhost:443", profile.Fallback.Destination);
        Assert.Equal(1, profile.Fallback.ProxyProtocolVersion);
        Assert.Equal(0, profile.Fallback.LimitUpload.AfterBytes);
        Assert.Equal(0, profile.Fallback.LimitUpload.BytesPerSecond);
        Assert.Equal(3, profile.Fallback.LimitUpload.BurstBytesPerSecond);
        Assert.Equal(4, profile.Fallback.LimitDownload.AfterBytes);
        Assert.Equal(5, profile.Fallback.LimitDownload.BytesPerSecond);
        Assert.Equal(0, profile.Fallback.LimitDownload.BurstBytesPerSecond);
        Assert.Equal(["edge.example.com"], profile.ServerNames);
        Assert.Equal(new byte[] { 1, 2, 0 }, profile.MinClientVersion);
        Assert.Equal(new byte[] { 3, 4, 5 }, profile.MaxClientVersion);
        Assert.Equal(2, profile.ShortIds.Count);
        Assert.Equal(new byte[] { 0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x00, 0x00, 0x00 }, profile.ShortIds[0]);
        Assert.Equal(new byte[8], profile.ShortIds[1]);
        Assert.NotNull(profile.Mldsa65Seed);
        Assert.Equal(32, profile.Mldsa65Seed!.Length);
    }

    [Fact]
    public void Create_treats_none_master_key_log_as_empty_like_xray_core()
    {
        var profile = RuntimeRealityInboundServerProfile.Create(
            CreateValidServerOptions() with
            {
                MasterKeyLog = "  none  "
            });

        Assert.Equal(string.Empty, profile.MasterKeyLog);
    }

    private static string ToBase64Url(byte[] value)
        => Convert
            .ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static RuntimeRealityServerOptions CreateValidServerOptions()
        => new()
        {
            ServerNames = ["edge.example.com"],
            PrivateKey = CreateBase64UrlSeed(1),
            ShortIds = ["a1b2c3d4"]
        };

    private static byte[] CreateProtectedClientHello(
        byte[] serverPublicKey,
        string shortId,
        DateTimeOffset timestamp,
        Action<byte[]>? mutatePlainSessionId = null)
    {
        using var x25519KeyPair = RuntimeX25519.CreateKeyPair();
        var request = new RuntimeRealityHandshakeRequest
        {
            TransportStream = Stream.Null,
            ServerHost = "127.0.0.1",
            ServerName = "edge.example.com",
            TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
            ApplicationProtocols = ["h2"],
            RealityOptions = new RuntimeRealityOptions
            {
                Fingerprint = "hellochrome_120",
                PublicKey = ToBase64Url(serverPublicKey),
                ShortId = shortId
            }
        };
        var profile = RuntimeRealityTls13ClientHelloProfileCatalog.Resolve("hellochrome_120");
        var rawClientHello = RuntimeRealityTls13ClientHelloBuilder.Build(
            request,
            profile,
            new Dictionary<ushort, byte[]>
            {
                [RuntimeTlsNamedGroups.X25519] = x25519KeyPair.PublicKey.ToArray()
            });
        var protectedResult = RuntimeRealityClientHelloProtector.TryProtect(
            rawClientHello,
            x25519KeyPair.PrivateKey,
            request.RealityOptions,
            timestamp,
            out var protectionResult,
            out var error);
        Assert.True(protectedResult, error);
        Assert.NotNull(protectionResult);

        if (mutatePlainSessionId is null)
        {
            return protectionResult!.ProtectedClientHello;
        }

        var plainSessionId = protectionResult!.PlainSessionId.ToArray();
        mutatePlainSessionId(plainSessionId);
        return RewriteProtectedClientHello(protectionResult, plainSessionId);
    }

    private static string CreateBase64UrlSeed(byte seed)
    {
        var bytes = new byte[32];
        for (var index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(seed + index);
        }

        return ToBase64Url(bytes);
    }

    private static InvalidOperationException AssertCreateThrows(RuntimeRealityServerOptions options)
        => Assert.Throws<InvalidOperationException>(() => RuntimeRealityInboundServerProfile.Create(options));

    private static byte[] RewriteProtectedClientHello(
        RuntimeRealityClientHelloProtectionResult protectionResult,
        byte[] plainSessionId)
    {
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(
                protectionResult.ProtectedClientHello,
                out var protectedHello,
                out var error),
            error);
        Assert.NotNull(protectedHello);

        var encryptedSessionId = EncryptSessionId(
            protectionResult.AuthKey,
            protectedHello!.Random.AsSpan(20, 12),
            plainSessionId,
            protectionResult.ZeroSessionIdClientHello.AsSpan(5));
        return protectedHello.Write(encryptedSessionId);
    }

    private static byte[] EncryptSessionId(
        byte[] authKey,
        ReadOnlySpan<byte> nonce,
        byte[] plainSessionId,
        ReadOnlySpan<byte> associatedData)
    {
        var encrypted = new byte[RuntimeRealityClientHelloProtector.EncryptedSessionIdLength];
        using var aead = new AesGcm(
            authKey,
            RuntimeRealityClientHelloProtector.EncryptedSessionIdLength - RuntimeRealityClientHelloProtector.PlainSessionIdLength);
        aead.Encrypt(
            nonce,
            plainSessionId,
            encrypted.AsSpan(0, RuntimeRealityClientHelloProtector.PlainSessionIdLength),
            encrypted.AsSpan(RuntimeRealityClientHelloProtector.PlainSessionIdLength),
            associatedData);
        return encrypted;
    }

    private static async Task<byte[]> ReadFallbackPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var scratch = new byte[1024];
        while (buffer.Length < 1024)
        {
            var read = await stream.ReadAsync(scratch.AsMemory(0, scratch.Length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            buffer.Write(scratch, 0, read);

            var current = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
            var headerEnd = current.IndexOf("\r\n"u8);
            if (headerEnd >= 0 && current.Length > headerEnd + 2)
            {
                break;
            }
        }

        return buffer.ToArray();
    }

    private static async Task<byte[]> ReadFallbackPayloadUntilContainsAsync(
        Stream stream,
        ReadOnlyMemory<byte> expectedPayload,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var scratch = new byte[1024];
        while (buffer.Length < 4096)
        {
            var read = await stream.ReadAsync(scratch.AsMemory(0, scratch.Length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            buffer.Write(scratch, 0, read);

            var current = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
            if (current.IndexOf(expectedPayload.Span) >= 0)
            {
                break;
            }
        }

        return buffer.ToArray();
    }
}

#pragma warning disable SYSLIB0039
using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeInternetProfileTests
{
    [Fact]
    public async Task OpenAsync_accepts_presecured_tls_like_stream_for_reality()
    {
        await using var baseStream = new FakeTlsStream(new MemoryStream());
        var options = CreateRealityOptions();

        var context = await RuntimeInternetProfile.Default.OpenAsync(
            baseStream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            CancellationToken.None);

        Assert.Same(baseStream, context.TransportStream);
        Assert.Same(baseStream, context.ApplicationStream);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
    }

    [Fact]
    public async Task OpenAsync_sends_builtin_reality_client_hello_before_waiting_for_serverhello()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = RealityClientHelloCaptureServer.AcceptOnceAsync(listener, cts.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions() with
        {
            ServerHost = IPAddress.Loopback.ToString(),
            ServerName = "localhost"
        };

        var exception = await Record.ExceptionAsync(() => RuntimeInternetProfile.Default.OpenAsync(
            stream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            cts.Token).AsTask());

        Assert.NotNull(exception);
        Assert.True(exception is EndOfStreamException or IOException, exception.ToString());

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal("localhost", capture.Metadata!.ServerName);
        Assert.Contains("h2", capture.Metadata.ApplicationProtocols);
        Assert.Contains("http/1.1", capture.Metadata.ApplicationProtocols);
        Assert.Contains(0x000B, capture.Metadata.Extensions);
        Assert.Contains(0x0017, capture.Metadata.SupportedGroups);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.True(hello!.SupportsTls13);
        Assert.NotNull(hello.X25519PublicKey);
        Assert.Equal(32, hello.SessionId.Length);
        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Equal(3, keyShares.Count);
        Assert.True(IsGreaseValue(keyShares[0].Group));
        Assert.Equal(RuntimeTlsNamedGroups.X25519MLKem768, keyShares[1].Group);
        Assert.Equal(RuntimeX25519MlKem768.ClientKeyShareLength, keyShares[1].KeyExchange.Length);
        Assert.Equal(0x001D, keyShares[2].Group);
        Assert.Equal(32, keyShares[2].KeyExchange.Length);
        Assert.Contains(
            ParseUInt16Vector(hello.Extensions.Single(static extension => extension.Type == 0x000A).Payload),
            value => value == RuntimeTlsNamedGroups.X25519MLKem768);
        Assert.Contains(ParseUInt16Vector(hello.CipherSuites), IsGreaseValue);
        Assert.Contains(hello.Extensions, static extension => IsGreaseValue(extension.Type));
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x0015);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0x44CD);
        var supportedVersions = hello.Extensions.Single(static extension => extension.Type == 0x002B).Payload;
        Assert.True(supportedVersions.Length >= 3);
        Assert.True(IsGreaseValue((supportedVersions[1] << 8) | supportedVersions[2]));
    }

    [Fact]
    public async Task OpenAsync_progresses_past_serverhello_when_server_selects_secp256r1()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = SendTls13ServerHelloAsync(listener, selectedGroup: 0x0017, cipherSuite: 0x1301, cts.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions() with
        {
            ServerHost = IPAddress.Loopback.ToString(),
            ServerName = "localhost",
            RealityOptions = CreateValidRealityOptions(CreateDefaultRealityPublicKey(), "hellofirefox_120")
        };

        var clientException = await Record.ExceptionAsync(() => RuntimeInternetProfile.Default.OpenAsync(
            stream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            cts.Token).AsTask());

        Assert.NotNull(clientException);
        Assert.True(clientException is EndOfStreamException or IOException, clientException.ToString());
        Assert.Contains("ReceiveServerHandshakeAsync", clientException.StackTrace);
        await serverTask;
    }

    [Fact]
    public async Task OpenAsync_progresses_past_serverhello_when_server_selects_sha384_cipher_suite()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = SendTls13ServerHelloAsync(listener, selectedGroup: 0x001D, cipherSuite: 0x1302, cts.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions() with
        {
            ServerHost = IPAddress.Loopback.ToString(),
            ServerName = "localhost"
        };

        var clientException = await Record.ExceptionAsync(() => RuntimeInternetProfile.Default.OpenAsync(
            stream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            cts.Token).AsTask());

        Assert.NotNull(clientException);
        Assert.True(clientException is EndOfStreamException or IOException, clientException.ToString());
        Assert.Contains("ReceiveServerHandshakeAsync", clientException.StackTrace);
        await serverTask;
    }

    [Theory]
    [InlineData(0x001D, 0x1301)]
    [InlineData(0x0017, 0x1302)]
    public async Task OpenAsync_completes_builtin_reality_handshake_and_exchanges_application_data(
        ushort selectedGroup,
        ushort cipherSuite)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAsync(
            listener,
            selectedGroup,
            cipherSuite,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            RealityOptions = selectedGroup == 0x0017
                ? CreateValidRealityOptions(realityKeyPair.PublicKey, "hellofirefox_120")
                : CreateValidRealityOptions(realityKeyPair.PublicKey)
        };

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);
        Assert.NotNull(context.RemoteCertificate);
        Assert.Equal(RuntimeEd25519.PublicKeyLength, context.RemoteCertificate!.GetPublicKey().Length);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var serverCapture = await serverTask;
        Assert.Equal(serverPayload, serverCapture.ServerApplicationData);
        Assert.Equal(clientPayload, serverCapture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_and_handles_tls13_keyupdate_request()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAsync(
            listener,
            selectedGroup: 0x001D,
            cipherSuite: 0x1301,
            realityPrivateKey: realityKeyPair.PrivateKey,
            cancellationToken: cts.Token,
            sendKeyUpdateRequest: true);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost");

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var serverCapture = await serverTask;
        Assert.Equal(serverPayload, serverCapture.ServerApplicationData);
        Assert.Equal(clientPayload, serverCapture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_with_x25519kyber768draft00()
    {
        if (!RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAsync(
            listener,
            RuntimeTlsNamedGroups.X25519Kyber768Draft00,
            0x1301,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                Fingerprint = "hellochrome_120_pq"
            }
        };

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var serverCapture = await serverTask;
        Assert.Equal(serverPayload, serverCapture.ServerApplicationData);
        Assert.Equal(clientPayload, serverCapture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_with_x25519mlkem768()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAsync(
            listener,
            RuntimeTlsNamedGroups.X25519MLKem768,
            0x1301,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                Fingerprint = "hellochrome_131"
            }
        };

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var serverCapture = await serverTask;
        Assert.Equal(serverPayload, serverCapture.ServerApplicationData);
        Assert.Equal(clientPayload, serverCapture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_with_mldsa65_verification()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var mldsa65 = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAsync(
            listener,
            selectedGroup: 0x001D,
            cipherSuite: 0x1301,
            realityPrivateKey: realityKeyPair.PrivateKey,
            cancellationToken: cts.Token,
            mldsa65PrivateSeed: mldsa65.ExportMLDsaPrivateSeed());

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                Mldsa65Verify = ToBase64Url(mldsa65.ExportMLDsaPublicKey())
            }
        };

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var serverCapture = await serverTask;
        Assert.Equal(serverPayload, serverCapture.ServerApplicationData);
        Assert.Equal(clientPayload, serverCapture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_rejects_real_certificate_fallback_even_when_skip_certificate_validation_is_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls13ServerFlightAndCaptureSpiderAsync(
            listener,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            SkipCertificateValidation = true,
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                SpiderX = "/portal",
                SpiderY = [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 200L, 200L]
            }
        };

        var exception = await Record.ExceptionAsync(() => RuntimeInternetProfile.Default.OpenAsync(
            stream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            cts.Token).AsTask());

        Assert.NotNull(exception);
        Assert.IsType<AuthenticationException>(exception);
        Assert.Contains("REALITY real-certificate fallback validation failed", exception.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(SslPolicyErrors.RemoteCertificateChainErrors), exception.Message, StringComparison.Ordinal);

        await stream.DisposeAsync();
        client.Dispose();

        var serverException = await Record.ExceptionAsync(async () => await serverTask);
        Assert.NotNull(serverException);
        Assert.True(
            serverException is EndOfStreamException or IOException or AuthenticationException,
            serverException.ToString());
    }

    [Fact]
    public async Task OpenAsync_rejects_real_certificate_fallback_without_invoking_certificate_validation_callback()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var callbackInvoked = false;

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls13ServerFlightAndCaptureSpiderAsync(
            listener,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            CertificateValidationCallback = (_sender, _certificate, _chain, _errors) =>
            {
                callbackInvoked = true;
                return true;
            },
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                SpiderX = "/portal",
                SpiderY = [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 200L, 200L]
            }
        };

        var exception = await Record.ExceptionAsync(() => RuntimeInternetProfile.Default.OpenAsync(
            stream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            cts.Token).AsTask());

        Assert.NotNull(exception);
        Assert.IsType<AuthenticationException>(exception);
        Assert.Contains("REALITY real-certificate fallback validation failed", exception.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(SslPolicyErrors.RemoteCertificateChainErrors), exception.Message, StringComparison.Ordinal);
        Assert.False(callbackInvoked);

        await stream.DisposeAsync();
        client.Dispose();

        var serverException = await Record.ExceptionAsync(async () => await serverTask);
        Assert.NotNull(serverException);
        Assert.True(
            serverException is EndOfStreamException or IOException or AuthenticationException,
            serverException.ToString());
    }

    [Fact]
    public async Task ProcessInvalidConnectionAsync_sends_http2_spider_request_before_throwing_processed_invalid_connection()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        const string serverName = "spider-single.invalid";

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureHttp2SpiderRequestAsync(listener, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = new RuntimeRealityOptions
        {
            SpiderX = "/portal",
            SpiderY = [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 200L, 200L]
        };

        var exception = await Record.ExceptionAsync(() => RuntimeRealitySpider.ProcessInvalidConnectionAsync(
            stream,
            serverName,
            options,
            "127.0.0.1:54321",
            cts.Token).AsTask());

        Assert.NotNull(exception);
        Assert.IsType<RuntimeRealityProcessedInvalidConnectionException>(exception);
        Assert.Contains("processed invalid connection", exception.Message, StringComparison.OrdinalIgnoreCase);

        var capture = await serverTask;
        Assert.Equal("/portal", capture.Path);
        Assert.Equal("GET", capture.Headers[":method"]);
        Assert.Equal("https", capture.Headers[":scheme"]);
        Assert.Equal(serverName, capture.Headers[":authority"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, capture.Headers["user-agent"]);
        Assert.Equal("padding=", capture.Headers["cookie"]);
    }

    [Fact]
    public async Task ProcessInvalidConnectionAsync_sends_concurrent_http2_spider_requests_before_throwing_processed_invalid_connection()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        const string serverName = "spider-concurrent.invalid";

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureHttp2SpiderRequestsAsync(
            listener,
            expectedRequestCount: 5,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = new RuntimeRealityOptions
        {
            SpiderX = "/portal",
            SpiderY = [0L, 1L, 2L, 2L, 2L, 2L, 0L, 0L, 200L, 200L]
        };

        var exception = await Record.ExceptionAsync(() => RuntimeRealitySpider.ProcessInvalidConnectionAsync(
            stream,
            serverName,
            options,
            "127.0.0.1:54321",
            cts.Token).AsTask());

        Assert.NotNull(exception);
        Assert.IsType<RuntimeRealityProcessedInvalidConnectionException>(exception);
        Assert.Contains("processed invalid connection", exception.Message, StringComparison.OrdinalIgnoreCase);

        var captures = await serverTask;
        Assert.Equal(5, captures.Count);
        Assert.Equal("/portal", captures[0].Path);
        Assert.All(
            captures,
            capture =>
            {
                Assert.Equal("GET", capture.Headers[":method"]);
                Assert.Equal("https", capture.Headers[":scheme"]);
                Assert.Equal(serverName, capture.Headers[":authority"]);
                Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, capture.Headers["user-agent"]);
                Assert.Equal("padding=", capture.Headers["cookie"]);
            });
        Assert.All(
            captures.Skip(1),
            capture => Assert.True(capture.Headers.ContainsKey("referer")));
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_after_hello_retry_request_from_x25519mlkem768_to_x25519()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAfterHelloRetryRequestAsync(
            listener,
            helloRetryRequestSelectedGroup: RuntimeTlsNamedGroups.X25519,
            finalSelectedGroup: RuntimeTlsNamedGroups.X25519,
            cipherSuite: 0x1301,
            realityPrivateKey: realityKeyPair.PrivateKey,
            cancellationToken: cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                Fingerprint = "hellochrome_131"
            }
        };

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var serverCapture = await serverTask;
        Assert.Equal(serverPayload, serverCapture.ServerApplicationData);
        Assert.Equal(clientPayload, serverCapture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_after_hello_retry_request_for_secp384r1()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAfterHelloRetryRequestAsync(
            listener,
            helloRetryRequestSelectedGroup: 0x0018,
            finalSelectedGroup: 0x0018,
            cipherSuite: 0x1302,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost");

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.Equal(serverPayload, capture.ServerApplicationData);
        Assert.Equal(clientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_with_mldsa65_after_hello_retry_request()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var mldsa65 = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAfterHelloRetryRequestAsync(
            listener,
            helloRetryRequestSelectedGroup: 0x0018,
            finalSelectedGroup: 0x0018,
            cipherSuite: 0x1302,
            realityPrivateKey: realityKeyPair.PrivateKey,
            cancellationToken: cts.Token,
            mldsa65PrivateSeed: mldsa65.ExportMLDsaPrivateSeed());

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost") with
        {
            RealityOptions = CreateValidRealityOptions(realityKeyPair.PublicKey) with
            {
                Mldsa65Verify = ToBase64Url(mldsa65.ExportMLDsaPublicKey())
            }
        };

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.Equal(serverPayload, capture.ServerApplicationData);
        Assert.Equal(clientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_completes_builtin_reality_handshake_after_cookie_only_hello_retry_request()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var realityKeyPair = RuntimeX25519.CreateKeyPair();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteSyntheticTls13ServerFlightAfterHelloRetryRequestAsync(
            listener,
            helloRetryRequestSelectedGroup: 0,
            finalSelectedGroup: 0x001D,
            cipherSuite: 0x1301,
            realityKeyPair.PrivateKey,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateRealityOptions(
            realityKeyPair.PublicKey,
            IPAddress.Loopback.ToString(),
            "localhost");

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.OpenAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Reality),
                options,
                transportInitializationData: null,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);

        await using var securedStream = context.TransportStream;
        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var receivedServerPayload = new byte[serverPayload.Length];
        await ReadExactlyAsync(securedStream, receivedServerPayload, cts.Token);
        Assert.Equal(serverPayload, receivedServerPayload);

        var clientPayload = Encoding.ASCII.GetBytes("client->server");
        await securedStream.WriteAsync(clientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.Equal(serverPayload, capture.ServerApplicationData);
        Assert.Equal(clientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task OpenAsync_uses_runtime_reality_handshake_provider_for_raw_stream()
    {
        var provider = new FakeRealityHandshakeProvider();
        var options = CreateRealityOptions() with
        {
            RealityHandshakeProvider = provider
        };
        await using var rawStream = new MemoryStream();

        var context = await RuntimeInternetProfile.Default.OpenAsync(
            rawStream,
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Reality),
            options,
            transportInitializationData: null,
            CancellationToken.None);

        Assert.True(provider.WasCalled);
        Assert.Same(rawStream, provider.ObservedTransportStream);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.SecurityState.NegotiatedSslProtocol);
        Assert.IsType<FakeTlsStream>(context.TransportStream);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_chrome_fingerprint_completes_handshake_and_exchanges_application_data()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls13ServerFlightAsync(
            listener,
            selectedGroup: 0x001D,
            cipherSuite: 0x1301,
            negotiatedApplicationProtocol: "h2",
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "chrome",
            enabledSslProtocols: SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");
        await using var securedStream = context.TransportStream;
        var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
        Assert.Equal(expectedServerPayload, receivedServerPayload);

        await securedStream.WriteAsync(expectedClientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal(SslProtocols.Tls13, capture.NegotiatedSslProtocol);
        Assert.Equal("h2", capture.NegotiatedApplicationProtocol);
        Assert.Contains("h2", capture.Metadata!.ApplicationProtocols);
        Assert.Contains("http/1.1", capture.Metadata.ApplicationProtocols);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_chrome_fingerprint_handles_tls13_keyupdate_request()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls13ServerFlightAsync(
            listener,
            selectedGroup: 0x001D,
            cipherSuite: 0x1301,
            negotiatedApplicationProtocol: "h2",
            cancellationToken: cts.Token,
            sendKeyUpdateRequest: true);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "chrome",
            enabledSslProtocols: SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");
        await using var securedStream = context.TransportStream;
        var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
        Assert.Equal(expectedServerPayload, receivedServerPayload);

        await securedStream.WriteAsync(expectedClientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_ws_tls_with_chrome_fingerprint_negotiates_http11()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls13ServerFlightAsync(
            listener,
            selectedGroup: 0x001D,
            cipherSuite: 0x1301,
            negotiatedApplicationProtocol: "http/1.1",
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Ws,
            fingerprint: "chrome",
            enabledSslProtocols: SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Ws,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");
        await using var securedStream = context.TransportStream;
        var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
        Assert.Equal(expectedServerPayload, receivedServerPayload);

        await securedStream.WriteAsync(expectedClientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal(SslProtocols.Tls13, capture.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", capture.NegotiatedApplicationProtocol);
        Assert.Equal(["http/1.1"], capture.Metadata!.ApplicationProtocols);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public void CreateClientAuthenticationOptions_disables_tls_resumption_by_default()
    {
        var options = CreateTlsOptions(
            "203.0.113.10",
            "edge.example.com",
            RuntimeInternetTransportProtocols.Tcp,
            "hellogolang",
            SslProtocols.Tls13);

        var sslOptions = RuntimeInternetProfile.CreateClientAuthenticationOptions(
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            options);

        Assert.False(sslOptions.AllowTlsResume);
    }

    [Fact]
    public void CreateClientAuthenticationOptions_honors_explicit_tls_resumption_enablement()
    {
        var options = CreateTlsOptions(
            "203.0.113.10",
            "edge.example.com",
            RuntimeInternetTransportProtocols.Tcp,
            "hellogolang",
            SslProtocols.Tls13) with
        {
            EnableTlsSessionResumption = true
        };

        var sslOptions = RuntimeInternetProfile.CreateClientAuthenticationOptions(
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            options);

        Assert.True(sslOptions.AllowTlsResume);
    }

    [Fact]
    public void CreateClientAuthenticationOptions_propagates_http_outbound_tls_resumption_setting()
    {
        var options = new HttpInternetOptions(
            new RuntimeHttpOutboundOptions
            {
                Tag = "http-out",
                ServerHost = "203.0.113.10",
                ServerPort = 443,
                ServerName = "edge.example.com",
                Transport = HttpOutboundTransports.Tls,
                EnableTlsSessionResumption = true
            });

        var sslOptions = RuntimeInternetProfile.CreateClientAuthenticationOptions(
            RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            options);

        Assert.True(sslOptions.AllowTlsResume);
    }

    [Fact]
    public void Empty_tls_fingerprint_uses_default_chrome_custom_client_branch()
    {
        Assert.False(RuntimeTlsFingerprintCatalog.ShouldUseSslStreamFallback(string.Empty));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldUseCustomClient(string.Empty));
        Assert.False(RuntimeTlsFingerprintCatalog.ShouldUseSslStreamFallback(string.Empty, SslProtocols.Tls12 | SslProtocols.Tls13));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldUseCustomClient(string.Empty, SslProtocols.Tls12 | SslProtocols.Tls13));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldTreatEmptyAsDefaultChrome(SslProtocols.Tls13));
        Assert.False(RuntimeTlsFingerprintCatalog.ShouldUseSslStreamFallback(string.Empty, SslProtocols.Tls13));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldUseCustomClient(string.Empty, SslProtocols.Tls13));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldTreatEmptyAsDefaultChrome(SslProtocols.Tls12));
        Assert.False(RuntimeTlsFingerprintCatalog.ShouldUseSslStreamFallback(string.Empty, SslProtocols.Tls12));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldUseCustomClient(string.Empty, SslProtocols.Tls12));
    }

    [Fact]
    public void Hellogolang_tls_fingerprint_uses_builtin_client_for_mixed_and_tls13_only()
    {
        Assert.False(RuntimeTlsFingerprintCatalog.ShouldUseSslStreamFallback("hellogolang", SslProtocols.Tls12 | SslProtocols.Tls13));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldUseCustomClient("hellogolang", SslProtocols.Tls12 | SslProtocols.Tls13));
        Assert.False(RuntimeTlsFingerprintCatalog.ShouldUseSslStreamFallback("hellogolang", SslProtocols.Tls13));
        Assert.True(RuntimeTlsFingerprintCatalog.ShouldUseCustomClient("hellogolang", SslProtocols.Tls13));
    }

    [Theory]
    [InlineData((int)SslProtocols.Tls13)]
    [InlineData((int)(SslProtocols.Tls12 | SslProtocols.Tls13))]
    [InlineData((int)SslProtocols.Tls12)]
    public async Task SecureAsync_tcp_tls_with_empty_fingerprint_matches_chrome_clienthello_for_enabled_protocols(
        int enabledSslProtocols)
    {
        var emptyCapture = await CaptureNormalTlsClientHelloAsync(
            string.Empty,
            (SslProtocols)enabledSslProtocols,
            RuntimeInternetTransportProtocols.Tcp);
        var chromeCapture = await CaptureNormalTlsClientHelloAsync(
            "chrome",
            (SslProtocols)enabledSslProtocols,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(emptyCapture.Metadata);
        Assert.NotNull(chromeCapture.Metadata);
        Assert.Equal(chromeCapture.Metadata!.CipherSuites, emptyCapture.Metadata!.CipherSuites);
        Assert.Equal(chromeCapture.Metadata.SupportedGroups, emptyCapture.Metadata.SupportedGroups);
        Assert.Equal(chromeCapture.Metadata.ApplicationProtocols, emptyCapture.Metadata.ApplicationProtocols);
        Assert.True(MatchesChromeAutoFingerprint(emptyCapture));
        Assert.True(MatchesChromeAutoFingerprint(chromeCapture));
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hello360_auto_fingerprint_matches_local_utls_360_7_5_shape()
    {
        var autoCapture = await CaptureNormalTlsClientHelloAsync(
            "hello360_auto",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);
        var aliasCapture = await CaptureNormalTlsClientHelloAsync(
            "360",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);
        var explicitCapture = await CaptureNormalTlsClientHelloAsync(
            "hello360_7_5",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(autoCapture.Metadata);
        Assert.NotNull(aliasCapture.Metadata);
        Assert.NotNull(explicitCapture.Metadata);

        Assert.Equal(explicitCapture.Metadata!.Ja3Text, autoCapture.Metadata!.Ja3Text);
        Assert.Equal(explicitCapture.Metadata.Ja3Text, aliasCapture.Metadata!.Ja3Text);
        Assert.Equal(GetExpectedThreeSixty75CipherSuites(), autoCapture.Metadata.CipherSuites);
        Assert.Equal(GetExpectedThreeSixty75Extensions(), autoCapture.Metadata.Extensions);
        Assert.Equal(GetExpectedThreeSixty75SupportedGroups(), autoCapture.Metadata.SupportedGroups);
        Assert.Equal(["spdy/2", "spdy/3", "spdy/3.1", "http/1.1"], autoCapture.Metadata.ApplicationProtocols);
        Assert.Equal(autoCapture.Metadata.CipherSuites, aliasCapture.Metadata.CipherSuites);
        Assert.Equal(autoCapture.Metadata.Extensions, aliasCapture.Metadata.Extensions);
        Assert.Equal(autoCapture.Metadata.SupportedGroups, aliasCapture.Metadata.SupportedGroups);
        Assert.Equal(autoCapture.Metadata.ApplicationProtocols, aliasCapture.Metadata.ApplicationProtocols);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(autoCapture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Equal(0x0303, hello!.LegacyVersion);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x002B);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x0033);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x002D);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 13172);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 30031);
    }

    [Fact]
    public async Task SecureAsync_ws_tls_with_hello360_auto_fingerprint_still_uses_http11_alpn()
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "hello360_auto",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Ws);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(["http/1.1"], capture.Metadata!.ApplicationProtocols);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls13_only_matches_go_default_clienthello()
    {
        var golangCapture = await CaptureNormalTlsClientHelloAsync(
            "hellogolang",
            SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);
        var chromeCapture = await CaptureNormalTlsClientHelloAsync(
            "chrome",
            SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(golangCapture.Metadata);
        Assert.NotNull(chromeCapture.Metadata);
        Assert.Equal(GetExpectedGolangCipherSuites(), golangCapture.Metadata!.CipherSuites);
        Assert.Equal(GetExpectedGolangExtensions(), golangCapture.Metadata.Extensions);
        Assert.Equal(GetExpectedGolangSupportedGroups(), golangCapture.Metadata.SupportedGroups);
        Assert.Empty(golangCapture.Metadata.ApplicationProtocols);
        Assert.NotEqual(chromeCapture.Metadata!.Ja3Text, golangCapture.Metadata.Ja3Text);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(golangCapture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Equal(32, hello!.SessionId.Length);
        Assert.False(IsAllZero(hello.SessionId));

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        if (RuntimeX25519MlKem768.IsSupported)
        {
            Assert.Equal(
                [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519],
                keyShares.Select(static entry => entry.Group).ToArray());
            Assert.True(
                keyShares[0].KeyExchange
                    .AsSpan(keyShares[0].KeyExchange.Length - RuntimeX25519.KeyLength)
                    .SequenceEqual(keyShares[1].KeyExchange));
        }
        else
        {
            Assert.Single(keyShares);
            Assert.Equal(RuntimeTlsNamedGroups.X25519, keyShares[0].Group);
        }
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_tls13_matches_go_mixed_clienthello()
    {
        var golangCapture = await CaptureNormalTlsClientHelloAsync(
            "hellogolang",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(golangCapture.Metadata);
        Assert.Equal(GetExpectedGolangCipherSuites(includeTls12CipherSuites: true), golangCapture.Metadata!.CipherSuites);
        Assert.Equal(GetExpectedGolangExtensions(), golangCapture.Metadata.Extensions);
        Assert.Equal(GetExpectedGolangSupportedGroups(), golangCapture.Metadata.SupportedGroups);
        Assert.Empty(golangCapture.Metadata.ApplicationProtocols);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(golangCapture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);

        var supportedVersionsPayload = hello!.Extensions.Single(static extension => extension.Type == 0x002B).Payload;
        Assert.Equal(4, supportedVersionsPayload[0]);
        Assert.Equal(new byte[] { 0x03, 0x04, 0x03, 0x03 }, supportedVersionsPayload.AsSpan(1, 4).ToArray());
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_only_matches_go_tls12_clienthello()
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "hellogolang",
            SslProtocols.Tls12,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(GetExpectedGolangTls12CipherSuites(), capture.Metadata!.CipherSuites);
        Assert.Equal(GetExpectedGolangTls12Extensions(), capture.Metadata.Extensions);
        Assert.Equal(GetExpectedGolangTls12SupportedGroups(), capture.Metadata.SupportedGroups);
        Assert.Empty(capture.Metadata.ApplicationProtocols);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.DoesNotContain(hello!.Extensions, static extension => extension.Type == 0x0033);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x002D);

        var supportedVersionsPayload = hello.Extensions.Single(static extension => extension.Type == 0x002B).Payload;
        Assert.Equal(2, supportedVersionsPayload[0]);
        Assert.Equal(new byte[] { 0x03, 0x03 }, supportedVersionsPayload.AsSpan(1, 2).ToArray());
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_randomized_fingerprint_and_tls13_only_is_process_stable()
    {
        var firstCapture = await CaptureNormalTlsClientHelloAsync(
            "randomized",
            SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);
        var secondCapture = await CaptureNormalTlsClientHelloAsync(
            "randomized",
            SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(firstCapture.Metadata);
        Assert.NotNull(secondCapture.Metadata);
        Assert.Equal(firstCapture.Metadata!.Ja3Text, secondCapture.Metadata!.Ja3Text);
        Assert.Equal(firstCapture.Metadata.CipherSuites, secondCapture.Metadata.CipherSuites);
        Assert.Equal(firstCapture.Metadata.Extensions, secondCapture.Metadata.Extensions);
        Assert.Equal(firstCapture.Metadata.SupportedGroups, secondCapture.Metadata.SupportedGroups);
        Assert.Equal(["h2", "http/1.1"], firstCapture.Metadata.ApplicationProtocols);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(firstCapture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Contains(hello!.Extensions, static extension => extension.Type == 0x002B);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0x0033);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0x002D);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_randomizednoalpn_fingerprint_and_tls13_only_omits_alpn_extension()
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "randomizednoalpn",
            SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Empty(capture.Metadata!.ApplicationProtocols);
        Assert.DoesNotContain(0x0010, capture.Metadata.Extensions);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Contains(hello!.Extensions, static extension => extension.Type == 0x002B);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0x0033);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0x002D);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_random_fingerprint_matches_xray_core_modern_set()
    {
        var firstCapture = await CaptureNormalTlsClientHelloAsync(
            "random",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);
        var secondCapture = await CaptureNormalTlsClientHelloAsync(
            "random",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(firstCapture.Metadata);
        Assert.NotNull(secondCapture.Metadata);
        Assert.Equal(firstCapture.Metadata!.CipherSuites, secondCapture.Metadata!.CipherSuites);
        Assert.Equal(firstCapture.Metadata.SupportedGroups, secondCapture.Metadata.SupportedGroups);
        Assert.Equal(firstCapture.Metadata.ApplicationProtocols, secondCapture.Metadata.ApplicationProtocols);

        var firstMatchedFingerprint = await IdentifyModernFingerprintAsync(firstCapture);
        var secondMatchedFingerprint = await IdentifyModernFingerprintAsync(secondCapture);

        Assert.False(string.IsNullOrWhiteSpace(firstMatchedFingerprint), "The first `random` fingerprint capture did not match any xray-core modern fingerprint shape.");
        Assert.False(string.IsNullOrWhiteSpace(secondMatchedFingerprint), "The second `random` fingerprint capture did not match any xray-core modern fingerprint shape.");
        Assert.Equal(firstMatchedFingerprint, secondMatchedFingerprint);

        if (!AllowsModernFingerprintOrderVariance(firstMatchedFingerprint!))
        {
            Assert.Equal(firstCapture.Metadata.Ja3Text, secondCapture.Metadata.Ja3Text);
            Assert.Equal(firstCapture.Metadata.Extensions, secondCapture.Metadata.Extensions);
        }
    }

    [Theory]
    [InlineData("hellochrome_106_shuffle")]
    [InlineData("hellochrome_100_psk")]
    [InlineData("hellochrome_112_psk_shuf")]
    [InlineData("hellochrome_114_padding_psk_shuf")]
    [InlineData("hellochrome_115_pq")]
    [InlineData("hellochrome_115_pq_psk")]
    [InlineData("hellochrome_120")]
    [InlineData("hellochrome_120_pq")]
    [InlineData("hellochrome_131")]
    public async Task SecureAsync_tcp_tls_with_modern_chrome_fingerprint_matches_local_utls_extension_shape(
        string fingerprint)
    {
        if (RequiresX25519Kyber768Draft00(fingerprint) &&
            !RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        var capture = await CaptureNormalTlsClientHelloAsync(
            fingerprint,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.True(
            MatchesChromeFingerprintShape(capture, fingerprint),
            $"The captured ClientHello did not match the expected local uTLS shape for '{fingerprint}'.");
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls13_only_completes_handshake_and_exchanges_application_data()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var selectedGroup = RuntimeX25519MlKem768.IsSupported
            ? RuntimeTlsNamedGroups.X25519MLKem768
            : RuntimeTlsNamedGroups.X25519;
        var serverTask = CompleteRealCertificateTls13ServerFlightAsync(
            listener,
            selectedGroup,
            cipherSuite: 0x1301,
            negotiatedApplicationProtocol: "h2",
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");
        await using var securedStream = context.TransportStream;
        var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
        Assert.Equal(expectedServerPayload, receivedServerPayload);

        await securedStream.WriteAsync(expectedClientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal(GetExpectedGolangCipherSuites(), capture.Metadata!.CipherSuites);
        Assert.Equal(GetExpectedGolangExtensions(), capture.Metadata.Extensions);
        Assert.Equal(GetExpectedGolangSupportedGroups(), capture.Metadata.SupportedGroups);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls13_only_handles_optional_client_certificate_request()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var selectedGroup = RuntimeX25519MlKem768.IsSupported
            ? RuntimeTlsNamedGroups.X25519MLKem768
            : RuntimeTlsNamedGroups.X25519;
        var serverTask = CompleteRealCertificateTls13ServerFlightAsync(
            listener,
            selectedGroup,
            cipherSuite: 0x1301,
            negotiatedApplicationProtocol: "h2",
            cancellationToken: cts.Token,
            requestClientCertificate: true);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
        Assert.Equal("h2", context.NegotiatedApplicationProtocol);

        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");
        await using var securedStream = context.TransportStream;
        var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
        Assert.Equal(expectedServerPayload, receivedServerPayload);

        await securedStream.WriteAsync(expectedClientPayload, cts.Token);
        await securedStream.FlushAsync(cts.Token);

        var capture = await serverTask;
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_only_completes_handshake_and_exchanges_application_data()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite: 0xC02F,
            selectedGroup: RuntimeTlsNamedGroups.X25519,
            negotiatedApplicationProtocol: "http/1.1",
            certificateKind: Tls12ServerCertificateKind.Rsa,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls12);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls12, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);
        Assert.NotNull(context.RemoteCertificate);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal(SslProtocols.Tls12, capture.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", capture.NegotiatedApplicationProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_tls13_completes_tls12_handshake_when_server_selects_tls12()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite: 0xC02F,
            selectedGroup: RuntimeTlsNamedGroups.X25519,
            negotiatedApplicationProtocol: "http/1.1",
            certificateKind: Tls12ServerCertificateKind.Rsa,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
        Assert.Equal(SslProtocols.Tls12, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.NotNull(capture.Metadata);
        Assert.Equal(GetExpectedGolangCipherSuites(includeTls12CipherSuites: true), capture.Metadata!.CipherSuites);
        Assert.Equal(SslProtocols.Tls12, capture.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", capture.NegotiatedApplicationProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Theory]
    [InlineData(0xC030, RuntimeTlsNamedGroups.X25519, false)]
    [InlineData(0xCCA8, RuntimeTlsNamedGroups.X25519, false)]
    [InlineData(0xC02B, RuntimeTlsNamedGroups.Secp256r1, true)]
    [InlineData(0xCCA9, RuntimeTlsNamedGroups.Secp256r1, true)]
    [InlineData(0xC013, RuntimeTlsNamedGroups.X25519, false)]
    [InlineData(0xC014, RuntimeTlsNamedGroups.X25519, false)]
    [InlineData(0xC009, RuntimeTlsNamedGroups.Secp256r1, true)]
    [InlineData(0xC00A, RuntimeTlsNamedGroups.Secp256r1, true)]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_only_supports_additional_tls12_server_choices(
        ushort cipherSuite,
        ushort selectedGroup,
        bool useEcdsaCertificate)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite,
            selectedGroup,
            negotiatedApplicationProtocol: "http/1.1",
            certificateKind: useEcdsaCertificate ? Tls12ServerCertificateKind.Ecdsa : Tls12ServerCertificateKind.Rsa,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls12);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(SslProtocols.Tls12, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal(SslProtocols.Tls12, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Theory]
    [InlineData("firefox", 0x009C, 0, (int)Tls12ServerCertificateKind.Rsa)]
    [InlineData("firefox", 0x009D, 0, (int)Tls12ServerCertificateKind.Rsa)]
    [InlineData("firefox", 0x002F, 0, (int)Tls12ServerCertificateKind.Rsa)]
    [InlineData("firefox", 0x0035, 0, (int)Tls12ServerCertificateKind.Rsa)]
    [InlineData("safari", 0xC008, RuntimeTlsNamedGroups.Secp256r1, (int)Tls12ServerCertificateKind.Ecdsa)]
    [InlineData("safari", 0xC012, RuntimeTlsNamedGroups.X25519, (int)Tls12ServerCertificateKind.Rsa)]
    [InlineData("safari", 0x000A, 0, (int)Tls12ServerCertificateKind.Rsa)]
    public async Task SecureAsync_tcp_tls_with_browser_fingerprint_and_tls12_only_supports_advertised_legacy_server_choices(
        string fingerprint,
        ushort cipherSuite,
        ushort selectedGroup,
        int certificateKind)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite,
            selectedGroup,
            negotiatedApplicationProtocol: "http/1.1",
            (Tls12ServerCertificateKind)certificateKind,
            cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: fingerprint,
            enabledSslProtocols: SslProtocols.Tls12);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(SslProtocols.Tls12, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal(SslProtocols.Tls12, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Theory]
    [InlineData(0xC02F, RuntimeTlsNamedGroups.X25519, (int)Tls12ServerCertificateKind.Rsa, 0x0201)]
    [InlineData(0xC02B, RuntimeTlsNamedGroups.Secp256r1, (int)Tls12ServerCertificateKind.Ecdsa, 0x0203)]
    [InlineData(0xC02B, RuntimeTlsNamedGroups.Secp256r1, (int)Tls12ServerCertificateKind.Ed25519, 0x0807)]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_only_supports_additional_tls12_server_signature_algorithms(
        ushort cipherSuite,
        ushort selectedGroup,
        int certificateKind,
        ushort signatureAlgorithm)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite,
            selectedGroup,
            negotiatedApplicationProtocol: "http/1.1",
            (Tls12ServerCertificateKind)certificateKind,
            cts.Token,
            signatureAlgorithm);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls12);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            throw;
        }

        Assert.Equal(SslProtocols.Tls12, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal(SslProtocols.Tls12, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_hellogolang_fingerprint_and_tls12_only_handles_optional_client_certificate_request()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite: 0xC02F,
            selectedGroup: RuntimeTlsNamedGroups.X25519,
            negotiatedApplicationProtocol: "http/1.1",
            certificateKind: Tls12ServerCertificateKind.Rsa,
            cancellationToken: cts.Token,
            requestClientCertificate: true);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellogolang",
            enabledSslProtocols: SslProtocols.Tls12);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(SslProtocols.Tls12, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal(SslProtocols.Tls12, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Theory]
    [InlineData(0xC009)]
    [InlineData(0xC00A)]
    [InlineData(0xC013)]
    [InlineData(0xC014)]
    public void RuntimeTls12TrafficProtector_cbc_rejects_records_with_tampered_explicit_iv(ushort cipherSuiteId)
    {
        var cipherSuite = RuntimeTls12CipherSuite.Resolve(cipherSuiteId);
        var key = Enumerable.Range(1, cipherSuite.KeyLength)
            .Select(static value => (byte)value)
            .ToArray();
        var iv = Enumerable.Range(65, cipherSuite.IvLength)
            .Select(static value => (byte)value)
            .ToArray();
        var macKey = Enumerable.Range(129, cipherSuite.MacKeyLength)
            .Select(static value => (byte)value)
            .ToArray();

        using var encryptor = RuntimeTls12TrafficProtector.Create(cipherSuite, key, iv, macKey);
        var record = encryptor.Encrypt(
            RuntimeTls13RecordType.ApplicationData,
            Encoding.ASCII.GetBytes("tls12-cbc-auth-check"));
        var payload = record.AsSpan(5).ToArray();
        payload[0] ^= 0x01;

        using var decryptor = RuntimeTls12TrafficProtector.Create(cipherSuite, key, iv, macKey);
        Assert.Throws<AuthenticationException>(() =>
            decryptor.Decrypt(RuntimeTls13RecordType.ApplicationData, payload));
    }

    [Theory]
    [InlineData(0xC009)]
    [InlineData(0xC00A)]
    [InlineData(0xC013)]
    [InlineData(0xC014)]
    public void RuntimeTls12TrafficProtector_cbc_rejects_records_with_tampered_padding_block(ushort cipherSuiteId)
    {
        var cipherSuite = RuntimeTls12CipherSuite.Resolve(cipherSuiteId);
        var key = Enumerable.Range(1, cipherSuite.KeyLength)
            .Select(static value => (byte)value)
            .ToArray();
        var iv = Enumerable.Range(65, cipherSuite.IvLength)
            .Select(static value => (byte)value)
            .ToArray();
        var macKey = Enumerable.Range(129, cipherSuite.MacKeyLength)
            .Select(static value => (byte)value)
            .ToArray();

        using var encryptor = RuntimeTls12TrafficProtector.Create(cipherSuite, key, iv, macKey);
        var record = encryptor.Encrypt(
            RuntimeTls13RecordType.ApplicationData,
            Encoding.ASCII.GetBytes("tls12-cbc-padding-check"));
        var payload = record.AsSpan(5).ToArray();
        payload[^1] ^= 0x01;

        using var decryptor = RuntimeTls12TrafficProtector.Create(cipherSuite, key, iv, macKey);
        Assert.Throws<AuthenticationException>(() =>
            decryptor.Decrypt(RuntimeTls13RecordType.ApplicationData, payload));
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_unknown_fingerprint_throws_argument_exception()
    {
        await using var stream = new MemoryStream();
        var options = CreateTlsOptions(
            "example.com",
            "example.com",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "not-a-browser",
            enabledSslProtocols: SslProtocols.Tls13);

        var exception = await Assert.ThrowsAsync<ArgumentException>(async () =>
            await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                CancellationToken.None));

        Assert.Contains("fingerprint", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not-a-browser", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_fingerprint_and_tls13_disabled_uses_builtin_tls12_clienthello()
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "chrome",
            SslProtocols.Tls12,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Contains(0x002B, capture.Metadata!.Extensions);
        Assert.DoesNotContain(0x0033, capture.Metadata.Extensions);
        Assert.DoesNotContain(0x002D, capture.Metadata.Extensions);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);

        var supportedVersionsPayload = hello!.Extensions.Single(static extension => extension.Type == 0x002B).Payload;
        Assert.Equal(4, supportedVersionsPayload[0]);
        Assert.True(IsGreaseValue((supportedVersionsPayload[1] << 8) | supportedVersionsPayload[2]));
        Assert.Equal(new byte[] { 0x03, 0x03 }, supportedVersionsPayload.AsSpan(3, 2).ToArray());
    }

    [Theory]
    [InlineData((int)SslProtocols.Tls11, 0x0302)]
    [InlineData((int)SslProtocols.Tls, 0x0301)]
    public async Task SecureAsync_tcp_tls_with_explicit_browser_fingerprint_and_legacy_only_protocols_constrains_clienthello(
        int enabledSslProtocols,
        int expectedLegacyVersion)
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "hellosafari_16_0",
            (SslProtocols)enabledSslProtocols,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(expectedLegacyVersion, capture.Metadata!.LegacyVersion);
        Assert.Contains(0x002B, capture.Metadata.Extensions);
        Assert.DoesNotContain(0x0033, capture.Metadata.Extensions);
        Assert.DoesNotContain(0x002D, capture.Metadata.Extensions);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);

        var supportedVersionsExtension = hello!.Extensions.Single(static extension => extension.Type == 0x002B);
        var actualSupportedVersions = ParseSupportedVersions(supportedVersionsExtension.Payload);
        Assert.NotEmpty(actualSupportedVersions);
        if (IsGreaseValue(actualSupportedVersions[0]))
        {
            actualSupportedVersions = actualSupportedVersions[1..];
        }

        int[] expectedSupportedVersions = expectedLegacyVersion == 0x0302
            ? [0x0302, 0x0301]
            : [expectedLegacyVersion];
        Assert.Equal(expectedSupportedVersions, actualSupportedVersions);
    }

    [Theory]
    [InlineData("helloedge_85")]
    [InlineData("hellochrome_120")]
    [InlineData("hellochrome_131")]
    [InlineData("helloedge_106")]
    [InlineData("helloios_14")]
    [InlineData("hello360_11_0")]
    [InlineData("helloqq_11_1")]
    [InlineData("hellofirefox_120")]
    [InlineData("hellosafari_16_0")]
    public async Task SecureAsync_tcp_tls_with_explicit_browser_fingerprint_matches_local_utls_cipher_suites_and_keyshare_shape(
        string fingerprint)
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            fingerprint,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(GetExpectedExplicitBrowserCipherSuites(fingerprint), capture.Metadata!.CipherSuites);
        Assert.Equal(GetExpectedExplicitBrowserSupportedGroups(fingerprint), capture.Metadata.SupportedGroups);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Equal(32, hello!.SessionId.Length);
        Assert.False(IsAllZero(hello.SessionId));

        var keyShareExtension = hello.Extensions.SingleOrDefault(static extension => extension.Type == 0x0033);
        Assert.NotNull(keyShareExtension);
        var keyShares = ParseKeyShares(keyShareExtension.Payload);
        var actualKeyShareGroups = keyShares.Select(static entry => (int)entry.Group).ToArray();
        if (ExpectedExplicitBrowserKeyShareIncludesGrease(fingerprint))
        {
            Assert.NotEmpty(actualKeyShareGroups);
            Assert.True(IsGreaseValue(actualKeyShareGroups[0]));
            actualKeyShareGroups = actualKeyShareGroups[1..];
        }

        Assert.Equal(GetExpectedExplicitBrowserKeyShareGroups(fingerprint), actualKeyShareGroups);

        var supportedVersionsExtension = hello.Extensions.SingleOrDefault(static extension => extension.Type == 0x002B);
        Assert.NotNull(supportedVersionsExtension);
        var actualSupportedVersions = ParseSupportedVersions(supportedVersionsExtension!.Payload);
        if (ExpectedExplicitBrowserSupportedVersionsIncludeGrease(fingerprint))
        {
            Assert.NotEmpty(actualSupportedVersions);
            Assert.True(IsGreaseValue(actualSupportedVersions[0]));
            actualSupportedVersions = actualSupportedVersions[1..];
        }

        Assert.Equal(GetExpectedExplicitBrowserSupportedVersions(fingerprint), actualSupportedVersions);

        if (string.Equals(fingerprint, "hello360_11_0", StringComparison.Ordinal))
        {
            Assert.Contains(hello.Extensions, static extension => extension.Type == 30032);
        }

        if (string.Equals(fingerprint, "helloqq_11_1", StringComparison.Ordinal))
        {
            Assert.Contains(hello.Extensions, static extension => extension.Type == 17513);
        }

        if (string.Equals(fingerprint, "helloios_14", StringComparison.Ordinal))
        {
            Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x001B);
        }
    }

    [Theory]
    [InlineData("hellochrome_58")]
    [InlineData("hellochrome_62")]
    [InlineData("hellochrome_70")]
    [InlineData("hellochrome_72")]
    [InlineData("hellochrome_83")]
    [InlineData("hellochrome_87")]
    [InlineData("hellochrome_96")]
    [InlineData("hellochrome_100")]
    [InlineData("hellochrome_102")]
    public async Task SecureAsync_tcp_tls_with_legacy_chrome_browser_fingerprint_matches_local_utls_shape(
        string fingerprint)
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            fingerprint,
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(GetExpectedLegacyChromeCipherSuites(fingerprint), capture.Metadata!.CipherSuites);
        Assert.Equal(GetExpectedLegacyChromeSupportedGroups(fingerprint), capture.Metadata.SupportedGroups);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Equal(32, hello!.SessionId.Length);
        Assert.False(IsAllZero(hello.SessionId));

        var actualExtensionTypes = hello.Extensions
            .Select(static extension => NormalizeGreaseValue(extension.Type))
            .ToArray();
        Assert.Equal(GetExpectedLegacyChromeExtensionTypes(fingerprint), actualExtensionTypes);

        var keyShareExtension = hello.Extensions.SingleOrDefault(static extension => extension.Type == 0x0033);
        if (GetExpectedLegacyChromeKeyShareGroups(fingerprint).Count == 0)
        {
            Assert.Null(keyShareExtension);
        }
        else
        {
            Assert.NotNull(keyShareExtension);
            var keyShares = ParseKeyShares(keyShareExtension!.Payload);
            Assert.NotEmpty(keyShares);
            Assert.True(IsGreaseValue(keyShares[0].Group));
            var actualKeyShareGroups = keyShares
                .Skip(1)
                .Select(static entry => (int)entry.Group)
                .ToArray();
            Assert.Equal(GetExpectedLegacyChromeKeyShareGroups(fingerprint), actualKeyShareGroups);
        }

        var supportedVersionsExtension = hello.Extensions.SingleOrDefault(static extension => extension.Type == 0x002B);
        if (GetExpectedLegacyChromeSupportedVersions(fingerprint).Count == 0)
        {
            Assert.Null(supportedVersionsExtension);
        }
        else
        {
            Assert.NotNull(supportedVersionsExtension);
            var actualSupportedVersions = ParseSupportedVersions(supportedVersionsExtension!.Payload);
            Assert.NotEmpty(actualSupportedVersions);
            Assert.True(IsGreaseValue(actualSupportedVersions[0]));
            Assert.Equal(
                GetExpectedLegacyChromeSupportedVersions(fingerprint),
                actualSupportedVersions[1..]);
        }

        var signatureAlgorithmsExtension = hello.Extensions.Single(static extension => extension.Type == 0x000D);
        Assert.True(signatureAlgorithmsExtension.Payload.Length >= 2);
        Assert.Equal(
            GetExpectedLegacyChromeSignatureAlgorithms(fingerprint),
            ParseUInt16Vector(signatureAlgorithmsExtension.Payload.AsSpan(2)));
    }

    [Theory]
    [InlineData(0x0302, (int)SslProtocols.Tls11)]
    [InlineData(0x0301, (int)SslProtocols.Tls)]
    public async Task SecureAsync_tcp_tls_with_explicit_browser_fingerprint_and_tls12_tls13_completes_legacy_rsa_handshake(
        ushort selectedVersion,
        int expectedProtocol)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite: 0x002F,
            selectedGroup: 0,
            negotiatedApplicationProtocol: "http/1.1",
            certificateKind: Tls12ServerCertificateKind.Rsa,
            cancellationToken: cts.Token,
            selectedVersion: selectedVersion);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            "helloedge_85",
            SslProtocols.Tls12 | SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal((SslProtocols)expectedProtocol, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal((SslProtocols)expectedProtocol, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Theory]
    [InlineData(0xC013, RuntimeTlsNamedGroups.X25519, (int)Tls12ServerCertificateKind.Rsa)]
    [InlineData(0xC009, RuntimeTlsNamedGroups.Secp256r1, (int)Tls12ServerCertificateKind.Ecdsa)]
    public async Task SecureAsync_tcp_tls_with_explicit_browser_fingerprint_supports_tls11_legacy_ecdhe_signatures(
        ushort cipherSuite,
        ushort selectedGroup,
        int certificateKind)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            cipherSuite,
            selectedGroup,
            negotiatedApplicationProtocol: "http/1.1",
            (Tls12ServerCertificateKind)certificateKind,
            cts.Token,
            selectedVersion: 0x0302);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellosafari_16_0",
            enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        Assert.Equal(SslProtocols.Tls11, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal(SslProtocols.Tls11, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Theory]
    [InlineData((int)SslProtocols.Tls11, 0x0302)]
    [InlineData((int)SslProtocols.Tls, 0x0301)]
    public async Task SecureAsync_tcp_tls_with_explicit_browser_fingerprint_and_legacy_only_protocols_completes_legacy_rsa_handshake(
        int enabledSslProtocols,
        ushort selectedVersion)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteRealCertificateTls12ServerFlightAsync(
            listener,
            0x002F,
            RuntimeTlsNamedGroups.X25519,
            negotiatedApplicationProtocol: "http/1.1",
            Tls12ServerCertificateKind.Rsa,
            cts.Token,
            selectedVersion: selectedVersion);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            RuntimeInternetTransportProtocols.Tcp,
            fingerprint: "hellosafari_16_0",
            enabledSslProtocols: (SslProtocols)enabledSslProtocols);

        RuntimeInternetConnectionContext context;
        try
        {
            context = await RuntimeInternetProfile.Default.SecureAsync(
                stream,
                RuntimeInternetStack.Create(
                    RuntimeInternetTransportProtocols.Tcp,
                    RuntimeInternetSecurityTypes.Tls),
                options,
                cts.Token);
        }
        catch
        {
            await serverTask;
            throw;
        }

        var expectedProtocol = ResolveLegacySslProtocol(selectedVersion);
        Assert.Equal(expectedProtocol, context.NegotiatedSslProtocol);
        Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);

        var securedStream = context.TransportStream;
        var expectedServerPayload = Encoding.ASCII.GetBytes("server->client");
        var expectedClientPayload = Encoding.ASCII.GetBytes("client->server");

        try
        {
            var receivedServerPayload = await ReadExactBytesAsync(securedStream, expectedServerPayload.Length, cts.Token);
            Assert.Equal(expectedServerPayload, receivedServerPayload);

            await securedStream.WriteAsync(expectedClientPayload, cts.Token);
            await securedStream.FlushAsync(cts.Token);
        }
        finally
        {
            await securedStream.DisposeAsync();
        }

        var capture = await serverTask;
        Assert.Equal(expectedProtocol, capture.NegotiatedSslProtocol);
        Assert.Equal(expectedServerPayload, capture.ServerApplicationData);
        Assert.Equal(expectedClientPayload, capture.ClientApplicationData);
    }

    [Fact]
    public async Task SecureAsync_tcp_tls_with_explicit_android_fingerprint_matches_local_utls_legacy_tls12_shape()
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "helloandroid_11_okhttp",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            RuntimeInternetTransportProtocols.Tcp);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(
            new[]
            {
                0xC02B, 0xC02C, 0xCCA9,
                0xC02F, 0xC030, 0xCCA8,
                0xC013, 0xC014,
                0x009C, 0x009D,
                0x002F, 0x0035
            },
            capture.Metadata!.CipherSuites.Select(static cipherSuite => (int)cipherSuite).ToArray());
        Assert.Equal(
            new[]
            {
                (int)RuntimeTlsNamedGroups.X25519,
                (int)RuntimeTlsNamedGroups.Secp256r1,
                (int)RuntimeTlsNamedGroups.Secp384r1
            },
            capture.Metadata.SupportedGroups.Select(static supportedGroup => (int)supportedGroup).ToArray());

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.DoesNotContain(hello!.Extensions, static extension => extension.Type == 0x0010);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x002B);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x0033);
    }

    [Theory]
    [InlineData(RuntimeInternetTransportProtocols.Ws)]
    [InlineData(RuntimeInternetTransportProtocols.HttpUpgrade)]
    public async Task SecureAsync_ws_like_tls_with_explicit_android_fingerprint_injects_http11_alpn_even_without_profile_alpn_extension(
        string transportProtocol)
    {
        var capture = await CaptureNormalTlsClientHelloAsync(
            "helloandroid_11_okhttp",
            SslProtocols.Tls12 | SslProtocols.Tls13,
            transportProtocol);

        Assert.NotNull(capture.Metadata);
        Assert.Equal(["http/1.1"], capture.Metadata!.ApplicationProtocols);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var hello, out var error);
        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.Contains(hello!.Extensions, static extension => extension.Type == 0x0010);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x002B);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0x0033);
    }

    private static VlessClientOptions CreateRealityOptions()
        => CreateRealityOptions(CreateDefaultRealityPublicKey(), "example.com", "example.com");

    private static VlessClientOptions CreateRealityOptions(
        byte[] realityPublicKey,
        string serverHost,
        string serverName)
        => new()
        {
            ServerHost = serverHost,
            ServerName = serverName,
            TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
            SecurityType = RuntimeInternetSecurityTypes.Reality,
            RealityOptions = CreateValidRealityOptions(realityPublicKey)
        };

    private static VlessClientOptions CreateTlsOptions(
        string serverHost,
        string serverName,
        string transportProtocol,
        string fingerprint,
        SslProtocols enabledSslProtocols)
        => new()
        {
            ServerHost = serverHost,
            ServerName = serverName,
            TransportProtocol = transportProtocol,
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            Fingerprint = fingerprint,
            SkipCertificateValidation = true,
            EnabledSslProtocols = enabledSslProtocols
        };

    private static async Task<RealityClientHelloCapture> CaptureNormalTlsClientHelloAsync(
        string fingerprint,
        SslProtocols enabledSslProtocols,
        string transportProtocol)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = RealityClientHelloCaptureServer.AcceptOnceAsync(listener, cts.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var stream = client.GetStream();
        var options = CreateTlsOptions(
            IPAddress.Loopback.ToString(),
            "localhost",
            transportProtocol,
            fingerprint,
            enabledSslProtocols);

        var exception = await Record.ExceptionAsync(() => RuntimeInternetProfile.Default.SecureAsync(
            stream,
            RuntimeInternetStack.Create(
                transportProtocol,
                RuntimeInternetSecurityTypes.Tls),
            options,
            cts.Token).AsTask());

        Assert.NotNull(exception);
        Assert.True(exception is EndOfStreamException or IOException, exception.ToString());

        return await serverTask;
    }

    private static async Task SendLegacyTlsServerHelloOnlyAsync(
        TcpListener listener,
        ushort selectedVersion,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out var error),
            error);
        Assert.NotNull(hello);

        var serverHello = BuildTls12ServerHelloMessage(
            hello!.SessionId,
            Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
            0x002F,
            negotiatedApplicationProtocol: string.Empty,
            selectedVersion);
        await WriteTls12PlaintextRecordAsync(
                stream,
                RuntimeTls13RecordType.Handshake,
                serverHello,
                selectedVersion,
                cancellationToken)
            ;
    }

    private static RuntimeRealityOptions CreateValidRealityOptions(byte[] publicKey)
        => new()
        {
            Fingerprint = "chrome",
            PublicKey = ToBase64Url(publicKey),
            ShortId = "01"
        };

    private static RuntimeRealityOptions CreateValidRealityOptions(byte[] publicKey, string fingerprint)
        => CreateValidRealityOptions(publicKey) with
        {
            Fingerprint = fingerprint
        };

    private static byte[] CreateDefaultRealityPublicKey()
    {
        var publicKey = new byte[RuntimeX25519.KeyLength];
        for (var index = 0; index < publicKey.Length; index++)
        {
            publicKey[index] = checked((byte)(index + 1));
        }

        return publicKey;
    }

    private static string ToBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static List<KeyShareEntry> ParseKeyShares(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return [];
        }

        var length = (payload[0] << 8) | payload[1];
        var cursor = 2;
        var end = Math.Min(payload.Length, cursor + length);
        var entries = new List<KeyShareEntry>();
        while (cursor + 4 <= end)
        {
            var group = (payload[cursor] << 8) | payload[cursor + 1];
            var keyExchangeLength = (payload[cursor + 2] << 8) | payload[cursor + 3];
            cursor += 4;
            if (cursor + keyExchangeLength > end)
            {
                break;
            }

            entries.Add(new KeyShareEntry(group, payload.Slice(cursor, keyExchangeLength).ToArray()));
            cursor += keyExchangeLength;
        }

        return entries;
    }

    private static int[] ParseSupportedVersions(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0)
        {
            return [];
        }

        var length = payload[0];
        var cursor = 1;
        var end = Math.Min(payload.Length, cursor + length);
        var versions = new List<int>((end - cursor) / 2);
        while (cursor + 1 < end)
        {
            versions.Add((payload[cursor] << 8) | payload[cursor + 1]);
            cursor += 2;
        }

        return versions.ToArray();
    }

    private static List<int> ParseUInt16Vector(ReadOnlySpan<byte> payload)
    {
        var values = new List<int>(payload.Length / 2);
        for (var index = 0; index + 1 < payload.Length; index += 2)
        {
            values.Add((payload[index] << 8) | payload[index + 1]);
        }

        return values;
    }

    private const int GreasePlaceholder = -1;

    private static bool IsGreaseValue(int value)
        => (value & 0x0f0f) == 0x0a0a && ((value >> 8) & 0xff) == (value & 0xff);

    private static int NormalizeGreaseValue(int value)
        => IsGreaseValue(value) ? GreasePlaceholder : value;

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        foreach (var current in value)
        {
            if (current != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static bool MatchesChromeAutoFingerprint(RealityClientHelloCapture capture)
        => MatchesChromeFingerprintShape(capture, "hellochrome_auto", allowProtocolConstraints: true);

    private static Task<string?> IdentifyModernFingerprintAsync(RealityClientHelloCapture capture)
    {
        string? matchedFingerprint = null;
        if (MatchesFirefoxModernFingerprint(capture))
        {
            matchedFingerprint = "hellofirefox_120";
        }
        else if (MatchesIosModernFingerprint(capture))
        {
            matchedFingerprint = "helloios_14";
        }
        else if (MatchesSafariModernFingerprint(capture))
        {
            matchedFingerprint = "hellosafari_16_0";
        }
        else if (MatchesThreeSixty11ModernFingerprint(capture))
        {
            matchedFingerprint = "hello360_11_0";
        }
        else if (MatchesQq11ModernFingerprint(capture))
        {
            matchedFingerprint = "helloqq_11_1";
        }
        else if (MatchesChromeFingerprintShape(capture, "hellochrome_131"))
        {
            matchedFingerprint = "hellochrome_131";
        }
        else if (MatchesChromeFingerprintShape(capture, "hellochrome_120"))
        {
            matchedFingerprint = "hellochrome_120";
        }
        else if (MatchesChromeFingerprintShape(capture, "hellochrome_106_shuffle"))
        {
            matchedFingerprint = "hellochrome_106_shuffle";
        }
        else if (MatchesFixedOrderModernChromeFingerprint(capture, "hellochrome_100"))
        {
            matchedFingerprint = "hellochrome_100";
        }
        else if (MatchesFixedOrderModernChromeFingerprint(capture, "hellochrome_96"))
        {
            matchedFingerprint = "hellochrome_96";
        }
        else if (MatchesFixedOrderModernChromeFingerprint(capture, "hellochrome_83"))
        {
            matchedFingerprint = "hellochrome_83";
        }

        return Task.FromResult(matchedFingerprint);
    }

    private static bool AllowsModernFingerprintOrderVariance(string fingerprint)
        => fingerprint is "hellochrome_106_shuffle" or "hellochrome_120" or "hellochrome_131";

    private static bool MatchesFirefoxModernFingerprint(RealityClientHelloCapture capture)
        => MatchesExplicitBrowserShape(capture, "hellofirefox_120");

    private static bool MatchesIosModernFingerprint(RealityClientHelloCapture capture)
        => MatchesExplicitBrowserShape(capture, "helloios_14");

    private static bool MatchesSafariModernFingerprint(RealityClientHelloCapture capture)
        => MatchesExplicitBrowserShape(capture, "hellosafari_16_0");

    private static bool MatchesThreeSixty11ModernFingerprint(RealityClientHelloCapture capture)
        => MatchesExplicitBrowserShape(capture, "hello360_11_0");

    private static bool MatchesQq11ModernFingerprint(RealityClientHelloCapture capture)
        => MatchesExplicitBrowserShape(capture, "helloqq_11_1") &&
           TryParseClientHello(capture, out var hello) &&
           GetSignatureAlgorithms(hello).SequenceEqual(GetExpectedAndroidSignatureAlgorithms());

    private static bool MatchesExplicitBrowserShape(
        RealityClientHelloCapture capture,
        string fingerprint)
    {
        if (capture.Metadata is null ||
            !TryParseClientHello(capture, out var hello) ||
            !HasRandomSessionId(hello))
        {
            return false;
        }

        return capture.Metadata.CipherSuites.SequenceEqual(GetExpectedExplicitBrowserCipherSuites(fingerprint)) &&
               capture.Metadata.SupportedGroups.SequenceEqual(GetExpectedExplicitBrowserSupportedGroups(fingerprint)) &&
               GetKeyShareGroups(hello, includeGrease: false).SequenceEqual(GetExpectedExplicitBrowserKeyShareGroups(fingerprint)) &&
               GetSupportedVersions(hello, includeGrease: false).SequenceEqual(GetExpectedExplicitBrowserSupportedVersions(fingerprint));
    }

    private static bool MatchesFixedOrderModernChromeFingerprint(
        RealityClientHelloCapture capture,
        string fingerprint)
    {
        if (capture.Metadata is null ||
            !TryParseClientHello(capture, out var hello) ||
            !HasRandomSessionId(hello))
        {
            return false;
        }

        return capture.Metadata.CipherSuites.SequenceEqual(GetExpectedLegacyChromeCipherSuites(fingerprint)) &&
               capture.Metadata.SupportedGroups.SequenceEqual(GetExpectedLegacyChromeSupportedGroups(fingerprint)) &&
               GetNormalizedExtensionTypes(hello).SequenceEqual(GetExpectedLegacyChromeExtensionTypes(fingerprint)) &&
               GetKeyShareGroups(hello, includeGrease: false).SequenceEqual(GetExpectedLegacyChromeKeyShareGroups(fingerprint)) &&
               GetSupportedVersions(hello, includeGrease: false).SequenceEqual(GetExpectedLegacyChromeSupportedVersions(fingerprint)) &&
               GetSignatureAlgorithms(hello).SequenceEqual(GetExpectedLegacyChromeSignatureAlgorithms(fingerprint));
    }

    private static bool MatchesChromeFingerprintShape(
        RealityClientHelloCapture capture,
        string fingerprint,
        bool allowProtocolConstraints = false)
    {
        if (capture.Metadata is null ||
            !TryParseClientHello(capture, out var hello) ||
            !HasRandomSessionId(hello))
        {
            return false;
        }

        var actualCipherSuites = capture.Metadata.CipherSuites;
        var actualSupportedGroups = capture.Metadata.SupportedGroups;
        var actualSupportedGroupsWithGrease = GetSupportedGroups(hello, includeGrease: true);
        var actualKeyShareGroups = GetKeyShareGroups(hello, includeGrease: false);
        var actualKeyShareGroupsWithGrease = GetKeyShareGroups(hello, includeGrease: true);
        var actualSupportedVersions = GetSupportedVersions(hello, includeGrease: false);
        var actualSupportedVersionsWithGrease = GetSupportedVersions(hello, includeGrease: true);
        var actualNormalizedExtensionTypes = GetNormalizedExtensionTypes(hello);
        var actualExtensionTypesWithoutGrease = GetExtensionTypes(hello, includeGrease: false);
        var actualSignatureAlgorithms = GetSignatureAlgorithms(hello);
        var expectedSignatureAlgorithms = GetExpectedChromeSignatureAlgorithms();
        var expectedCipherSuites = Array.Empty<int>();
        var expectedSupportedGroups = Array.Empty<int>();
        var expectedKeyShareGroups = Array.Empty<int>();
        var expectedSupportedVersions = Array.Empty<int>();
        var expectedExtensionTypes = Array.Empty<int>();
        var expectedFixedOrderExtensionTypes = Array.Empty<int>();
        var expectedApplicationSettingsExtensionType = 0;
        var expectsEchGrease = false;
        var expectsPadding = false;
        var allowsOptionalPadding = false;
        var expectsKeyShare = true;
        var expectsGreasedSupportedVersions = true;
        var expectsGreasedSupportedGroups = true;
        var requiresFixedExtensionOrder = false;
        var expectedHybridKeyShareGroup = 0;
        var expectedHybridKeyShareLength = 0;

        switch (fingerprint)
        {
            case "hellochrome_106_shuffle":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: true);
                expectsPadding = true;
                expectedApplicationSettingsExtensionType = 17513;
                break;

            case "hellochrome_100_psk":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: false);
                expectedFixedOrderExtensionTypes = [.. GetExpectedChrome100PskExtensionTypes()];
                expectedApplicationSettingsExtensionType = 17513;
                requiresFixedExtensionOrder = true;
                break;

            case "hellochrome_112_psk_shuf":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: false);
                expectedApplicationSettingsExtensionType = 17513;
                break;

            case "hellochrome_114_padding_psk_shuf":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: true);
                expectsPadding = true;
                expectedApplicationSettingsExtensionType = 17513;
                break;

            case "hellochrome_115_pq":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519Kyber768Draft00, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519Kyber768Draft00, RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: false);
                expectedApplicationSettingsExtensionType = 17513;
                expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519Kyber768Draft00;
                expectedHybridKeyShareLength = RuntimeX25519Kyber768Draft00.ClientKeyShareLength;
                break;

            case "hellochrome_115_pq_psk":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519Kyber768Draft00, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519Kyber768Draft00, RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: false);
                expectedApplicationSettingsExtensionType = 17513;
                expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519Kyber768Draft00;
                expectedHybridKeyShareLength = RuntimeX25519Kyber768Draft00.ClientKeyShareLength;
                break;

            case "hellochrome_120":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: true,
                    includePadding: false);
                expectsEchGrease = true;
                allowsOptionalPadding = true;
                expectedApplicationSettingsExtensionType = 17513;
                break;

            case "hellochrome_120_pq":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519Kyber768Draft00, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519Kyber768Draft00, RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: true,
                    includePadding: false);
                expectsEchGrease = true;
                expectedApplicationSettingsExtensionType = 17513;
                expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519Kyber768Draft00;
                expectedHybridKeyShareLength = RuntimeX25519Kyber768Draft00.ClientKeyShareLength;
                break;

            case "hellochrome_131":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: true,
                    includePadding: false);
                expectsEchGrease = true;
                expectedApplicationSettingsExtensionType = 17513;
                expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                break;

            case "chrome":
            case "hellochrome_auto":
                if (!allowProtocolConstraints)
                {
                    expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                    expectedSupportedVersions = [0x0304, 0x0303];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: true,
                        includePskKeyExchangeModes: true,
                        includeSupportedVersions: true,
                        includeCompressCertificate: true,
                        applicationSettingsExtensionType: 17613,
                        includeEchGrease: true,
                        includePadding: false);
                    expectsEchGrease = true;
                    expectedApplicationSettingsExtensionType = 17613;
                    expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                    expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                    break;
                }

                if (actualSupportedVersions.SequenceEqual(new[] { 0x0304 }))
                {
                    expectedCipherSuites = [.. GetExpectedChromeTls13OnlyCipherSuites()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                    expectedSupportedVersions = [0x0304];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: true,
                        includePskKeyExchangeModes: true,
                        includeSupportedVersions: true,
                        includeCompressCertificate: true,
                        applicationSettingsExtensionType: 17613,
                        includeEchGrease: true,
                        includePadding: false);
                    expectsEchGrease = true;
                    expectedApplicationSettingsExtensionType = 17613;
                    expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                    expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                    break;
                }

                if (actualSupportedVersions.SequenceEqual(new[] { 0x0304, 0x0303 }))
                {
                    expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                    expectedSupportedVersions = [0x0304, 0x0303];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: true,
                        includePskKeyExchangeModes: true,
                        includeSupportedVersions: true,
                        includeCompressCertificate: true,
                        applicationSettingsExtensionType: 17613,
                        includeEchGrease: true,
                        includePadding: false);
                    expectsEchGrease = true;
                    expectedApplicationSettingsExtensionType = 17613;
                    expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                    expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                    break;
                }

                if (actualSupportedVersions.SequenceEqual(new[] { 0x0303 }))
                {
                    expectedCipherSuites = [.. GetExpectedChromeLegacyCipherSuitesWithoutTls13()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = Array.Empty<int>();
                    expectedSupportedVersions = [0x0303];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: false,
                        includePskKeyExchangeModes: false,
                        includeSupportedVersions: true,
                        includeCompressCertificate: false,
                        applicationSettingsExtensionType: null,
                        includeEchGrease: false,
                        includePadding: false);
                    expectsKeyShare = false;
                    break;
                }

                return false;

            default:
                throw new NotSupportedException($"Unsupported Chrome fingerprint '{fingerprint}'.");
        }

        if (!actualCipherSuites.SequenceEqual(expectedCipherSuites) ||
            !actualSupportedGroups.SequenceEqual(expectedSupportedGroups) ||
            !actualSupportedVersions.SequenceEqual(expectedSupportedVersions) ||
            !actualSignatureAlgorithms.SequenceEqual(expectedSignatureAlgorithms))
        {
            return false;
        }

        if (expectsGreasedSupportedGroups &&
            (actualSupportedGroupsWithGrease.Length == 0 || !IsGreaseValue(actualSupportedGroupsWithGrease[0])))
        {
            return false;
        }

        if (expectsGreasedSupportedVersions &&
            (actualSupportedVersionsWithGrease.Length == 0 || !IsGreaseValue(actualSupportedVersionsWithGrease[0])))
        {
            return false;
        }

        if (!expectsKeyShare)
        {
            if (HasExtension(hello, 0x0033) || actualKeyShareGroups.Length != 0)
            {
                return false;
            }
        }
        else if (!actualKeyShareGroups.SequenceEqual(expectedKeyShareGroups) ||
                 actualKeyShareGroupsWithGrease.Length == 0 ||
                 !IsGreaseValue(actualKeyShareGroupsWithGrease[0]))
        {
            return false;
        }

        var hasPadding = HasExtension(hello, 0x0015);
        if (HasExtension(hello, 0x0032) ||
            HasExtension(hello, 0x0029) ||
            HasExtension(hello, 0xFE0D) != expectsEchGrease ||
            (!allowsOptionalPadding && hasPadding != expectsPadding) ||
            HasExtension(hello, 17513) != (expectedApplicationSettingsExtensionType == 17513) ||
            HasExtension(hello, 17613) != (expectedApplicationSettingsExtensionType == 17613))
        {
            return false;
        }

        if (requiresFixedExtensionOrder)
        {
            if (!actualNormalizedExtensionTypes.SequenceEqual(expectedFixedOrderExtensionTypes))
            {
                return false;
            }
        }
        else
        {
            var expectedExtensionTypeSet = allowsOptionalPadding
                ? BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: expectedApplicationSettingsExtensionType,
                    includeEchGrease: expectsEchGrease,
                    includePadding: hasPadding)
                : expectedExtensionTypes;
            if (!SetEquals(actualExtensionTypesWithoutGrease, expectedExtensionTypeSet))
            {
                return false;
            }
        }

        if (expectedHybridKeyShareGroup != 0)
        {
            var hybridKeyShare = GetKeyShares(hello)
                .SingleOrDefault(entry => entry.Group == expectedHybridKeyShareGroup);
            if (hybridKeyShare is null ||
                hybridKeyShare.KeyExchange.Length != expectedHybridKeyShareLength)
            {
                return false;
            }
        }

        return true;
    }

    private static bool RequiresX25519Kyber768Draft00(string fingerprint)
        => fingerprint is "hellochrome_115_pq" or "hellochrome_115_pq_psk" or "hellochrome_120_pq";

    private static bool TryParseClientHello(
        RealityClientHelloCapture capture,
        out RuntimeRealityClientHelloDocument hello)
    {
        hello = null!;
        var parsed = RuntimeRealityClientHelloDocument.TryParse(capture.ClientHello, out var document, out _);
        if (!parsed || document is null)
        {
            return false;
        }

        hello = document;
        return true;
    }

    private static bool HasRandomSessionId(RuntimeRealityClientHelloDocument hello)
        => hello.SessionId.Length == 32 && !IsAllZero(hello.SessionId);

    private static bool HasExtension(RuntimeRealityClientHelloDocument hello, int extensionType)
        => hello.Extensions.Any(extension => extension.Type == extensionType);

    private static int[] GetNormalizedExtensionTypes(RuntimeRealityClientHelloDocument hello)
        => hello.Extensions
            .Select(static extension => NormalizeGreaseValue(extension.Type))
            .ToArray();

    private static int[] GetExtensionTypes(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
        => hello.Extensions
            .Select(static extension => (int)extension.Type)
            .Where(extensionType => includeGrease || !IsGreaseValue(extensionType))
            .ToArray();

    private static int[] GetSupportedGroups(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
    {
        var extension = hello.Extensions.SingleOrDefault(static current => current.Type == 0x000A);
        if (extension is null)
        {
            return [];
        }

        return ParseSupportedGroupsPayload(extension.Payload)
            .Where(group => includeGrease || !IsGreaseValue(group))
            .ToArray();
    }

    private static int[] GetSupportedVersions(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
    {
        var extension = hello.Extensions.SingleOrDefault(static current => current.Type == 0x002B);
        if (extension is null)
        {
            return [];
        }

        return ParseSupportedVersions(extension.Payload)
            .Where(version => includeGrease || !IsGreaseValue(version))
            .ToArray();
    }

    private static int[] GetKeyShareGroups(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
        => GetKeyShares(hello)
            .Select(static entry => entry.Group)
            .Where(group => includeGrease || !IsGreaseValue(group))
            .ToArray();

    private static List<KeyShareEntry> GetKeyShares(RuntimeRealityClientHelloDocument hello)
    {
        var extension = hello.Extensions.SingleOrDefault(static current => current.Type == 0x0033);
        return extension is null
            ? []
            : ParseKeyShares(extension.Payload);
    }

    private static IReadOnlyList<int> GetSignatureAlgorithms(RuntimeRealityClientHelloDocument hello)
    {
        var extension = hello.Extensions.SingleOrDefault(static current => current.Type == 0x000D);
        if (extension is null || extension.Payload.Length < 2)
        {
            return Array.Empty<int>();
        }

        return ParseUInt16Vector(extension.Payload.AsSpan(2));
    }

    private static int[] ParseSupportedGroupsPayload(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return [];
        }

        var length = (payload[0] << 8) | payload[1];
        var cursor = 2;
        var end = Math.Min(payload.Length, cursor + length);
        var values = new List<int>((end - cursor) / 2);
        while (cursor + 1 < end)
        {
            values.Add((payload[cursor] << 8) | payload[cursor + 1]);
            cursor += 2;
        }

        return values.ToArray();
    }

    private static bool SetEquals(
        IReadOnlyList<int> actual,
        IReadOnlyList<int> expected)
        => actual.Count == expected.Count &&
           actual.OrderBy(static value => value).SequenceEqual(expected.OrderBy(static value => value));

    private static int[] BuildExpectedChromeExtensionTypeSet(
        bool includeKeyShare,
        bool includePskKeyExchangeModes,
        bool includeSupportedVersions,
        bool includeCompressCertificate,
        int? applicationSettingsExtensionType,
        bool includeEchGrease,
        bool includePadding)
    {
        var values = new List<int>
        {
            0x0000,
            0x0017,
            0xFF01,
            0x000A,
            0x000B,
            0x0023,
            0x0010,
            0x0005,
            0x000D,
            0x0012
        };
        if (includeKeyShare)
        {
            values.Add(0x0033);
        }

        if (includePskKeyExchangeModes)
        {
            values.Add(0x002D);
        }

        if (includeSupportedVersions)
        {
            values.Add(0x002B);
        }

        if (includeCompressCertificate)
        {
            values.Add(0x001B);
        }

        if (applicationSettingsExtensionType.HasValue)
        {
            values.Add(applicationSettingsExtensionType.Value);
        }

        if (includeEchGrease)
        {
            values.Add(0xFE0D);
        }

        if (includePadding)
        {
            values.Add(0x0015);
        }

        return values.ToArray();
    }

    private static IReadOnlyList<int> GetExpectedChromeMixedCipherSuites()
        => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035];

    private static IReadOnlyList<int> GetExpectedChromeTls13OnlyCipherSuites()
        => [0x1301, 0x1302, 0x1303];

    private static IReadOnlyList<int> GetExpectedChromeLegacyCipherSuitesWithoutTls13()
        => [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035];

    private static IReadOnlyList<int> GetExpectedChromeSignatureAlgorithms()
        => [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

    private static IReadOnlyList<int> GetExpectedAndroidSignatureAlgorithms()
        => [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201];

    private static IReadOnlyList<int> GetExpectedChrome100PskExtensionTypes()
        => [GreasePlaceholder, 0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B, 17513, GreasePlaceholder];

    private static IReadOnlyList<int> GetExpectedGolangCipherSuites(bool includeTls12CipherSuites = false)
    {
        if (!includeTls12CipherSuites)
        {
            return PreferAesGcmCipherSuites()
                ? [0x1301, 0x1302, 0x1303]
                : [0x1303, 0x1301, 0x1302];
        }

        return PreferAesGcmCipherSuites()
            ? [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014, 0x1301, 0x1302, 0x1303]
            : [0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC009, 0xC013, 0xC00A, 0xC014, 0x1303, 0x1301, 0x1302];
    }

    private static IReadOnlyList<int> GetExpectedGolangTls12CipherSuites()
        => PreferAesGcmCipherSuites()
            ? [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014]
            : [0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC009, 0xC013, 0xC00A, 0xC014];

    private static IReadOnlyList<int> GetExpectedGolangExtensions()
        => [0x0000, 0x000B, 0xFF01, 0x0017, 0x0012, 0x0005, 0x000A, 0x000D, 0x002B, 0x0033];

    private static IReadOnlyList<int> GetExpectedGolangTls12Extensions()
        => [0x0000, 0x000B, 0xFF01, 0x0017, 0x0012, 0x0005, 0x000A, 0x000D, 0x002B];

    private static IReadOnlyList<int> GetExpectedGolangSupportedGroups()
        => RuntimeX25519MlKem768.IsSupported
            ? [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1]
            : [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1];

    private static IReadOnlyList<int> GetExpectedGolangTls12SupportedGroups()
        => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1];

    private static IReadOnlyList<int> GetExpectedThreeSixty75CipherSuites()
        => [0xC00A, 0xC014, 0x0039, 0x006B, 0x0035, 0x003D, 0xC007, 0xC009, 0xC023, 0xC011, 0xC013, 0xC027, 0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002F, 0x003C, 0x000A];

    private static IReadOnlyList<int> GetExpectedThreeSixty75Extensions()
        => [0x0000, 0xFF01, 0x000A, 0x000B, 0x0023, 13172, 0x0010, 30031, 0x0005, 0x000D];

    private static IReadOnlyList<int> GetExpectedThreeSixty75SupportedGroups()
        => [RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1];

    private static IReadOnlyList<int> GetExpectedExplicitBrowserCipherSuites(string fingerprint)
        => fingerprint switch
        {
            "helloedge_85" or "hellochrome_120" or "hellochrome_131" or "helloedge_106"
                => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
            "helloios_14"
                => [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC024, 0xC023, 0xC00A, 0xC009, 0xC028, 0xC027, 0xC014, 0xC013, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0xC008, 0xC012, 0x000A],
            "hello360_11_0"
                => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A],
            "helloqq_11_1"
                => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
            "hellofirefox_120"
                => [0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC00A, 0xC009, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
            "hellosafari_16_0"
                => [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F, 0xCCA8, 0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x0035, 0x002F, 0xC008, 0xC012, 0x000A],
            _ => throw new NotSupportedException($"Unsupported explicit browser fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedExplicitBrowserSupportedGroups(string fingerprint)
        => fingerprint switch
        {
            "helloedge_85" or "hellochrome_120" or "helloedge_106"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1],
            "helloios_14"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1],
            "hello360_11_0" or "helloqq_11_1"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1],
            "hellochrome_131"
                => [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1],
            "hellofirefox_120"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1, 0x0100, 0x0101],
            "hellosafari_16_0"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1],
            _ => throw new NotSupportedException($"Unsupported explicit browser fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedExplicitBrowserKeyShareGroups(string fingerprint)
        => fingerprint switch
        {
            "helloedge_85" or "hellochrome_120" or "helloedge_106"
                => [RuntimeTlsNamedGroups.X25519],
            "helloios_14" or "hello360_11_0" or "helloqq_11_1"
                => [RuntimeTlsNamedGroups.X25519],
            "hellochrome_131"
                => [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519],
            "hellofirefox_120"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1],
            "hellosafari_16_0"
                => [RuntimeTlsNamedGroups.X25519],
            _ => throw new NotSupportedException($"Unsupported explicit browser fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedExplicitBrowserSupportedVersions(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_120" or "hellochrome_131" or "helloedge_106" or "hellofirefox_120"
                => [0x0304, 0x0303],
            "helloedge_85" or "helloios_14" or "hello360_11_0" or "helloqq_11_1" or "hellosafari_16_0"
                => [0x0304, 0x0303, 0x0302, 0x0301],
            _ => throw new NotSupportedException($"Unsupported explicit browser fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedLegacyChromeCipherSuites(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_58" or "hellochrome_62"
                => [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A],
            "hellochrome_70" or "hellochrome_72"
                => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A],
            "hellochrome_83" or "hellochrome_87" or "hellochrome_96" or "hellochrome_100" or "hellochrome_102"
                => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
            _ => throw new NotSupportedException($"Unsupported legacy Chrome fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedLegacyChromeSupportedGroups(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_58" or "hellochrome_62" or "hellochrome_70" or "hellochrome_72" or "hellochrome_83" or "hellochrome_87" or "hellochrome_96" or "hellochrome_100" or "hellochrome_102"
                => [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1],
            _ => throw new NotSupportedException($"Unsupported legacy Chrome fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedLegacyChromeExtensionTypes(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_58" or "hellochrome_62"
                => [GreasePlaceholder, 0xFF01, 0x0000, 0x0017, 0x0023, 0x000D, 0x0005, 0x0012, 0x0010, 30032, 0x000B, 0x000A, GreasePlaceholder],
            "hellochrome_70"
                => [GreasePlaceholder, 0xFF01, 0x0000, 0x0017, 0x0023, 0x000D, 0x0005, 0x0012, 0x0010, 30032, 0x000B, 0x0033, 0x002D, 0x002B, 0x000A, 0x001B, GreasePlaceholder, 0x0015],
            "hellochrome_72" or "hellochrome_83" or "hellochrome_87"
                => [GreasePlaceholder, 0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B, GreasePlaceholder, 0x0015],
            "hellochrome_96" or "hellochrome_100" or "hellochrome_102"
                => [GreasePlaceholder, 0x0000, 0x0017, 0xFF01, 0x000A, 0x000B, 0x0023, 0x0010, 0x0005, 0x000D, 0x0012, 0x0033, 0x002D, 0x002B, 0x001B, 17513, GreasePlaceholder, 0x0015],
            _ => throw new NotSupportedException($"Unsupported legacy Chrome fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedLegacyChromeKeyShareGroups(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_58" or "hellochrome_62"
                => [],
            "hellochrome_70" or "hellochrome_72" or "hellochrome_83" or "hellochrome_87" or "hellochrome_96" or "hellochrome_100" or "hellochrome_102"
                => [RuntimeTlsNamedGroups.X25519],
            _ => throw new NotSupportedException($"Unsupported legacy Chrome fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedLegacyChromeSupportedVersions(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_58" or "hellochrome_62"
                => [],
            "hellochrome_70" or "hellochrome_72" or "hellochrome_83" or "hellochrome_87" or "hellochrome_96"
                => [0x0304, 0x0303, 0x0302, 0x0301],
            "hellochrome_100" or "hellochrome_102"
                => [0x0304, 0x0303],
            _ => throw new NotSupportedException($"Unsupported legacy Chrome fingerprint '{fingerprint}'.")
        };

    private static IReadOnlyList<int> GetExpectedLegacyChromeSignatureAlgorithms(string fingerprint)
        => fingerprint switch
        {
            "hellochrome_58" or "hellochrome_62" or "hellochrome_70" or "hellochrome_72"
                => [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201],
            "hellochrome_83" or "hellochrome_87" or "hellochrome_96" or "hellochrome_100" or "hellochrome_102"
                => [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
            _ => throw new NotSupportedException($"Unsupported legacy Chrome fingerprint '{fingerprint}'.")
        };

    private static bool ExpectedExplicitBrowserKeyShareIncludesGrease(string fingerprint)
        => fingerprint switch
        {
            "helloedge_85" or "hellochrome_120" or "hellochrome_131" or "helloedge_106" or "helloios_14" or "hello360_11_0" or "helloqq_11_1" => true,
            "hellofirefox_120" or "hellosafari_16_0" => false,
            _ => throw new NotSupportedException($"Unsupported explicit browser fingerprint '{fingerprint}'.")
        };

    private static bool ExpectedExplicitBrowserSupportedVersionsIncludeGrease(string fingerprint)
        => fingerprint switch
        {
            "helloedge_85" or "hellochrome_120" or "hellochrome_131" or "helloedge_106" or "helloios_14" or "hello360_11_0" or "helloqq_11_1" or "hellosafari_16_0" => true,
            "hellofirefox_120" => false,
            _ => throw new NotSupportedException($"Unsupported explicit browser fingerprint '{fingerprint}'.")
        };

    private static bool PreferAesGcmCipherSuites()
        => AesGcm.IsSupported &&
           ((System.Runtime.Intrinsics.X86.Aes.IsSupported &&
             System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
             System.Runtime.Intrinsics.X86.Sse41.IsSupported &&
             System.Runtime.Intrinsics.X86.Ssse3.IsSupported) ||
            System.Runtime.Intrinsics.Arm.Aes.IsSupported);

    private static async Task<StandardTlsServerCapture> CompleteRealCertificateTls13ServerFlightAsync(
        TcpListener listener,
        ushort selectedGroup,
        ushort cipherSuite,
        string negotiatedApplicationProtocol,
        CancellationToken cancellationToken,
        bool requestClientCertificate = false,
        bool sendKeyUpdateRequest = false)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(RuntimeTlsClientHelloParser.TryParse(clientHello, out var metadata));
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out var error),
            error);
        Assert.NotNull(hello);
        Assert.NotNull(hello!.X25519PublicKey);
        await AssertNoPendingClientDataAsync(client, cancellationToken);

        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(clientHello.AsSpan(5));

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        var serverHandshakeState = CreateServerHandshakeState(selectedGroup, keyShares);
        var serverHello = BuildServerHello(hello.SessionId, selectedGroup, cipherSuite, serverHandshakeState.ServerKeyShare);
        transcript.Append(serverHello.AsSpan(5));

        var tlsCipherSuite = RuntimeTls13CipherSuite.Resolve(cipherSuite);
        var keySchedule = RuntimeTls13KeySchedule.Create(
            tlsCipherSuite,
            serverHandshakeState.SharedSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));

        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate(
            "localhost",
            ["localhost"]);
        var rawCertificate = certificate.Export(X509ContentType.Cert);

        var encryptedExtensions = BuildEncryptedExtensions(negotiatedApplicationProtocol);
        transcript.Append(encryptedExtensions);

        var certificateRequest = requestClientCertificate
            ? BuildTls13CertificateRequestMessage()
            : Array.Empty<byte>();
        if (requestClientCertificate)
        {
            transcript.Append(certificateRequest);
        }

        var certificateMessage = BuildCertificate(rawCertificate);
        transcript.Append(certificateMessage);

        using var rsa = certificate.GetRSAPrivateKey();
        Assert.NotNull(rsa);
        var certificateVerifySignature = rsa!.SignData(
            BuildCertificateVerifyData(
                "TLS 1.3, server CertificateVerify",
                transcript.GetHash(tlsCipherSuite.HashAlgorithm)),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var certificateVerify = BuildCertificateVerify(0x0804, certificateVerifySignature);
        transcript.Append(certificateVerify);

        var finished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ServerHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        transcript.Append(finished);

        using var serverHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ServerHandshakeTrafficSecret);
        using var clientHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ClientHandshakeTrafficSecret);

        await stream.WriteAsync(serverHello, cancellationToken);
        await WriteCompatibilityChangeCipherSpecAsync(stream, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, encryptedExtensions, cancellationToken);
        if (requestClientCertificate)
        {
            await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateRequest, cancellationToken);
        }
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateMessage, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateVerify, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, finished, cancellationToken);

        if (requestClientCertificate)
        {
            var clientCertificate = await ReadEncryptedHandshakeMessageAsync(
                stream,
                clientHandshakeProtector,
                cancellationToken);
            AssertEmptyTls13CertificateMessage(clientCertificate);
            transcript.Append(clientCertificate);
        }

        var expectedClientFinished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ClientHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        var applicationSecrets = keySchedule.CreateApplicationSecrets(
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));
        var clientFinished = await ReadEncryptedHandshakeMessageAsync(
            stream,
            clientHandshakeProtector,
            cancellationToken);
        Assert.Equal(expectedClientFinished, clientFinished);
        transcript.Append(clientFinished);
        using var clientApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ClientApplicationTrafficSecret);
        using var serverApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ServerApplicationTrafficSecret);
        if (sendKeyUpdateRequest)
        {
            await WriteEncryptedRecordAsync(
                stream,
                serverApplicationProtector,
                BuildTls13KeyUpdateMessage(updateRequested: true),
                cancellationToken);
            serverApplicationProtector.AdvanceTrafficSecret();
        }

        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var serverRecord = serverApplicationProtector.Encrypt(
            RuntimeTls13RecordType.ApplicationData,
            serverPayload);
        await stream.WriteAsync(serverRecord, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var clientPayload = await ReadEncryptedApplicationDataAsync(
            stream,
            clientApplicationProtector,
            cancellationToken,
            allowPostHandshakeKeyUpdate: sendKeyUpdateRequest);

        return new StandardTlsServerCapture(
            metadata,
            SslProtocols.Tls13,
            negotiatedApplicationProtocol,
            serverPayload,
            clientPayload);
    }

    private static async Task<StandardTlsServerCapture> CompleteRealCertificateTls12ServerFlightAsync(
        TcpListener listener,
        ushort cipherSuite,
        ushort selectedGroup,
        string negotiatedApplicationProtocol,
        Tls12ServerCertificateKind certificateKind,
        CancellationToken cancellationToken,
        ushort? signatureAlgorithm = null,
        bool requestClientCertificate = false,
        ushort selectedVersion = 0x0303)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(RuntimeTlsClientHelloParser.TryParse(clientHello, out var metadata));
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out var error),
            error);
        Assert.NotNull(hello);
        await AssertNoPendingClientDataAsync(client, cancellationToken);

        var clientHelloMessage = clientHello.AsSpan(5).ToArray();
        var clientRandom = ExtractTlsClientRandom(clientHelloMessage);
        var serverRandom = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var negotiatedSslProtocol = ResolveLegacySslProtocol(selectedVersion);
        using var transcript = new RuntimeTls12HandshakeTranscript();
        transcript.Append(clientHelloMessage);

        var serverHello = BuildTls12ServerHelloMessage(
            hello!.SessionId,
            serverRandom,
            cipherSuite,
            negotiatedApplicationProtocol,
            selectedVersion);
        transcript.Append(serverHello);
        var tlsCipherSuite = RuntimeTls12CipherSuite.Resolve(cipherSuite);

        X509Certificate2? certificate = null;
        IDisposable? disposableSigningKey = null;
        object signingKeyMaterial;
        byte[] rawCertificate;
        ushort defaultSignatureAlgorithm;
        switch (certificateKind)
        {
            case Tls12ServerCertificateKind.Rsa:
                certificate = TestCertificateFactory.CreateSelfSignedServerCertificate(
                    "localhost",
                    ["localhost"]);
                rawCertificate = certificate.Export(X509ContentType.Cert);
                disposableSigningKey = certificate.GetRSAPrivateKey();
                Assert.NotNull(disposableSigningKey);
                signingKeyMaterial = disposableSigningKey;
                defaultSignatureAlgorithm = 0x0804;
                break;
            case Tls12ServerCertificateKind.Ecdsa:
                certificate = TestCertificateFactory.CreateSelfSignedEcdsaServerCertificate(
                    "localhost",
                    ["localhost"]);
                rawCertificate = certificate.Export(X509ContentType.Cert);
                disposableSigningKey = certificate.GetECDsaPrivateKey();
                Assert.NotNull(disposableSigningKey);
                signingKeyMaterial = disposableSigningKey;
                defaultSignatureAlgorithm = 0x0403;
                break;
            case Tls12ServerCertificateKind.Ed25519:
                var privateKey = Enumerable.Range(1, RuntimeEd25519.PrivateKeyLength)
                    .Select(static value => (byte)value)
                    .ToArray();
                rawCertificate = TestCertificateFactory.CreateEd25519Certificate(
                    RuntimeEd25519.DerivePublicKey(privateKey),
                    new byte[RuntimeEd25519.SignatureLength],
                    "localhost");
                signingKeyMaterial = privateKey;
                defaultSignatureAlgorithm = 0x0807;
                break;
            default:
                throw new NotSupportedException($"Unsupported TLS 1.2 test certificate kind '{certificateKind}'.");
        }

        try
        {
            var certificateMessage = BuildTls12CertificateMessage(rawCertificate);
            transcript.Append(certificateMessage);
            var resolvedSignatureAlgorithm = signatureAlgorithm ?? defaultSignatureAlgorithm;
            Tls12ServerEphemeralKeyState? serverKeyPair = null;
            byte[]? serverKeyExchange = null;
            if (tlsCipherSuite.KeyExchangeKind == RuntimeTls12KeyExchangeKind.Ecdhe)
            {
                serverKeyPair = CreateTls12ServerEphemeralKeyState(selectedGroup);
                serverKeyExchange = BuildTls12ServerKeyExchangeMessage(
                    selectedGroup,
                    serverKeyPair.PublicKey,
                    clientRandom,
                    serverRandom,
                    negotiatedSslProtocol,
                    resolvedSignatureAlgorithm,
                    signingKeyMaterial);
                transcript.Append(serverKeyExchange);
            }

            var certificateRequest = requestClientCertificate
                ? BuildTls12CertificateRequestMessage()
                : Array.Empty<byte>();
            if (requestClientCertificate)
            {
                transcript.Append(certificateRequest);
            }

            var serverHelloDone = BuildHandshakeMessage((RuntimeTls13HandshakeType)14, []);
            transcript.Append(serverHelloDone);

            await WriteTls12PlaintextRecordAsync(
                    stream,
                    RuntimeTls13RecordType.Handshake,
                    serverHello,
                    selectedVersion,
                    cancellationToken)
                ;
            await WriteTls12PlaintextRecordAsync(
                    stream,
                    RuntimeTls13RecordType.Handshake,
                    certificateMessage,
                    selectedVersion,
                    cancellationToken)
                ;
            if (serverKeyExchange is not null)
            {
                await WriteTls12PlaintextRecordAsync(
                        stream,
                        RuntimeTls13RecordType.Handshake,
                        serverKeyExchange,
                        selectedVersion,
                        cancellationToken)
                    ;
            }
            if (requestClientCertificate)
            {
                await WriteTls12PlaintextRecordAsync(
                        stream,
                        RuntimeTls13RecordType.Handshake,
                        certificateRequest,
                        selectedVersion,
                        cancellationToken)
                    ;
            }
            await WriteTls12PlaintextRecordAsync(
                    stream,
                    RuntimeTls13RecordType.Handshake,
                    serverHelloDone,
                    selectedVersion,
                    cancellationToken)
                ;

            if (requestClientCertificate)
            {
                var clientCertificate = await ReadTls12PlaintextHandshakeMessageAsync(stream, cancellationToken);
                AssertEmptyTls12CertificateMessage(clientCertificate);
                transcript.Append(clientCertificate);
            }

            var clientKeyExchange = await ReadTls12PlaintextHandshakeMessageAsync(stream, cancellationToken);
            transcript.Append(clientKeyExchange);
            byte[] preMasterSecret;
            if (tlsCipherSuite.KeyExchangeKind == RuntimeTls12KeyExchangeKind.Ecdhe)
            {
                var clientKeyShare = ExtractTls12ClientKeyExchangePublicKey(clientKeyExchange);
                preMasterSecret = DeriveTls12PreMasterSecret(selectedGroup, serverKeyPair!.PrivateKey, clientKeyShare);
            }
            else
            {
                preMasterSecret = DecryptTls12RsaClientKeyExchangePreMasterSecret(clientKeyExchange, certificate!);
            }

            var preFinishedTranscriptHash = transcript.GetHashForPseudoRandomFunction(
                negotiatedSslProtocol,
                tlsCipherSuite.HashAlgorithm);
            var masterSecret = RuntimeTls12PseudoRandomFunction.CreateMasterSecret(
                negotiatedSslProtocol,
                tlsCipherSuite,
                preMasterSecret,
                clientRandom,
                serverRandom);
            var keyBlock = RuntimeTls12PseudoRandomFunction.CreateKeyBlock(
                negotiatedSslProtocol,
                tlsCipherSuite,
                masterSecret,
                clientRandom,
                serverRandom);

            using var clientReadProtector = RuntimeTls12TrafficProtector.Create(
                tlsCipherSuite,
                keyBlock.ClientWriteKey,
                keyBlock.ClientWriteIv,
                keyBlock.ClientMacKey,
                selectedVersion,
                selectedVersion != 0x0301);
            using var serverWriteProtector = RuntimeTls12TrafficProtector.Create(
                tlsCipherSuite,
                keyBlock.ServerWriteKey,
                keyBlock.ServerWriteIv,
                keyBlock.ServerMacKey,
                selectedVersion,
                selectedVersion != 0x0301);

            var clientChangeCipherSpec = await RuntimeTls13Record.ReadAsync(
                    stream,
                    allowEof: false,
                    cancellationToken)
                
                ?? throw new EndOfStreamException("Unexpected EOF while waiting for the TLS 1.2 client ChangeCipherSpec.");
            Assert.Equal(RuntimeTls13RecordType.ChangeCipherSpec, clientChangeCipherSpec.Type);
            Assert.True(RuntimeTls13Record.IsCompatibilityChangeCipherSpec(clientChangeCipherSpec.Payload));

            var clientFinishedRecord = await RuntimeTls13Record.ReadAsync(
                    stream,
                    allowEof: false,
                    cancellationToken)
                
                ?? throw new EndOfStreamException("Unexpected EOF while waiting for the TLS 1.2 client Finished.");
            Assert.Equal(RuntimeTls13RecordType.Handshake, clientFinishedRecord.Type);
            var expectedClientFinished = RuntimeTls12PseudoRandomFunction.CreateFinishedMessage(
                negotiatedSslProtocol,
                tlsCipherSuite,
                masterSecret,
                preFinishedTranscriptHash,
                isClient: true);
            var clientFinished = clientReadProtector.Decrypt(
                RuntimeTls13RecordType.Handshake,
                clientFinishedRecord.Payload);
            Assert.Equal(expectedClientFinished, clientFinished);
            transcript.Append(clientFinished);

            await WriteTls12PlaintextRecordAsync(
                    stream,
                    RuntimeTls13RecordType.ChangeCipherSpec,
                    new byte[] { 0x01 },
                    selectedVersion,
                    cancellationToken)
                ;
            var serverFinishedTranscriptHash = transcript.GetHashForPseudoRandomFunction(
                negotiatedSslProtocol,
                tlsCipherSuite.HashAlgorithm);
            var serverFinished = RuntimeTls12PseudoRandomFunction.CreateFinishedMessage(
                negotiatedSslProtocol,
                tlsCipherSuite,
                masterSecret,
                serverFinishedTranscriptHash,
                isClient: false);
            var serverFinishedRecord = serverWriteProtector.Encrypt(
                RuntimeTls13RecordType.Handshake,
                serverFinished);
            await stream.WriteAsync(serverFinishedRecord, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            var serverPayload = Encoding.ASCII.GetBytes("server->client");
            var serverApplicationRecord = serverWriteProtector.Encrypt(
                RuntimeTls13RecordType.ApplicationData,
                serverPayload);
            await stream.WriteAsync(serverApplicationRecord, cancellationToken);
            await stream.FlushAsync(cancellationToken);

            var clientPayload = await ReadTls12EncryptedApplicationDataAsync(
                stream,
                clientReadProtector,
                cancellationToken);
            await ReadTls12EncryptedCloseNotifyAsync(
                stream,
                clientReadProtector,
                cancellationToken);

            return new StandardTlsServerCapture(
                metadata,
                negotiatedSslProtocol,
                negotiatedApplicationProtocol,
                serverPayload,
                clientPayload);
        }
        finally
        {
            disposableSigningKey?.Dispose();
            certificate?.Dispose();
        }
    }

    private static async Task SendTls13ServerHelloAsync(
        TcpListener listener,
        ushort selectedGroup,
        ushort cipherSuite,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out var error),
            error);
        Assert.NotNull(hello);

        var keyShares = ParseKeyShares(hello!.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Contains(keyShares, entry => entry.Group == selectedGroup);
        await AssertNoPendingClientDataAsync(client, cancellationToken);

        var serverHandshakeState = CreateServerHandshakeState(selectedGroup, keyShares);

        var serverHello = BuildServerHello(hello.SessionId, selectedGroup, cipherSuite, serverHandshakeState.ServerKeyShare);
        await stream.WriteAsync(serverHello, cancellationToken);
        await stream.WriteAsync(new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 }, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        await Task.Delay(100, cancellationToken);
    }

    private static async Task<SyntheticTls13ServerCapture> CompleteSyntheticTls13ServerFlightAsync(
        TcpListener listener,
        ushort selectedGroup,
        ushort cipherSuite,
        byte[] realityPrivateKey,
        CancellationToken cancellationToken,
        byte[]? mldsa65PrivateSeed = null,
        bool sendKeyUpdateRequest = false)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out var error),
            error);
        Assert.NotNull(hello);
        Assert.NotNull(hello!.X25519PublicKey);
        await AssertNoPendingClientDataAsync(client, cancellationToken);

        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(clientHello.AsSpan(5));

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        var serverHandshakeState = CreateServerHandshakeState(selectedGroup, keyShares);
        var serverHello = BuildServerHello(hello.SessionId, selectedGroup, cipherSuite, serverHandshakeState.ServerKeyShare);
        transcript.Append(serverHello.AsSpan(5));

        var tlsCipherSuite = RuntimeTls13CipherSuite.Resolve(cipherSuite);
        var keySchedule = RuntimeTls13KeySchedule.Create(
            tlsCipherSuite,
            serverHandshakeState.SharedSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));

        var realitySharedSecret = RuntimeX25519.DeriveSharedSecret(realityPrivateKey, hello.X25519PublicKey!);
        var authKey = RuntimeHkdf.ExtractAndExpandSha256(
            realitySharedSecret,
            hello.Random.AsSpan(0, 20),
            "REALITY"u8,
            RuntimeX25519.KeyLength);

        var syntheticPrivateKey = Enumerable
            .Range(1, RuntimeEd25519.PrivateKeyLength)
            .Select(static value => (byte)value)
            .ToArray();
        var syntheticPublicKey = RuntimeEd25519.DerivePublicKey(syntheticPrivateKey);
        var certificateSignature = HMACSHA512.HashData(authKey, syntheticPublicKey);
        IReadOnlyList<X509Extension>? certificateExtensions = null;
        if (mldsa65PrivateSeed is { Length: > 0 })
        {
            using var mldsa65 = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, mldsa65PrivateSeed);
            var mldsaPayload = BuildMldsa65Payload(
                authKey,
                syntheticPublicKey,
                clientHello.AsSpan(5),
                serverHello.AsSpan(5));
            var mldsaSignature = mldsa65.SignData(mldsaPayload, Array.Empty<byte>());
            certificateExtensions =
            [
                new X509Extension(new Oid("1.3.6.1.4.1.55555.1"), mldsaSignature, critical: false)
            ];
        }

        var rawCertificate = TestCertificateFactory.CreateEd25519Certificate(
            syntheticPublicKey,
            certificateSignature,
            "localhost",
            certificateExtensions);

        using var serverHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ServerHandshakeTrafficSecret);
        using var clientHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ClientHandshakeTrafficSecret);

        var encryptedExtensions = BuildEncryptedExtensions("h2");
        transcript.Append(encryptedExtensions);

        var certificate = BuildCertificate(rawCertificate);
        transcript.Append(certificate);

        var certificateVerifySignature = RuntimeEd25519.Sign(
            syntheticPrivateKey,
            BuildCertificateVerifyData(
                "TLS 1.3, server CertificateVerify",
                transcript.GetHash(tlsCipherSuite.HashAlgorithm)));
        var certificateVerify = BuildCertificateVerify(0x0807, certificateVerifySignature);
        transcript.Append(certificateVerify);

        var finished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ServerHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        transcript.Append(finished);

        await stream.WriteAsync(serverHello, cancellationToken);
        await WriteCompatibilityChangeCipherSpecAsync(stream, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, encryptedExtensions, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificate, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateVerify, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, finished, cancellationToken);

        var expectedClientFinished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ClientHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        var applicationSecrets = keySchedule.CreateApplicationSecrets(
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));
        var clientFinished = await ReadEncryptedHandshakeMessageAsync(
            stream,
            clientHandshakeProtector,
            cancellationToken);
        Assert.Equal(expectedClientFinished, clientFinished);
        transcript.Append(clientFinished);
        using var serverApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ServerApplicationTrafficSecret);
        using var clientApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ClientApplicationTrafficSecret);
        if (sendKeyUpdateRequest)
        {
            await WriteEncryptedRecordAsync(
                stream,
                serverApplicationProtector,
                BuildTls13KeyUpdateMessage(updateRequested: true),
                cancellationToken);
            serverApplicationProtector.AdvanceTrafficSecret();
        }

        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var serverRecord = serverApplicationProtector.Encrypt(
            RuntimeTls13RecordType.ApplicationData,
            serverPayload);
        await stream.WriteAsync(serverRecord, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var clientPayload = await ReadEncryptedApplicationDataAsync(
            stream,
            clientApplicationProtector,
            cancellationToken,
            allowPostHandshakeKeyUpdate: sendKeyUpdateRequest);
        return new SyntheticTls13ServerCapture(serverPayload, clientPayload);
    }

    private static async Task<SyntheticTls13ServerCapture> CompleteSyntheticTls13ServerFlightAfterHelloRetryRequestAsync(
        TcpListener listener,
        ushort helloRetryRequestSelectedGroup,
        ushort finalSelectedGroup,
        ushort cipherSuite,
        byte[] realityPrivateKey,
        CancellationToken cancellationToken,
        byte[]? mldsa65PrivateSeed = null)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var clientHello1 = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello1, out var firstHello, out var error),
            error);
        Assert.NotNull(firstHello);
        Assert.NotNull(firstHello!.X25519PublicKey);
        await AssertNoPendingClientDataAsync(client, cancellationToken);

        var tlsCipherSuite = RuntimeTls13CipherSuite.Resolve(cipherSuite);
        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(clientHello1.AsSpan(5));

        var cookieExtensionPayload = BuildCookieExtensionPayload([0xA1, 0xB2, 0xC3, 0xD4]);
        var helloRetryRequest = BuildHelloRetryRequest(
            firstHello.SessionId,
            helloRetryRequestSelectedGroup,
            cipherSuite,
            cookieExtensionPayload);
        transcript.ReplaceClientHelloWithMessageHashAndAppendHelloRetryRequest(
            tlsCipherSuite.HashAlgorithm,
            helloRetryRequest.AsSpan(5));

        await stream.WriteAsync(helloRetryRequest, cancellationToken);
        await WriteCompatibilityChangeCipherSpecAsync(stream, cancellationToken);
        await ConsumeCompatibilityChangeCipherSpecAsync(stream, cancellationToken);

        var clientHello2 = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello2, out var secondHello, out var retryError),
            retryError);
        Assert.NotNull(secondHello);
        Assert.Equal(firstHello.SessionId, secondHello!.SessionId);
        Assert.Equal(firstHello.Random, secondHello.Random);

        var cookieExtension = secondHello.Extensions.Single(static extension => extension.Type == 0x002C);
        Assert.Equal(cookieExtensionPayload, cookieExtension.Payload);

        var retryKeyShares = ParseKeyShares(secondHello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        if (helloRetryRequestSelectedGroup == 0)
        {
            Assert.Contains(retryKeyShares, entry => entry.Group == finalSelectedGroup);
        }
        else
        {
            Assert.Single(retryKeyShares);
            Assert.Equal(helloRetryRequestSelectedGroup, retryKeyShares[0].Group);
        }

        transcript.Append(clientHello2.AsSpan(5));

        var serverHandshakeState = CreateServerHandshakeState(finalSelectedGroup, retryKeyShares);
        var serverHello = BuildServerHello(secondHello.SessionId, finalSelectedGroup, cipherSuite, serverHandshakeState.ServerKeyShare);
        transcript.Append(serverHello.AsSpan(5));

        var keySchedule = RuntimeTls13KeySchedule.Create(
            tlsCipherSuite,
            serverHandshakeState.SharedSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));

        var realitySharedSecret = RuntimeX25519.DeriveSharedSecret(realityPrivateKey, firstHello.X25519PublicKey!);
        var authKey = RuntimeHkdf.ExtractAndExpandSha256(
            realitySharedSecret,
            firstHello.Random.AsSpan(0, 20),
            "REALITY"u8,
            RuntimeX25519.KeyLength);

        var syntheticPrivateKey = Enumerable
            .Range(1, RuntimeEd25519.PrivateKeyLength)
            .Select(static value => (byte)value)
            .ToArray();
        var syntheticPublicKey = RuntimeEd25519.DerivePublicKey(syntheticPrivateKey);
        var certificateSignature = HMACSHA512.HashData(authKey, syntheticPublicKey);
        IReadOnlyList<X509Extension>? certificateExtensions = null;
        if (mldsa65PrivateSeed is { Length: > 0 })
        {
            using var mldsa65 = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, mldsa65PrivateSeed);
            var mldsaPayload = BuildMldsa65Payload(
                authKey,
                syntheticPublicKey,
                clientHello2.AsSpan(5),
                serverHello.AsSpan(5));
            var mldsaSignature = mldsa65.SignData(mldsaPayload, Array.Empty<byte>());
            certificateExtensions =
            [
                new X509Extension(new Oid("1.3.6.1.4.1.55555.1"), mldsaSignature, critical: false)
            ];
        }

        var rawCertificate = TestCertificateFactory.CreateEd25519Certificate(
            syntheticPublicKey,
            certificateSignature,
            "localhost",
            certificateExtensions);

        using var serverHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ServerHandshakeTrafficSecret);
        using var clientHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ClientHandshakeTrafficSecret);

        var encryptedExtensions = BuildEncryptedExtensions("h2");
        transcript.Append(encryptedExtensions);

        var certificate = BuildCertificate(rawCertificate);
        transcript.Append(certificate);

        var certificateVerifySignature = RuntimeEd25519.Sign(
            syntheticPrivateKey,
            BuildCertificateVerifyData(
                "TLS 1.3, server CertificateVerify",
                transcript.GetHash(tlsCipherSuite.HashAlgorithm)));
        var certificateVerify = BuildCertificateVerify(0x0807, certificateVerifySignature);
        transcript.Append(certificateVerify);

        var finished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ServerHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        transcript.Append(finished);

        await stream.WriteAsync(serverHello, cancellationToken);
        await WriteCompatibilityChangeCipherSpecAsync(stream, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, encryptedExtensions, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificate, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateVerify, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, finished, cancellationToken);

        var expectedClientFinished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ClientHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        var applicationSecrets = keySchedule.CreateApplicationSecrets(
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));
        var clientFinished = await ReadEncryptedHandshakeMessageAsync(
            stream,
            clientHandshakeProtector,
            cancellationToken);
        Assert.Equal(expectedClientFinished, clientFinished);
        transcript.Append(clientFinished);
        using var serverApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ServerApplicationTrafficSecret);
        using var clientApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ClientApplicationTrafficSecret);

        var serverPayload = Encoding.ASCII.GetBytes("server->client");
        var serverRecord = serverApplicationProtector.Encrypt(
            RuntimeTls13RecordType.ApplicationData,
            serverPayload);
        await stream.WriteAsync(serverRecord, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var clientPayload = await ReadEncryptedApplicationDataAsync(
            stream,
            clientApplicationProtector,
            cancellationToken);
        return new SyntheticTls13ServerCapture(serverPayload, clientPayload);
    }

    private static async Task<RealCertificateSpiderCapture> CompleteRealCertificateTls13ServerFlightAndCaptureSpiderAsync(
        TcpListener listener,
        byte[] realityPrivateKey,
        CancellationToken cancellationToken)
        => (await CompleteRealCertificateTls13ServerFlightAndCaptureSpiderRequestsAsync(
                listener,
                realityPrivateKey,
                expectedRequestCount: 1,
                cancellationToken)
            )
            .Single();

    private static async Task<RealCertificateSpiderCapture> CaptureHttp2SpiderRequestAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
        => (await CaptureHttp2SpiderRequestsAsync(
                listener,
                expectedRequestCount: 1,
                cancellationToken)
            )
            .Single();

    private static async Task<IReadOnlyList<RealCertificateSpiderCapture>> CaptureHttp2SpiderRequestsAsync(
        TcpListener listener,
        int expectedRequestCount,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        return await CaptureHttp2SpiderRequestsAsync(stream, expectedRequestCount, cancellationToken);
    }

    private static async Task<IReadOnlyList<RealCertificateSpiderCapture>> CompleteRealCertificateTls13ServerFlightAndCaptureSpiderRequestsAsync(
        TcpListener listener,
        byte[] realityPrivateKey,
        int expectedRequestCount,
        CancellationToken cancellationToken)
    {
        if (expectedRequestCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedRequestCount));
        }

        const ushort selectedGroup = 0x001D;
        const ushort cipherSuite = 0x1301;

        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out var error),
            error);
        Assert.NotNull(hello);
        Assert.NotNull(hello!.X25519PublicKey);
        await AssertNoPendingClientDataAsync(client, cancellationToken);

        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(clientHello.AsSpan(5));

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        var serverHandshakeState = CreateServerHandshakeState(selectedGroup, keyShares);
        var serverHello = BuildServerHello(hello.SessionId, selectedGroup, cipherSuite, serverHandshakeState.ServerKeyShare);
        transcript.Append(serverHello.AsSpan(5));

        var tlsCipherSuite = RuntimeTls13CipherSuite.Resolve(cipherSuite);
        var keySchedule = RuntimeTls13KeySchedule.Create(
            tlsCipherSuite,
            serverHandshakeState.SharedSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));

        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate(
            "localhost",
            ["localhost"]);
        var rawCertificate = certificate.Export(X509ContentType.Cert);

        var encryptedExtensions = BuildEncryptedExtensions("h2");
        transcript.Append(encryptedExtensions);

        var certificateMessage = BuildCertificate(rawCertificate);
        transcript.Append(certificateMessage);

        using var rsa = certificate.GetRSAPrivateKey();
        Assert.NotNull(rsa);
        var certificateVerifySignature = rsa!.SignData(
            BuildCertificateVerifyData(
                "TLS 1.3, server CertificateVerify",
                transcript.GetHash(tlsCipherSuite.HashAlgorithm)),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var certificateVerify = BuildCertificateVerify(0x0804, certificateVerifySignature);
        transcript.Append(certificateVerify);

        var finished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ServerHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        transcript.Append(finished);

        using var serverHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ServerHandshakeTrafficSecret);
        using var clientHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            keySchedule.ClientHandshakeTrafficSecret);

        await stream.WriteAsync(serverHello, cancellationToken);
        await WriteCompatibilityChangeCipherSpecAsync(stream, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, encryptedExtensions, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateMessage, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, certificateVerify, cancellationToken);
        await WriteEncryptedRecordAsync(stream, serverHandshakeProtector, finished, cancellationToken);

        var expectedClientFinished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ClientHandshakeTrafficSecret,
            transcript.GetHash(tlsCipherSuite.HashAlgorithm),
            tlsCipherSuite);
        var applicationSecrets = keySchedule.CreateApplicationSecrets(
            transcript.GetHash(tlsCipherSuite.HashAlgorithm));
        var clientFinished = await ReadEncryptedHandshakeMessageAsync(
            stream,
            clientHandshakeProtector,
            cancellationToken);
        Assert.Equal(expectedClientFinished, clientFinished);
        transcript.Append(clientFinished);
        using var clientApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ClientApplicationTrafficSecret);
        using var serverApplicationProtector = RuntimeTls13TrafficProtector.Create(
            tlsCipherSuite,
            applicationSecrets.ServerApplicationTrafficSecret);
        await using var realityApplicationStream = new RuntimeTls13DuplexStream(
            stream,
            clientApplicationProtector,
            serverApplicationProtector);

        return await CaptureHttp2SpiderRequestsAsync(
                realityApplicationStream,
                expectedRequestCount,
                cancellationToken)
            ;
    }

    private static async Task<IReadOnlyList<RealCertificateSpiderCapture>> CaptureHttp2SpiderRequestsAsync(
        Stream applicationStream,
        int expectedRequestCount,
        CancellationToken cancellationToken)
    {
        if (expectedRequestCount <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedRequestCount));
        }

        var preface = await ReadExactBytesAsync(applicationStream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(applicationStream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(applicationStream, cancellationToken);

        var captures = new List<RealCertificateSpiderCapture>(expectedRequestCount);
        for (var requestIndex = 0; requestIndex < expectedRequestCount; requestIndex++)
        {
            var request = await ReadHttp2RequestHeadersWithStreamIdAsync(
                applicationStream,
                cancellationToken);
            captures.Add(new RealCertificateSpiderCapture(request.Headers[":path"], request.Headers));

            await WriteHttp2HeadersStatusAsync(
                applicationStream,
                streamId: request.StreamId,
                cancellationToken);
            await WriteHttp2DataAsync(
                applicationStream,
                Encoding.ASCII.GetBytes("<a href=\"/next\">next</a>"),
                streamId: request.StreamId,
                endStream: true,
                cancellationToken);
        }

        return captures;
    }

    private static Tls13ServerHandshakeState CreateServerHandshakeState(
        ushort selectedGroup,
        IReadOnlyList<KeyShareEntry> keyShares)
    {
        var clientKeyShare = keyShares.Single(entry => entry.Group == selectedGroup).KeyExchange;

        switch (selectedGroup)
        {
            case 0x001D:
                using (var keyPair = RuntimeX25519.CreateKeyPair())
                {
                    return new Tls13ServerHandshakeState(
                        keyPair.PublicKey.ToArray(),
                        RuntimeX25519.DeriveSharedSecret(keyPair.PrivateKey, clientKeyShare));
                }
            case RuntimeTlsNamedGroups.X25519Kyber768Draft00:
                {
                    var exchange = RuntimeX25519Kyber768Draft00.Encapsulate(clientKeyShare);
                    return new Tls13ServerHandshakeState(
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case RuntimeTlsNamedGroups.X25519MLKem768:
                {
                    var exchange = RuntimeX25519MlKem768.Encapsulate(clientKeyShare);
                    return new Tls13ServerHandshakeState(
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case RuntimeTlsNamedGroups.Secp256r1MLKem768:
                {
                    var exchange = RuntimeSecp256r1MlKem768.Encapsulate(clientKeyShare);
                    return new Tls13ServerHandshakeState(
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case 0x0017:
                using (var keyPair = RuntimeSecp256r1.CreateKeyPair())
                {
                    return new Tls13ServerHandshakeState(
                        keyPair.PublicKey.ToArray(),
                        RuntimeSecp256r1.DeriveSharedSecret(keyPair.PrivateKey, clientKeyShare));
                }
            case RuntimeTlsNamedGroups.Secp384r1MLKem1024:
                {
                    var exchange = RuntimeSecp384r1MlKem1024.Encapsulate(clientKeyShare);
                    return new Tls13ServerHandshakeState(
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case 0x0018:
                using (var keyPair = RuntimeSecp384r1.CreateKeyPair())
                {
                    return new Tls13ServerHandshakeState(
                        keyPair.PublicKey.ToArray(),
                        RuntimeSecp384r1.DeriveSharedSecret(keyPair.PrivateKey, clientKeyShare));
                }
            case RuntimeTlsNamedGroups.Secp521r1:
                using (var keyPair = RuntimeSecp521r1.CreateKeyPair())
                {
                    return new Tls13ServerHandshakeState(
                        keyPair.PublicKey.ToArray(),
                        RuntimeSecp521r1.DeriveSharedSecret(keyPair.PrivateKey, clientKeyShare));
                }
            default:
                throw new NotSupportedException($"Unsupported test key share group 0x{selectedGroup:X4}.");
        }
    }

    private static byte[] BuildEncryptedExtensions(string negotiatedApplicationProtocol)
    {
        using var extensions = new MemoryStream();
        if (!string.IsNullOrWhiteSpace(negotiatedApplicationProtocol))
        {
            var protocolBytes = Encoding.ASCII.GetBytes(negotiatedApplicationProtocol.Trim());
            using var alpnPayload = new MemoryStream();
            WriteUInt16(alpnPayload, checked((ushort)(protocolBytes.Length + 1)));
            alpnPayload.WriteByte(checked((byte)protocolBytes.Length));
            alpnPayload.Write(protocolBytes);
            var alpnBytes = alpnPayload.ToArray();

            WriteUInt16(extensions, 0x0010);
            WriteUInt16(extensions, checked((ushort)alpnBytes.Length));
            extensions.Write(alpnBytes);
        }

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        body.Write(extensionBytes);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.EncryptedExtensions, body.ToArray());
    }

    private static byte[] BuildCertificate(ReadOnlySpan<byte> rawCertificate)
    {
        using var certificateEntry = new MemoryStream();
        WriteUInt24(certificateEntry, rawCertificate.Length);
        certificateEntry.Write(rawCertificate);
        WriteUInt16(certificateEntry, 0);
        var certificateEntryBytes = certificateEntry.ToArray();

        using var body = new MemoryStream();
        body.WriteByte(0x00);
        WriteUInt24(body, certificateEntryBytes.Length);
        body.Write(certificateEntryBytes);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.Certificate, body.ToArray());
    }

    private static byte[] BuildTls13CertificateRequestMessage()
    {
        using var extensions = new MemoryStream();
        using var signatureAlgorithms = new MemoryStream();
        WriteUInt16(signatureAlgorithms, 0x0804);
        WriteUInt16(signatureAlgorithms, 0x0805);
        WriteUInt16(signatureAlgorithms, 0x0806);
        WriteUInt16(signatureAlgorithms, 0x0403);
        WriteUInt16(signatureAlgorithms, 0x0503);
        WriteUInt16(signatureAlgorithms, 0x0603);

        using var signatureAlgorithmsExtension = new MemoryStream();
        WriteUInt16(signatureAlgorithmsExtension, checked((ushort)signatureAlgorithms.Length));
        signatureAlgorithms.Position = 0;
        signatureAlgorithms.CopyTo(signatureAlgorithmsExtension);

        WriteUInt16(extensions, 0x000D);
        WriteUInt16(extensions, checked((ushort)signatureAlgorithmsExtension.Length));
        signatureAlgorithmsExtension.Position = 0;
        signatureAlgorithmsExtension.CopyTo(extensions);

        using var body = new MemoryStream();
        body.WriteByte(0x00);
        WriteUInt16(body, checked((ushort)extensions.Length));
        extensions.Position = 0;
        extensions.CopyTo(body);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.CertificateRequest, body.ToArray());
    }

    private static byte[] BuildCertificateVerify(ushort algorithm, ReadOnlySpan<byte> signature)
    {
        using var body = new MemoryStream();
        WriteUInt16(body, algorithm);
        WriteUInt16(body, checked((ushort)signature.Length));
        body.Write(signature);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.CertificateVerify, body.ToArray());
    }

    private static byte[] BuildTls12ServerHelloMessage(
        ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> serverRandom,
        ushort cipherSuite,
        string negotiatedApplicationProtocol,
        ushort selectedVersion = 0x0303)
    {
        using var extensions = new MemoryStream();
        if (!string.IsNullOrWhiteSpace(negotiatedApplicationProtocol))
        {
            var protocolBytes = Encoding.ASCII.GetBytes(negotiatedApplicationProtocol.Trim());
            using var alpnPayload = new MemoryStream();
            WriteUInt16(alpnPayload, checked((ushort)(protocolBytes.Length + 1)));
            alpnPayload.WriteByte(checked((byte)protocolBytes.Length));
            alpnPayload.Write(protocolBytes);

            WriteUInt16(extensions, 0x0010);
            WriteUInt16(extensions, checked((ushort)alpnPayload.Length));
            extensions.Write(alpnPayload.ToArray());
        }

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, selectedVersion);
        body.Write(serverRandom);
        body.WriteByte(checked((byte)sessionId.Length));
        if (!sessionId.IsEmpty)
        {
            body.Write(sessionId);
        }

        WriteUInt16(body, cipherSuite);
        body.WriteByte(0x00);
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        if (extensionBytes.Length > 0)
        {
            body.Write(extensionBytes);
        }

        return BuildHandshakeMessage(RuntimeTls13HandshakeType.ServerHello, body.ToArray());
    }

    private static byte[] BuildTls12CertificateMessage(ReadOnlySpan<byte> rawCertificate)
    {
        using var certificateEntry = new MemoryStream();
        WriteUInt24(certificateEntry, rawCertificate.Length);
        certificateEntry.Write(rawCertificate);
        var certificateEntryBytes = certificateEntry.ToArray();

        using var body = new MemoryStream();
        WriteUInt24(body, certificateEntryBytes.Length);
        body.Write(certificateEntryBytes);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.Certificate, body.ToArray());
    }

    private static byte[] BuildTls12CertificateRequestMessage()
    {
        using var body = new MemoryStream();
        body.WriteByte(0x02);
        body.WriteByte(0x01);
        body.WriteByte(0x40);

        using var supportedSignatureAlgorithms = new MemoryStream();
        WriteUInt16(supportedSignatureAlgorithms, 0x0401);
        WriteUInt16(supportedSignatureAlgorithms, 0x0403);
        WriteUInt16(supportedSignatureAlgorithms, 0x0804);
        WriteUInt16(supportedSignatureAlgorithms, 0x0807);
        WriteUInt16(body, checked((ushort)supportedSignatureAlgorithms.Length));
        supportedSignatureAlgorithms.Position = 0;
        supportedSignatureAlgorithms.CopyTo(body);

        WriteUInt16(body, 0);
        return BuildHandshakeMessage((RuntimeTls13HandshakeType)13, body.ToArray());
    }

    private static byte[] BuildTls12ServerKeyExchangeMessage(
        ushort namedGroup,
        ReadOnlySpan<byte> serverPublicKey,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        SslProtocols negotiatedProtocol,
        ushort signatureAlgorithm,
        object signingKeyMaterial)
    {
        using var signedParameters = new MemoryStream();
        signedParameters.WriteByte(0x03);
        WriteUInt16(signedParameters, namedGroup);
        signedParameters.WriteByte(checked((byte)serverPublicKey.Length));
        signedParameters.Write(serverPublicKey);
        var signedParameterBytes = signedParameters.ToArray();

        var signedData = new byte[clientRandom.Length + serverRandom.Length + signedParameterBytes.Length];
        clientRandom.CopyTo(signedData.AsSpan(0, clientRandom.Length));
        serverRandom.CopyTo(signedData.AsSpan(clientRandom.Length, serverRandom.Length));
        signedParameterBytes.CopyTo(signedData.AsSpan(clientRandom.Length + serverRandom.Length));

        var signature = negotiatedProtocol == SslProtocols.Tls12
            ? SignTls12ServerKeyExchangeDigest(
                signingKeyMaterial,
                signatureAlgorithm,
                CreateTls12ServerKeyExchangeDigest(signatureAlgorithm, signedData))
            : SignLegacyTlsServerKeyExchange(signingKeyMaterial, signedData);

        using var body = new MemoryStream();
        body.Write(signedParameterBytes);
        if (negotiatedProtocol == SslProtocols.Tls12)
        {
            WriteUInt16(body, signatureAlgorithm);
        }

        WriteUInt16(body, checked((ushort)signature.Length));
        body.Write(signature);
        return BuildHandshakeMessage((RuntimeTls13HandshakeType)12, body.ToArray());
    }

    private static byte[] CreateTls12ServerKeyExchangeDigest(
        ushort signatureAlgorithm,
        byte[] signedData)
        => signatureAlgorithm switch
        {
            0x0807 => signedData,
            var algorithm when GetTls12SignatureHashAlgorithm(algorithm) == HashAlgorithmName.SHA1 => SHA1.HashData(signedData),
            var algorithm when GetTls12SignatureHashAlgorithm(algorithm) == HashAlgorithmName.SHA256 => SHA256.HashData(signedData),
            var algorithm when GetTls12SignatureHashAlgorithm(algorithm) == HashAlgorithmName.SHA384 => SHA384.HashData(signedData),
            var algorithm when GetTls12SignatureHashAlgorithm(algorithm) == HashAlgorithmName.SHA512 => SHA512.HashData(signedData),
            _ => throw new NotSupportedException(
                $"Unsupported TLS 1.2 test signature algorithm 0x{signatureAlgorithm:X4}.")
        };

    private static byte[] SignTls12ServerKeyExchangeDigest(
        object signingKeyMaterial,
        ushort signatureAlgorithm,
        byte[] digest)
        => signatureAlgorithm switch
        {
            0x0201 or 0x0401 or 0x0501 or 0x0601 when signingKeyMaterial is RSA rsa
                => rsa.SignHash(digest, GetTls12SignatureHashAlgorithm(signatureAlgorithm), RSASignaturePadding.Pkcs1),
            0x0804 or 0x0805 or 0x0806 when signingKeyMaterial is RSA rsa
                => rsa.SignHash(digest, GetTls12SignatureHashAlgorithm(signatureAlgorithm), RSASignaturePadding.Pss),
            0x0203 or 0x0403 or 0x0503 or 0x0603 when signingKeyMaterial is ECDsa ecdsa
                => ecdsa.SignHash(digest),
            0x0807 when signingKeyMaterial is byte[] ed25519PrivateKey
                => RuntimeEd25519.Sign(ed25519PrivateKey, digest),
            _ => throw new NotSupportedException(
                $"Signing material '{signingKeyMaterial.GetType().Name}' does not support TLS 1.2 signature algorithm 0x{signatureAlgorithm:X4}.")
        };

    private static byte[] SignLegacyTlsServerKeyExchange(
        object signingKeyMaterial,
        byte[] signedData)
        => signingKeyMaterial switch
        {
            RSA rsa => RuntimeRsaPkcs1SignaturePrimitives.SignLegacyMd5Sha1(rsa, signedData),
            ECDsa ecdsa => ecdsa.SignHash(SHA1.HashData(signedData)),
            _ => throw new NotSupportedException(
                $"Signing material '{signingKeyMaterial.GetType().Name}' does not support pre-TLS1.2 ServerKeyExchange signatures.")
        };

    private static HashAlgorithmName GetTls12SignatureHashAlgorithm(ushort signatureAlgorithm)
        => signatureAlgorithm switch
        {
            0x0201 or 0x0203 => HashAlgorithmName.SHA1,
            0x0401 or 0x0403 or 0x0804 => HashAlgorithmName.SHA256,
            0x0501 or 0x0503 or 0x0805 => HashAlgorithmName.SHA384,
            0x0601 or 0x0603 or 0x0806 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException(
                $"Unsupported TLS 1.2 test signature algorithm 0x{signatureAlgorithm:X4}.")
        };

    private static Tls12ServerEphemeralKeyState CreateTls12ServerEphemeralKeyState(ushort namedGroup)
    {
        switch (namedGroup)
        {
            case RuntimeTlsNamedGroups.X25519:
                using (var keyPair = RuntimeX25519.CreateKeyPair())
                {
                    return new Tls12ServerEphemeralKeyState(keyPair.PublicKey.ToArray(), keyPair.PrivateKey.ToArray());
                }
            case RuntimeTlsNamedGroups.Secp256r1:
                using (var keyPair = RuntimeSecp256r1.CreateKeyPair())
                {
                    return new Tls12ServerEphemeralKeyState(keyPair.PublicKey.ToArray(), keyPair.PrivateKey.ToArray());
                }
            case RuntimeTlsNamedGroups.Secp384r1:
                using (var keyPair = RuntimeSecp384r1.CreateKeyPair())
                {
                    return new Tls12ServerEphemeralKeyState(keyPair.PublicKey.ToArray(), keyPair.PrivateKey.ToArray());
                }
            case RuntimeTlsNamedGroups.Secp521r1:
                using (var keyPair = RuntimeSecp521r1.CreateKeyPair())
                {
                    return new Tls12ServerEphemeralKeyState(keyPair.PublicKey.ToArray(), keyPair.PrivateKey.ToArray());
                }
            default:
                throw new NotSupportedException(
                    $"Unsupported TLS 1.2 test named group 0x{namedGroup:X4}.");
        }
    }

    private static byte[] DeriveTls12PreMasterSecret(
        ushort namedGroup,
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> clientKeyShare)
        => namedGroup switch
        {
            RuntimeTlsNamedGroups.X25519 => RuntimeX25519.DeriveSharedSecret(privateKey, clientKeyShare),
            RuntimeTlsNamedGroups.Secp256r1 => RuntimeSecp256r1.DeriveSharedSecret(privateKey, clientKeyShare),
            RuntimeTlsNamedGroups.Secp384r1 => RuntimeSecp384r1.DeriveSharedSecret(privateKey, clientKeyShare),
            RuntimeTlsNamedGroups.Secp521r1 => RuntimeSecp521r1.DeriveSharedSecret(privateKey, clientKeyShare),
            _ => throw new NotSupportedException(
                $"Unsupported TLS 1.2 test named group 0x{namedGroup:X4}.")
        };

    private static byte[] BuildHandshakeMessage(RuntimeTls13HandshakeType handshakeType, ReadOnlySpan<byte> body)
    {
        var message = new byte[4 + body.Length];
        message[0] = (byte)handshakeType;
        WriteUInt24(message.AsSpan(1, 3), body.Length);
        body.CopyTo(message.AsSpan(4));
        return message;
    }

    private static byte[] BuildTls13KeyUpdateMessage(bool updateRequested)
        => BuildHandshakeMessage(
            RuntimeTls13HandshakeType.KeyUpdate,
            [updateRequested ? (byte)0x01 : (byte)0x00]);

    private static byte[] BuildCertificateVerifyData(string context, byte[] transcriptHash)
    {
        var contextBytes = Encoding.ASCII.GetBytes(context);
        var message = new byte[64 + contextBytes.Length + 1 + transcriptHash.Length];
        message.AsSpan(0, 64).Fill(0x20);
        contextBytes.CopyTo(message, 64);
        transcriptHash.CopyTo(message, 64 + contextBytes.Length + 1);
        return message;
    }

    private static byte[] BuildMldsa65Payload(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> clientHelloMessage,
        ReadOnlySpan<byte> serverHelloMessage)
    {
        var payload = new byte[publicKey.Length + clientHelloMessage.Length + serverHelloMessage.Length];
        var offset = 0;
        publicKey.CopyTo(payload);
        offset += publicKey.Length;
        clientHelloMessage.CopyTo(payload.AsSpan(offset));
        offset += clientHelloMessage.Length;
        serverHelloMessage.CopyTo(payload.AsSpan(offset));
        return HMACSHA512.HashData(authKey.ToArray(), payload);
    }

    private static async ValueTask WriteCompatibilityChangeCipherSpecAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> record = new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        await stream.WriteAsync(record, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task AssertNoPendingClientDataAsync(
        TcpClient client,
        CancellationToken cancellationToken)
    {
        await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
        Assert.Equal(0, client.Available);
    }

    private static async ValueTask WriteEncryptedRecordAsync(
        Stream stream,
        RuntimeTls13TrafficProtector protector,
        byte[] handshakeMessage,
        CancellationToken cancellationToken)
    {
        var record = protector.Encrypt(RuntimeTls13RecordType.Handshake, handshakeMessage);
        await stream.WriteAsync(record, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task<byte[]> ReadEncryptedHandshakeMessageAsync(
        Stream stream,
        RuntimeTls13TrafficProtector protector,
        CancellationToken cancellationToken)
    {
        var handshakeBuffer = new ResizableByteQueue();

        while (true)
        {
            var plaintext = await ReadEncryptedTls13PlaintextAsync(
                stream,
                protector,
                cancellationToken);

            Assert.Equal(RuntimeTls13RecordType.Handshake, plaintext.ContentType);
            handshakeBuffer.Append(plaintext.Content);
            if (TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
            {
                return handshakeMessage;
            }
        }
    }

    private static async Task ConsumeCompatibilityChangeCipherSpecAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var record = await RuntimeTls13Record.ReadAsync(stream, allowEof: false, cancellationToken)
            ?? throw new EndOfStreamException("Unexpected EOF while waiting for a compatibility ChangeCipherSpec record.");
        Assert.Equal(RuntimeTls13RecordType.ChangeCipherSpec, record.Type);
        Assert.True(RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload));
    }

    private static async Task<byte[]> ReadEncryptedApplicationDataAsync(
        Stream stream,
        RuntimeTls13TrafficProtector protector,
        CancellationToken cancellationToken,
        bool allowPostHandshakeKeyUpdate = false)
    {
        var handshakeBuffer = allowPostHandshakeKeyUpdate
            ? new ResizableByteQueue()
            : null;

        while (true)
        {
            var plaintext = await ReadEncryptedTls13PlaintextAsync(
                stream,
                protector,
                cancellationToken);
            if (plaintext.ContentType == RuntimeTls13RecordType.ApplicationData)
            {
                return plaintext.Content;
            }

            if (allowPostHandshakeKeyUpdate && plaintext.ContentType == RuntimeTls13RecordType.Handshake)
            {
                handshakeBuffer!.Append(plaintext.Content);
                while (TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
                {
                    HandlePostHandshakeMessage(handshakeMessage, protector);
                }
            }
        }
    }

    private static void HandlePostHandshakeMessage(
        byte[] handshakeMessage,
        RuntimeTls13TrafficProtector protector)
    {
        Assert.Equal(5, handshakeMessage.Length);
        Assert.Equal((byte)RuntimeTls13HandshakeType.KeyUpdate, handshakeMessage[0]);
        Assert.Equal((byte)0x00, handshakeMessage[4]);
        protector.AdvanceTrafficSecret();
    }

    private static async Task<byte[]> ReadTls12PlaintextHandshakeMessageAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var handshakeBuffer = new ResizableByteQueue();
        while (true)
        {
            if (TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
            {
                return handshakeMessage;
            }

            var record = await RuntimeTls13Record.ReadAsync(stream, allowEof: false, cancellationToken)
                ?? throw new EndOfStreamException("Unexpected EOF while reading a TLS 1.2 handshake record.");
            Assert.Equal(RuntimeTls13RecordType.Handshake, record.Type);
            handshakeBuffer.Append(record.Payload);
        }
    }

    private static async ValueTask WriteTls12PlaintextRecordAsync(
        Stream stream,
        RuntimeTls13RecordType type,
        ReadOnlyMemory<byte> payload,
        ushort recordVersion,
        CancellationToken cancellationToken)
    {
        var record = new byte[5 + payload.Length];
        record[0] = (byte)type;
        record[1] = (byte)(recordVersion >> 8);
        record[2] = (byte)recordVersion;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), checked((ushort)payload.Length));
        payload.CopyTo(record.AsMemory(5));
        await stream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static SslProtocols ResolveLegacySslProtocol(ushort selectedVersion)
        => selectedVersion switch
        {
            0x0303 => SslProtocols.Tls12,
            0x0302 => SslProtocols.Tls11,
            0x0301 => SslProtocols.Tls,
            _ => throw new NotSupportedException($"Unsupported TLS test version 0x{selectedVersion:X4}.")
        };

    private static async Task<byte[]> ReadTls12EncryptedApplicationDataAsync(
        Stream stream,
        RuntimeTls12TrafficProtector protector,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(stream, allowEof: false, cancellationToken)
                ?? throw new EndOfStreamException("Unexpected EOF while reading a TLS 1.2 application record.");
            switch (record.Type)
            {
                case RuntimeTls13RecordType.ApplicationData:
                    return protector.Decrypt(RuntimeTls13RecordType.ApplicationData, record.Payload);
                case RuntimeTls13RecordType.Handshake:
                    _ = protector.Decrypt(RuntimeTls13RecordType.Handshake, record.Payload);
                    continue;
                default:
                    throw new InvalidDataException(
                        $"Unexpected TLS record '{record.Type}' while waiting for TLS 1.2 application data.");
            }
        }
    }

    private static async Task ReadTls12EncryptedCloseNotifyAsync(
        Stream stream,
        RuntimeTls12TrafficProtector protector,
        CancellationToken cancellationToken)
    {
        var record = await RuntimeTls13Record.ReadAsync(stream, allowEof: false, cancellationToken)
            ?? throw new EndOfStreamException("Unexpected EOF while waiting for TLS 1.2 close_notify.");
        Assert.Equal(RuntimeTls13RecordType.Alert, record.Type);
        Assert.Equal(
            new byte[] { 0x01, 0x00 },
            protector.Decrypt(RuntimeTls13RecordType.Alert, record.Payload));
    }

    private static async Task<RuntimeTls13Plaintext> ReadEncryptedTls13PlaintextAsync(
        Stream stream,
        RuntimeTls13TrafficProtector protector,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(stream, allowEof: false, cancellationToken)
                ?? throw new EndOfStreamException("Unexpected EOF while reading an encrypted TLS 1.3 record.");

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.ApplicationData:
                    return protector.Decrypt(record.Payload);
                default:
                    throw new InvalidDataException(
                        $"Unexpected TLS record '{record.Type}' while reading encrypted TLS 1.3 payload.");
            }
        }
    }

    private static bool TryReadHandshakeMessage(ResizableByteQueue buffer, out byte[] handshakeMessage)
    {
        handshakeMessage = Array.Empty<byte>();
        if (buffer.Length < 4)
        {
            return false;
        }

        var header = buffer.Slice(0, 4);
        var bodyLength = (header[1] << 16) | (header[2] << 8) | header[3];
        var totalLength = 4 + bodyLength;
        if (buffer.Length < totalLength)
        {
            return false;
        }

        handshakeMessage = buffer.Slice(0, totalLength).ToArray();
        buffer.Consume(totalLength);
        return true;
    }

    private static async Task<Http2TestFrame> ReadHttp2FrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = await ReadExactBytesAsync(stream, 9, cancellationToken);
        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var payload = length == 0
            ? Array.Empty<byte>()
            : await ReadExactBytesAsync(stream, length, cancellationToken);
        return new Http2TestFrame(
            Type: header[3],
            Flags: header[4],
            StreamId:
                ((header[5] & 0x7F) << 24) |
                (header[6] << 16) |
                (header[7] << 8) |
                header[8],
            Payload: payload);
    }

    private static async Task<IReadOnlyDictionary<string, string>> ReadHttp2RequestHeadersAsync(
        Stream stream,
        int expectedStreamId,
        CancellationToken cancellationToken)
    {
        var request = await ReadHttp2RequestHeadersWithStreamIdAsync(stream, cancellationToken);
        Assert.Equal(expectedStreamId, request.StreamId);
        return request.Headers;
    }

    private static async Task<(int StreamId, IReadOnlyDictionary<string, string> Headers)> ReadHttp2RequestHeadersWithStreamIdAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            Assert.Equal(Http2TestFrameTypes.Headers, frame.Type);
            var headerBlock = await ReadHttp2HeaderBlockAsync(stream, frame, cancellationToken);
            return (frame.StreamId, DecodeHttp2RequestHeaders(headerBlock));
        }
    }

    private static async Task<byte[]> ReadHttp2HeaderBlockAsync(
        Stream stream,
        Http2TestFrame firstFrame,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        if (firstFrame.Payload.Length > 0)
        {
            buffer.Write(firstFrame.Payload, 0, firstFrame.Payload.Length);
        }

        if ((firstFrame.Flags & Http2TestFrameFlags.EndHeaders) == Http2TestFrameFlags.EndHeaders)
        {
            return buffer.ToArray();
        }

        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Continuation, frame.Type);
            Assert.Equal(firstFrame.StreamId, frame.StreamId);
            if (frame.Payload.Length > 0)
            {
                buffer.Write(frame.Payload, 0, frame.Payload.Length);
            }

            if ((frame.Flags & Http2TestFrameFlags.EndHeaders) == Http2TestFrameFlags.EndHeaders)
            {
                return buffer.ToArray();
            }
        }
    }

    private static Dictionary<string, string> DecodeHttp2RequestHeaders(byte[] headerBlock)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            Assert.False((first & 0x80) != 0, "Unexpected indexed header field in HTTP/2 request.");
            Assert.False((first & 0x20) != 0, "Unexpected dynamic table size update in HTTP/2 request.");

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var name = nameIndex switch
            {
                1 => ":authority",
                2 => ":method",
                4 => ":path",
                6 => ":scheme",
                54 => "server",
                55 => "set-cookie",
                58 => "user-agent",
                0 => ReadHpackString(headerBlock, ref offset),
                _ => throw new InvalidDataException($"Unsupported HPACK name index in test decoder: {nameIndex}.")
            };
            var value = ReadHpackString(headerBlock, ref offset);
            headers[name] = value;
        }

        return headers;
    }

    private static int ReadHpackInteger(byte[] buffer, ref int offset, int prefixBits)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static string ReadHpackString(byte[] buffer, ref int offset)
    {
        Assert.False((buffer[offset] & 0x80) != 0, "Test decoder does not support Huffman-encoded HPACK strings.");
        var length = ReadHpackInteger(buffer, ref offset, 7);
        var value = Encoding.ASCII.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static async Task WriteHttp2SettingsAsync(Stream stream, CancellationToken cancellationToken)
        => await WriteHttp2FrameAsync(
                stream,
                Http2TestFrameTypes.Settings,
                Http2TestFrameFlags.None,
                streamId: 0,
                payload: Array.Empty<byte>(),
                cancellationToken)
            ;

    private static async Task WriteHttp2HeadersStatusAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
        => await WriteHttp2FrameAsync(
                stream,
                Http2TestFrameTypes.Headers,
                Http2TestFrameFlags.EndHeaders,
                streamId,
                payload: [0x88],
                cancellationToken)
            ;

    private static async Task WriteHttp2DataAsync(
        Stream stream,
        byte[] payload,
        int streamId,
        bool endStream,
        CancellationToken cancellationToken)
        => await WriteHttp2FrameAsync(
                stream,
                Http2TestFrameTypes.Data,
                endStream ? Http2TestFrameFlags.EndStream : Http2TestFrameFlags.None,
                streamId,
                payload,
                cancellationToken)
            ;

    private static async Task WriteHttp2FrameAsync(
        Stream stream,
        byte type,
        byte flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)((payload.Length >> 16) & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)(payload.Length & 0xFF);
        header[3] = type;
        header[4] = flags;
        header[5] = (byte)((streamId >> 24) & 0x7F);
        header[6] = (byte)((streamId >> 16) & 0xFF);
        header[7] = (byte)((streamId >> 8) & 0xFF);
        header[8] = (byte)(streamId & 0xFF);

        await stream.WriteAsync(header.AsMemory(0, header.Length), cancellationToken);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken);
        }

        await stream.FlushAsync(cancellationToken);
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer[read..], cancellationToken);
            if (current == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading the TLS application payload.");
            }

            read += current;
        }
    }

    private static async Task<byte[]> ReadExactBytesAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await ReadExactlyAsync(stream, buffer, cancellationToken);
        return buffer;
    }

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        int selectedGroup,
        ushort cipherSuite,
        ReadOnlySpan<byte> serverKeyShare)
    {
        using var extensions = new MemoryStream();
        WriteUInt16(extensions, 0x002B);
        WriteUInt16(extensions, 0x0002);
        WriteUInt16(extensions, 0x0304);

        using var keySharePayload = new MemoryStream();
        WriteUInt16(keySharePayload, checked((ushort)selectedGroup));
        WriteUInt16(keySharePayload, checked((ushort)serverKeyShare.Length));
        keySharePayload.Write(serverKeyShare);
        var keyShareBytes = keySharePayload.ToArray();
        WriteUInt16(extensions, 0x0033);
        WriteUInt16(extensions, checked((ushort)keyShareBytes.Length));
        extensions.Write(keyShareBytes);

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, 0x0303);
        body.Write(Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray());
        body.WriteByte(checked((byte)sessionId.Length));
        if (sessionId.Length > 0)
        {
            body.Write(sessionId);
        }

        WriteUInt16(body, cipherSuite);
        body.WriteByte(0x00);
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        body.Write(extensionBytes);

        var bodyBytes = body.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        WriteUInt16(record, 0x0303);
        WriteUInt16(record, checked((ushort)(bodyBytes.Length + 4)));
        record.WriteByte(0x02);
        WriteUInt24(record, bodyBytes.Length);
        record.Write(bodyBytes);
        return record.ToArray();
    }

    private static byte[] BuildHelloRetryRequest(
        ReadOnlySpan<byte> sessionId,
        int selectedGroup,
        ushort cipherSuite,
        ReadOnlySpan<byte> cookieExtensionPayload)
    {
        using var extensions = new MemoryStream();
        WriteUInt16(extensions, 0x002B);
        WriteUInt16(extensions, 0x0002);
        WriteUInt16(extensions, 0x0304);

        if (cookieExtensionPayload.Length > 0)
        {
            WriteUInt16(extensions, 0x002C);
            WriteUInt16(extensions, checked((ushort)cookieExtensionPayload.Length));
            extensions.Write(cookieExtensionPayload);
        }

        if (selectedGroup != 0)
        {
            WriteUInt16(extensions, 0x0033);
            WriteUInt16(extensions, 0x0002);
            WriteUInt16(extensions, checked((ushort)selectedGroup));
        }

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, 0x0303);
        body.Write(
        [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        ]);
        body.WriteByte(checked((byte)sessionId.Length));
        if (sessionId.Length > 0)
        {
            body.Write(sessionId);
        }

        WriteUInt16(body, cipherSuite);
        body.WriteByte(0x00);
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        body.Write(extensionBytes);

        var bodyBytes = body.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        WriteUInt16(record, 0x0303);
        WriteUInt16(record, checked((ushort)(bodyBytes.Length + 4)));
        record.WriteByte(0x02);
        WriteUInt24(record, bodyBytes.Length);
        record.Write(bodyBytes);
        return record.ToArray();
    }

    private static byte[] BuildCookieExtensionPayload(ReadOnlySpan<byte> cookie)
    {
        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)cookie.Length));
        payload.Write(cookie);
        return payload.ToArray();
    }

    private static byte[] ExtractTlsClientRandom(ReadOnlySpan<byte> clientHelloMessage)
    {
        Assert.True(clientHelloMessage.Length >= 38);
        Assert.Equal((byte)RuntimeTls13HandshakeType.ClientHello, clientHelloMessage[0]);
        return clientHelloMessage.Slice(6, 32).ToArray();
    }

    private static byte[] ExtractTls12ClientKeyExchangePublicKey(ReadOnlySpan<byte> handshakeMessage)
    {
        Assert.True(handshakeMessage.Length >= 5);
        Assert.Equal(16, handshakeMessage[0]);
        var bodyLength = (handshakeMessage[1] << 16) | (handshakeMessage[2] << 8) | handshakeMessage[3];
        Assert.Equal(bodyLength, handshakeMessage.Length - 4);
        var publicKeyLength = handshakeMessage[4];
        Assert.Equal(publicKeyLength, handshakeMessage.Length - 5);
        return handshakeMessage[5..].ToArray();
    }

    private static byte[] DecryptTls12RsaClientKeyExchangePreMasterSecret(
        ReadOnlySpan<byte> handshakeMessage,
        X509Certificate2 certificate)
    {
        Assert.True(handshakeMessage.Length >= 8);
        Assert.Equal(16, handshakeMessage[0]);
        var bodyLength = (handshakeMessage[1] << 16) | (handshakeMessage[2] << 8) | handshakeMessage[3];
        Assert.Equal(bodyLength, handshakeMessage.Length - 4);
        var encryptedLength = BinaryPrimitives.ReadUInt16BigEndian(handshakeMessage.Slice(4, 2));
        Assert.Equal(encryptedLength, handshakeMessage.Length - 6);

        using var rsa = certificate.GetRSAPrivateKey();
        Assert.NotNull(rsa);
        var preMasterSecret = rsa!.Decrypt(handshakeMessage[6..].ToArray(), RSAEncryptionPadding.Pkcs1);
        Assert.Equal(48, preMasterSecret.Length);
        return preMasterSecret;
    }

    private static void AssertEmptyTls12CertificateMessage(ReadOnlySpan<byte> handshakeMessage)
    {
        Assert.True(handshakeMessage.Length >= 7);
        Assert.Equal((byte)RuntimeTls13HandshakeType.Certificate, handshakeMessage[0]);
        Assert.Equal(3, (handshakeMessage[1] << 16) | (handshakeMessage[2] << 8) | handshakeMessage[3]);
        Assert.Equal(0, (handshakeMessage[4] << 16) | (handshakeMessage[5] << 8) | handshakeMessage[6]);
    }

    private static void AssertEmptyTls13CertificateMessage(ReadOnlySpan<byte> handshakeMessage)
    {
        Assert.True(handshakeMessage.Length >= 8);
        Assert.Equal((byte)RuntimeTls13HandshakeType.Certificate, handshakeMessage[0]);

        var bodyLength = (handshakeMessage[1] << 16) | (handshakeMessage[2] << 8) | handshakeMessage[3];
        Assert.Equal(bodyLength, handshakeMessage.Length - 4);

        var contextLength = handshakeMessage[4];
        Assert.Equal(0, contextLength);
        Assert.Equal(0, (handshakeMessage[5] << 16) | (handshakeMessage[6] << 8) | handshakeMessage[7]);
    }

    private static void WriteUInt16(Stream destination, ushort value)
    {
        destination.WriteByte((byte)(value >> 8));
        destination.WriteByte((byte)value);
    }

    private static void WriteUInt24(Stream destination, int value)
    {
        destination.WriteByte((byte)((value >> 16) & 0xFF));
        destination.WriteByte((byte)((value >> 8) & 0xFF));
        destination.WriteByte((byte)(value & 0xFF));
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }

    private sealed class FakeTlsStream : SslStream
    {
        private readonly Stream _innerStream;

        public FakeTlsStream(Stream innerStream)
            : base(innerStream, leaveInnerStreamOpen: false)
        {
            _innerStream = innerStream;
        }

        public override SslProtocols SslProtocol => SslProtocols.Tls13;

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _innerStream.CanWrite;

        public override bool CanTimeout => _innerStream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int ReadTimeout
        {
            get => _innerStream.ReadTimeout;
            set => _innerStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _innerStream.WriteTimeout;
            set => _innerStream.WriteTimeout = value;
        }

        public override void Flush()
            => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _innerStream.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _innerStream.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();
    }

    private sealed class FakeRealityHandshakeProvider : IRuntimeRealityHandshakeProvider
    {
        public string Identity => "runtime-profile-test-provider";

        public bool WasCalled { get; private set; }

        public Stream? ObservedTransportStream { get; private set; }

        public ValueTask<RuntimeRealityHandshakeResult> SecureAsync(
            RuntimeRealityHandshakeRequest request,
            CancellationToken cancellationToken)
        {
            WasCalled = true;
            ObservedTransportStream = request.TransportStream;

            var tlsStream = new FakeTlsStream(request.TransportStream);
            return ValueTask.FromResult(new RuntimeRealityHandshakeResult
            {
                TransportStream = tlsStream,
                SslStream = tlsStream,
                SecurityState = RuntimeInternetSecurityState.Create(
                    RuntimeInternetSecurityTypes.Reality,
                    SslProtocols.Tls13,
                    request.ApplicationProtocols.FirstOrDefault())
            });
        }
    }

    private sealed record KeyShareEntry(int Group, byte[] KeyExchange);

    private sealed record Tls13ServerHandshakeState(byte[] ServerKeyShare, byte[] SharedSecret);

    private sealed record Tls12ServerEphemeralKeyState(byte[] PublicKey, byte[] PrivateKey);

    private sealed record SyntheticTls13ServerCapture(
        byte[] ServerApplicationData,
        byte[] ClientApplicationData);

    private sealed record StandardTlsServerCapture(
        RuntimeTlsClientHelloMetadata? Metadata,
        SslProtocols NegotiatedSslProtocol,
        string NegotiatedApplicationProtocol,
        byte[] ServerApplicationData,
        byte[] ClientApplicationData);

    private sealed record RealCertificateSpiderCapture(
        string Path,
        IReadOnlyDictionary<string, string> Headers);

    private sealed record Http2TestFrame(
        byte Type,
        byte Flags,
        int StreamId,
        byte[] Payload);

    private static class Http2TestFrameTypes
    {
        public const byte Data = 0x00;
        public const byte Headers = 0x01;
        public const byte RstStream = 0x03;
        public const byte Settings = 0x04;
        public const byte WindowUpdate = 0x08;
        public const byte Continuation = 0x09;
    }

    private enum Tls12ServerCertificateKind
    {
        Rsa,
        Ecdsa,
        Ed25519
    }

    private static class Http2TestFrameFlags
    {
        public const byte None = 0x00;
        public const byte EndStream = 0x01;
        public const byte EndHeaders = 0x04;
        public const byte Ack = 0x01;
    }
}

#pragma warning restore SYSLIB0039

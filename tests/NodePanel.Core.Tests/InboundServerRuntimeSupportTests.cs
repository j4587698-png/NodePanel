using NodePanel.Core.Runtime;
using System.Security.Authentication;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NodePanel.Core.Tests;

public sealed class InboundServerRuntimeSupportTests
{
    private static readonly object WindowsServerTlsProbeSync = new();
    private static Task<bool>? WindowsServerTlsSupportProbeTask;

    [Fact]
    public void BuildAuthenticationOptions_disables_tls_resumption_by_default()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("edge.example.com");
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificate
        };

        var authOptions = TlsInboundConnectionAcceptor.BuildAuthenticationOptions(["h2"], tlsOptions);

        Assert.False(authOptions.AllowTlsResume);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, authOptions.EnabledSslProtocols);
        Assert.NotNull(authOptions.ServerCertificateContext);
    }

    [Fact]
    public void BuildAuthenticationOptions_honors_explicit_tls_resumption_enablement()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("edge.example.com");
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificate,
            EnableTlsSessionResumption = true
        };

        var authOptions = TlsInboundConnectionAcceptor.BuildAuthenticationOptions(["h2"], tlsOptions);

        Assert.True(authOptions.AllowTlsResume);
    }

    [Fact]
    public void BuildAuthenticationOptions_includes_configured_intermediate_certificates()
    {
        using var certificateChain = TestServerCertificateChain.Create("edge.example.com");
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificateChain.Leaf,
            AdditionalCertificates = [certificateChain.Intermediate]
        };

        var authOptions = TlsInboundConnectionAcceptor.BuildAuthenticationOptions(["h2"], tlsOptions);
        Assert.NotNull(authOptions.ServerCertificateContext);
        var certificateContext = authOptions.ServerCertificateContext;
        var intermediateCertificatesProperty = certificateContext.GetType().GetProperty("IntermediateCertificates");

        Assert.NotNull(intermediateCertificatesProperty);
        var intermediateCertificates = Assert.IsAssignableFrom<IEnumerable<X509Certificate2>>(
            intermediateCertificatesProperty!.GetValue(certificateContext));
        var intermediate = Assert.Single(intermediateCertificates);
        Assert.Equal(certificateChain.Intermediate.Thumbprint, intermediate.Thumbprint);
    }

    [Fact]
    public async Task AuthenticateAsServerAsync_accepts_self_signed_server_certificate_with_minimal_options()
    {
        if (!await IsWindowsServerTlsHandshakeSupportedAsync())
        {
            return;
        }

        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        await CompleteLoopbackTlsHandshakeAsync(
            CreateMinimalServerAuthenticationOptions(certificate));
    }

    [Fact]
    public async Task AuthenticateAsServerAsync_accepts_self_signed_server_certificate_with_inbound_runtime_options()
    {
        if (!await IsWindowsServerTlsHandshakeSupportedAsync())
        {
            return;
        }

        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificate
        };

        await CompleteLoopbackTlsHandshakeAsync(
            TlsInboundConnectionAcceptor.BuildAuthenticationOptions(["h2"], tlsOptions));
    }

    [Fact]
    public async Task AuthenticateAsServerAsync_accepts_self_signed_server_certificate_with_empty_alpn()
    {
        if (!await IsWindowsServerTlsHandshakeSupportedAsync())
        {
            return;
        }

        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("tls.example.com", ["tls.example.com"]);
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificate
        };

        await CompleteLoopbackTlsHandshakeAsync(
            TlsInboundConnectionAcceptor.BuildAuthenticationOptions([], tlsOptions),
            targetHost: "tls.example.com");
    }

    [Fact]
    public async Task AuthenticateAsServerAsync_accepts_parallel_handshakes_with_inbound_runtime_options()
    {
        if (!await IsWindowsServerTlsHandshakeSupportedAsync())
        {
            return;
        }

        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("tls.example.com", ["tls.example.com"]);
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificate
        };

        await CompleteConcurrentLoopbackTlsHandshakesAsync(
            static (options, _) => TlsInboundConnectionAcceptor.BuildAuthenticationOptions([], options),
            tlsOptions,
            targetHost: "tls.example.com",
            connectionCount: 4);
    }

    [Fact]
    public async Task HandleTransportAsync_routes_splithttp_requests_into_server_bridge()
    {
        using var stream = new MemoryStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "OPTIONS /xhttp/ HTTP/1.1\r\nHost: edge.example.com\r\nOrigin: https://app.example.com\r\n\r\n"));
        stream.Position = 0;

        await InboundServerRuntimeSupport.HandleTransportAsync(
            stream,
            new object(),
            static _ => new InboundInternetStack(
                InboundTransports.Tls,
                RuntimeInternetTransportProtocols.SplitHttp,
                RuntimeInternetSecurityTypes.Tls),
            static _ => string.Empty,
            static _ => "/xhttp/",
            static _ => 0,
            static _ => 0,
            static _ => RuntimeGrpcTransportOptions.Empty,
            static _ => new RuntimeSplitHttpInboundOptions
            {
                Host = "edge.example.com",
                Path = "/xhttp/",
                XPaddingBytes = new RuntimeInt32Range
                {
                    From = 1,
                    To = 1
                }
            },
            static (_, _) => Task.CompletedTask,
            CancellationToken.None);

        var responseText = Encoding.ASCII.GetString(stream.ToArray());
        Assert.Contains("HTTP/1.1 200 OK", responseText, StringComparison.Ordinal);
        Assert.Contains("Access-Control-Allow-Origin: https://app.example.com", responseText, StringComparison.Ordinal);
    }

    private static async Task CompleteLoopbackTlsHandshakeAsync(
        SslServerAuthenticationOptions serverOptions,
        string targetHost = "localhost")
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptTlsServerAsync(listener, serverOptions, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using var clientStream = client.GetStream();
        await using var clientSsl = new SslStream(
            clientStream,
            leaveInnerStreamOpen: false,
            static (_, _, _, _) => true);
        await clientSsl.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            cts.Token);

        await serverTask;
    }

    private static async Task CompleteConcurrentLoopbackTlsHandshakesAsync(
        Func<RuntimeTlsOptions, int, SslServerAuthenticationOptions> serverOptionsFactory,
        RuntimeTlsOptions tlsOptions,
        string targetHost,
        int connectionCount)
    {
        ArgumentNullException.ThrowIfNull(serverOptionsFactory);
        ArgumentNullException.ThrowIfNull(tlsOptions);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(connectionCount);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptedConnections = new List<Task>(connectionCount);
        var acceptTask = Task.Run(
            async () =>
            {
                for (var index = 0; index < connectionCount; index++)
                {
                    var acceptedClient = await listener.AcceptTcpClientAsync(cts.Token);
                    var serverOptions = serverOptionsFactory(tlsOptions, index);
                    acceptedConnections.Add(AuthenticateAcceptedClientAsync(acceptedClient, serverOptions, cts.Token));
                }

                await Task.WhenAll(acceptedConnections);
            },
            cts.Token);

        var clientTasks = Enumerable.Range(0, connectionCount)
            .Select(_ => ConnectTlsClientAsync(port, targetHost, cts.Token))
            .ToArray();

        await Task.WhenAll(clientTasks);
        await acceptTask;
    }

    private static async Task AcceptTlsServerAsync(
        TcpListener listener,
        SslServerAuthenticationOptions serverOptions,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var serverStream = client.GetStream();
        await using var serverSsl = new SslStream(serverStream, leaveInnerStreamOpen: false);
        await serverSsl.AuthenticateAsServerAsync(serverOptions, cancellationToken);
    }

    private static async Task AuthenticateAcceptedClientAsync(
        TcpClient client,
        SslServerAuthenticationOptions serverOptions,
        CancellationToken cancellationToken)
    {
        using (client)
        {
            await using var serverStream = client.GetStream();
            await using var serverSsl = new SslStream(serverStream, leaveInnerStreamOpen: false);
            await serverSsl.AuthenticateAsServerAsync(serverOptions, cancellationToken);
        }
    }

    private static async Task ConnectTlsClientAsync(
        int port,
        string targetHost,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
        await using var clientStream = client.GetStream();
        await using var clientSsl = new SslStream(
            clientStream,
            leaveInnerStreamOpen: false,
            static (_, _, _, _) => true);
        await clientSsl.AuthenticateAsClientAsync(
            new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            },
            cancellationToken);
    }

    private static SslServerAuthenticationOptions CreateMinimalServerAuthenticationOptions(
        X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var options = new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

        options.ServerCertificateContext = SslStreamCertificateContext.Create(
            certificate,
            additionalCertificates: [],
            offline: true);

        return options;
    }

    private static Task<bool> IsWindowsServerTlsHandshakeSupportedAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(true);
        }

        lock (WindowsServerTlsProbeSync)
        {
            WindowsServerTlsSupportProbeTask ??= ProbeWindowsServerTlsHandshakeSupportAsync();
            return WindowsServerTlsSupportProbeTask;
        }
    }

    private static async Task<bool> ProbeWindowsServerTlsHandshakeSupportAsync()
    {
        try
        {
            using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);
            await CompleteLoopbackTlsHandshakeAsync(CreateMinimalServerAuthenticationOptions(certificate));
            return true;
        }
        catch (Exception ex) when (IsWindowsServerCredentialUnavailable(ex))
        {
            return false;
        }
    }

    private static bool IsWindowsServerCredentialUnavailable(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException!)
        {
            if (current is Win32Exception win32 &&
                (win32.HResult == unchecked((int)0x8009030E) ||
                 win32.Message.Contains("No credentials are available in the security package", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (current is AuthenticationException auth &&
                auth.InnerException is Win32Exception innerWin32 &&
                (innerWin32.HResult == unchecked((int)0x8009030E) ||
                 innerWin32.Message.Contains("No credentials are available in the security package", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private sealed class TestServerCertificateChain : IDisposable
    {
        private TestServerCertificateChain(
            X509Certificate2 root,
            X509Certificate2 intermediate,
            X509Certificate2 leaf)
        {
            Root = root;
            Intermediate = intermediate;
            Leaf = leaf;
        }

        public X509Certificate2 Root { get; }

        public X509Certificate2 Intermediate { get; }

        public X509Certificate2 Leaf { get; }

        public static TestServerCertificateChain Create(string commonName)
        {
            var now = DateTimeOffset.UtcNow;
            using var rootKey = RSA.Create(2048);
            using var intermediateKey = RSA.Create(2048);
            using var leafKey = RSA.Create(2048);

            var rootRequest = CreateCertificateRequest("NodePanel Test Root", rootKey, isCertificateAuthority: true);
            var root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

            var intermediateRequest = CreateCertificateRequest("NodePanel Test Intermediate", intermediateKey, isCertificateAuthority: true);
            using var intermediatePublic = intermediateRequest.Create(root, now.AddDays(-1), now.AddDays(30), CreateSerialNumber());
            using var intermediateWithPrivateKey = intermediatePublic.CopyWithPrivateKey(intermediateKey);
            var intermediate = X509CertificateLoader.LoadCertificate(
                intermediateWithPrivateKey.Export(X509ContentType.Cert));

            var leafRequest = CreateServerCertificateRequest(commonName, leafKey);
            using var leafPublic = leafRequest.Create(intermediateWithPrivateKey, now.AddDays(-1), now.AddDays(30), CreateSerialNumber());
            var leaf = leafPublic.CopyWithPrivateKey(leafKey);

            return new TestServerCertificateChain(root, intermediate, leaf);
        }

        public void Dispose()
        {
            Leaf.Dispose();
            Intermediate.Dispose();
            Root.Dispose();
        }

        private static CertificateRequest CreateCertificateRequest(
            string commonName,
            RSA key,
            bool isCertificateAuthority)
        {
            var request = new CertificateRequest(
                $"CN={commonName}",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
                isCertificateAuthority,
                false,
                0,
                critical: true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
                critical: true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request;
        }

        private static CertificateRequest CreateServerCertificateRequest(string commonName, RSA key)
        {
            var request = new CertificateRequest(
                $"CN={commonName}",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new("1.3.6.1.5.5.7.3.1")
                },
                critical: false));

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(commonName);
            request.CertificateExtensions.Add(sanBuilder.Build());
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            return request;
        }

        private static byte[] CreateSerialNumber()
        {
            var serialNumber = RandomNumberGenerator.GetBytes(16);
            serialNumber[0] &= 0x7F;
            return serialNumber;
        }
    }
}

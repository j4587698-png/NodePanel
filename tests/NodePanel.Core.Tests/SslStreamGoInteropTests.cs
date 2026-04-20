using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[Collection(RuntimeSplitHttpTransportTestCollection.CollectionName)]
public sealed class SslStreamGoInteropTests
{
    private const string ServerName = "tls.example.com";

    [Theory]
    [InlineData("rsa", "stdlib-default")]
    [InlineData("rsa-store-backed", "stdlib-default")]
    [InlineData("rsa-passworded-pfx", "stdlib-default")]
    [InlineData("rsa-raw", "stdlib-default")]
    [InlineData("rsa", "stdlib-tls12")]
    [InlineData("rsa", "stdlib-tls13")]
    [InlineData("rsa", "stdlib-no-pq")]
    [InlineData("rsa", "utls-hellogolang")]
    [InlineData("rsa-store-backed", "utls-hellogolang")]
    [InlineData("rsa", "utls-hellochrome-auto")]
    [InlineData("ecdsa", "stdlib-default")]
    [InlineData("ecdsa", "utls-hellogolang")]
    public async Task Go_tls_clients_can_complete_handshake_with_sslstream_server(string certificateKind, string mode)
    {
        if (!GoInteropTestSupport.TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        var workspaceRoot = GoInteropTestSupport.FindWorkspaceRoot();
        var helperPath = Path.Combine(workspaceRoot, "xray-core", ".codex-probes", "tls-client-probe", "main.go");
        Assert.True(File.Exists(helperPath), $"Missing Go TLS probe helper: {helperPath}");

        using var certificateLease = CreateServerCertificateLease(certificateKind);
        var tlsOptions = new RuntimeTlsOptions
        {
            Certificate = certificateLease.Certificate
        };

        using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcceptTlsClientAsync(
            listener,
            TlsInboundConnectionAcceptor.BuildAuthenticationOptions([], tlsOptions),
            cancellationTokenSource.Token);

        using var process = new Process
        {
            StartInfo = GoInteropTestSupport.CreateGoHelperStartInfo(
                goExecutable,
                workspaceRoot,
                helperPath,
                mode,
                port.ToString(),
                ServerName)
        };

        Assert.True(process.Start(), $"Failed to start Go TLS probe '{mode}'.");

        var processOutputTask = GoInteropTestSupport.WaitForProcessExitAsync(process, cancellationTokenSource.Token);
        (string Stdout, string Stderr) output = (string.Empty, string.Empty);

        try
        {
            output = await processOutputTask;
            await serverTask;
        }
        catch (Exception ex)
        {
            GoInteropTestSupport.TryTerminateProcess(process);
            output = await CaptureProcessOutputSafelyAsync(processOutputTask);

            throw new InvalidOperationException(
                $"Go TLS probe '{mode}' failed to handshake with the .NET SslStream server using certificate kind '{certificateKind}'.{Environment.NewLine}" +
                $"stdout:{Environment.NewLine}{FormatCapturedText(output.Stdout)}{Environment.NewLine}" +
                $"stderr:{Environment.NewLine}{FormatCapturedText(output.Stderr)}",
                ex);
        }

        Assert.True(
            process.ExitCode == 0,
            $"Go TLS probe '{mode}' using certificate kind '{certificateKind}' exited with code {process.ExitCode}.{Environment.NewLine}" +
            $"stdout:{Environment.NewLine}{FormatCapturedText(output.Stdout)}{Environment.NewLine}" +
            $"stderr:{Environment.NewLine}{FormatCapturedText(output.Stderr)}");
        Assert.Contains("ok", output.Stdout, StringComparison.Ordinal);
        Assert.True(
            string.IsNullOrWhiteSpace(output.Stderr),
            $"Go TLS probe '{mode}' stderr:{Environment.NewLine}{output.Stderr}");
    }

    private static TestCertificateLease CreateServerCertificateLease(string certificateKind)
        => certificateKind switch
        {
            "rsa" => new TestCertificateLease(TestCertificateFactory.CreateSelfSignedServerCertificate(ServerName, [ServerName])),
            "rsa-store-backed" => TestCertificateFactory.CreateCurrentUserStoreBackedServerCertificate(ServerName, [ServerName]),
            "rsa-passworded-pfx" => new TestCertificateLease(CreatePasswordedPfxRsaCertificate()),
            "rsa-raw" => new TestCertificateLease(CreateRawRsaCertificate()),
            "ecdsa" => new TestCertificateLease(TestCertificateFactory.CreateSelfSignedEcdsaServerCertificate(ServerName, [ServerName])),
            _ => throw new ArgumentOutOfRangeException(nameof(certificateKind), certificateKind, "Unsupported certificate kind.")
        };

    private static X509Certificate2 CreatePasswordedPfxRsaCertificate()
    {
        using var certificate = CreateRawRsaCertificate();
        const string password = "interop-password";
        var pfx = certificate.Export(X509ContentType.Pfx, password);

        if (OperatingSystem.IsWindows())
        {
            return X509CertificateLoader.LoadPkcs12(
                pfx,
                password,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);
        }

        return X509CertificateLoader.LoadPkcs12(
            pfx,
            password,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 CreateRawRsaCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={ServerName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new("1.3.6.1.5.5.7.3.1")
            },
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(ServerName);
        request.CertificateExtensions.Add(sanBuilder.Build());

        if (!OperatingSystem.IsWindows())
        {
            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(30));
        }

        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        var pfx = certificate.Export(X509ContentType.Pfx);
        return X509CertificateLoader.LoadPkcs12(
            pfx,
            password: (string?)null,
            X509KeyStorageFlags.UserKeySet |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.Exportable);
    }

    private static async Task AcceptTlsClientAsync(
        TcpListener listener,
        SslServerAuthenticationOptions serverOptions,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        await using var sslStream = new SslStream(stream, leaveInnerStreamOpen: false);
        await sslStream.AuthenticateAsServerAsync(serverOptions, cancellationToken);
    }

    private static async Task<(string Stdout, string Stderr)> CaptureProcessOutputSafelyAsync(
        Task<(string Stdout, string Stderr)> processOutputTask)
    {
        try
        {
            return await processOutputTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch
        {
            return (string.Empty, string.Empty);
        }
    }

    private static string FormatCapturedText(string text)
        => string.IsNullOrWhiteSpace(text) ? "(empty)" : text;
}

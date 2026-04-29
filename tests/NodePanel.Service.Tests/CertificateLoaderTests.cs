using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Tests;

public sealed class CertificateLoaderTests
{
    [Fact]
    public void LoadPackage_includes_intermediate_certificates_from_pfx()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), "nodepanel-cert-loader-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        var pfxPath = Path.Combine(tempDirectory, "server-chain.pfx");
        const string password = "test-password";

        try
        {
            using var certificateChain = TestServerCertificateChain.Create("edge.example.com");
            var collection = new X509Certificate2Collection
            {
                certificateChain.Leaf,
                certificateChain.Intermediate
            };
            var pfxBytes = collection.Export(X509ContentType.Pkcs12, password)
                ?? throw new InvalidOperationException("Failed to export test certificate package.");
            File.WriteAllBytes(pfxPath, pfxBytes);

            using var package = CertificateLoader.LoadPackage(new CertificateOptions
            {
                PfxPath = pfxPath,
                PfxPassword = password
            });

            Assert.True(package.Certificate.HasPrivateKey);
            Assert.Equal(certificateChain.Leaf.Thumbprint, package.Certificate.Thumbprint);
            var intermediate = Assert.Single(package.AdditionalCertificates);
            Assert.False(intermediate.HasPrivateKey);
            Assert.Equal(certificateChain.Intermediate.Thumbprint, intermediate.Thumbprint);
        }
        finally
        {
            if (Directory.Exists(tempDirectory))
            {
                Directory.Delete(tempDirectory, recursive: true);
            }
        }
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

            var rootRequest = CreateCertificateAuthorityRequest("NodePanel Test Root", rootKey);
            var root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(30));

            var intermediateRequest = CreateCertificateAuthorityRequest("NodePanel Test Intermediate", intermediateKey);
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

        private static CertificateRequest CreateCertificateAuthorityRequest(string commonName, RSA key)
        {
            var request = new CertificateRequest(
                $"CN={commonName}",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
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

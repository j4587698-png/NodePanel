using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Service.Runtime;

public static class CertificateLoader
{
    public static X509Certificate2 Load(CertificateOptions config)
    {
        ArgumentNullException.ThrowIfNull(config);

        foreach (var flags in GetCandidateKeyStorageFlags())
        {
            try
            {
                return X509CertificateLoader.LoadPkcs12FromFile(
                    config.PfxPath,
                    config.PfxPassword,
                    flags);
            }
            catch (CryptographicException)
            {
            }
        }

        throw new CryptographicException("Unable to load the configured TLS certificate with a usable private key.");
    }

    public static LoadedCertificatePackage LoadPackage(CertificateOptions config)
    {
        ArgumentNullException.ThrowIfNull(config);

        foreach (var flags in GetCandidateKeyStorageFlags())
        {
            try
            {
                var collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                    config.PfxPath,
                    config.PfxPassword,
                    flags);
                return LoadedCertificatePackage.Create(collection);
            }
            catch (CryptographicException)
            {
            }
        }

        throw new CryptographicException("Unable to load the configured TLS certificate package with a usable private key.");
    }

    private static IEnumerable<X509KeyStorageFlags> GetCandidateKeyStorageFlags()
    {
        if (OperatingSystem.IsWindows())
        {
            yield return X509KeyStorageFlags.MachineKeySet |
                         X509KeyStorageFlags.PersistKeySet |
                         X509KeyStorageFlags.Exportable;
            yield return X509KeyStorageFlags.UserKeySet |
                         X509KeyStorageFlags.PersistKeySet |
                         X509KeyStorageFlags.Exportable;
        }

        yield return X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
    }
}

public sealed class LoadedCertificatePackage : IDisposable
{
    private readonly IReadOnlyList<X509Certificate2> _ownedCertificates;
    private bool _disposed;

    private LoadedCertificatePackage(
        IReadOnlyList<X509Certificate2> ownedCertificates,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> additionalCertificates)
    {
        _ownedCertificates = ownedCertificates;
        Certificate = certificate;
        AdditionalCertificates = additionalCertificates;
    }

    public X509Certificate2 Certificate { get; }

    public IReadOnlyList<X509Certificate2> AdditionalCertificates { get; }

    public static LoadedCertificatePackage Create(X509Certificate2Collection collection)
    {
        ArgumentNullException.ThrowIfNull(collection);

        var certificates = collection
            .OfType<X509Certificate2>()
            .ToArray();

        try
        {
            var certificate = certificates.FirstOrDefault(static item => item.HasPrivateKey)
                ?? throw new CryptographicException("The TLS certificate package does not contain a certificate with a private key.");
            var additionalCertificates = certificates
                .Where(item => !SameCertificate(item, certificate))
                .GroupBy(static item => item.Thumbprint ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                .Select(static group => group.First())
                .ToArray();

            return new LoadedCertificatePackage(certificates, certificate, additionalCertificates);
        }
        catch
        {
            DisposeCertificates(certificates);
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        DisposeCertificates(_ownedCertificates);
        _disposed = true;
    }

    private static bool SameCertificate(X509Certificate2 left, X509Certificate2 right)
    {
        if (!string.IsNullOrWhiteSpace(left.Thumbprint) &&
            !string.IsNullOrWhiteSpace(right.Thumbprint))
        {
            return string.Equals(left.Thumbprint, right.Thumbprint, StringComparison.OrdinalIgnoreCase);
        }

        return ReferenceEquals(left, right);
    }

    private static void DisposeCertificates(IEnumerable<X509Certificate2> certificates)
    {
        foreach (var certificate in certificates)
        {
            certificate.Dispose();
        }
    }
}

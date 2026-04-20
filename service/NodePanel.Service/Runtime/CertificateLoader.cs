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

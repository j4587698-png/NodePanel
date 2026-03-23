using System.Security.Cryptography.X509Certificates;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Service.Runtime;

public static class CertificateLoader
{
    public static X509Certificate2 Load(CertificateOptions config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return X509CertificateLoader.LoadPkcs12FromFile(
            config.PfxPath,
            config.PfxPassword,
            ResolveKeyStorageFlags());
    }

    private static X509KeyStorageFlags ResolveKeyStorageFlags()
        => OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.Exportable
            : X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
}

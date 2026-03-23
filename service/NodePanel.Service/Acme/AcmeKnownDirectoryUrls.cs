using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Service.Acme;

internal static class AcmeKnownDirectoryUrls
{
    public const string LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory";
    public const string LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory";

    public static string Resolve(CertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(options.AcmeDirectoryUrl))
        {
            return options.AcmeDirectoryUrl;
        }

        return options.UseStaging ? LetsEncryptStaging : LetsEncryptProduction;
    }
}

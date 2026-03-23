using NodePanel.ControlPlane.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

internal static class AcmeKnownDirectoryUrls
{
    public const string LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory";
    public const string LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory";

    public static Uri Resolve(PanelCertificateRecord certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var value = string.IsNullOrWhiteSpace(certificate.AcmeDirectoryUrl)
            ? (certificate.UseStaging ? LetsEncryptStaging : LetsEncryptProduction)
            : certificate.AcmeDirectoryUrl.Trim();

        return new Uri(value, UriKind.Absolute);
    }

    public static string NormalizeChallengeType(string challengeType)
        => CertificateChallengeTypes.Normalize(challengeType) switch
        {
            CertificateChallengeTypes.Http01 => CertificateChallengeTypes.Http01,
            CertificateChallengeTypes.Dns01 => CertificateChallengeTypes.Dns01,
            _ => CertificateChallengeTypes.Http01
        };
}

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

internal static class RuntimeServerCertificateValidation
{
    public static bool Validate(
        bool skipCertificateValidation,
        RemoteCertificateValidationCallback? callback,
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors errors)
    {
        if (callback is not null)
        {
            return callback(sender, certificate, chain, errors);
        }

        if (skipCertificateValidation)
        {
            return true;
        }

        return errors == SslPolicyErrors.None;
    }

    public static bool Validate(
        string requestedServerName,
        bool skipCertificateValidation,
        RemoteCertificateValidationCallback? callback,
        object sender,
        X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2> chainCertificates,
        out X509Chain chain,
        out SslPolicyErrors errors)
    {
        chain = new X509Chain();
        errors = SslPolicyErrors.None;

        if (certificate is null)
        {
            errors = SslPolicyErrors.RemoteCertificateNotAvailable;
            return Validate(
                skipCertificateValidation,
                callback,
                sender,
                certificate: null,
                chain: null,
                errors);
        }

        if (skipCertificateValidation && callback is null)
        {
            return true;
        }

        PopulatePolicyErrors(
            requestedServerName,
            certificate,
            chainCertificates,
            chain,
            out errors);

        return Validate(
            skipCertificateValidation,
            callback,
            sender,
            certificate,
            chain,
            errors);
    }

    public static bool ValidateStrictly(
        string requestedServerName,
        X509Certificate2? certificate,
        IReadOnlyList<X509Certificate2> chainCertificates,
        out SslPolicyErrors errors)
    {
        using var chain = new X509Chain();
        if (certificate is null)
        {
            errors = SslPolicyErrors.RemoteCertificateNotAvailable;
            return false;
        }

        PopulatePolicyErrors(
            requestedServerName,
            certificate,
            chainCertificates,
            chain,
            out errors);
        return errors == SslPolicyErrors.None;
    }

    private static void PopulatePolicyErrors(
        string requestedServerName,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> chainCertificates,
        X509Chain chain,
        out SslPolicyErrors errors)
    {
        errors = SslPolicyErrors.None;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.DisableCertificateDownloads = true;

        foreach (var current in chainCertificates)
        {
            if (current.Thumbprint == certificate.Thumbprint)
            {
                continue;
            }

            chain.ChainPolicy.ExtraStore.Add(current);
        }

        try
        {
            if (!chain.Build(certificate))
            {
                errors |= SslPolicyErrors.RemoteCertificateChainErrors;
            }
        }
        catch (CryptographicException)
        {
            errors |= SslPolicyErrors.RemoteCertificateChainErrors;
        }

        if (RuntimeTlsServerNamePolicy.ShouldReject(
                new RuntimeTlsServerNamePolicyOptions
                {
                    RejectUnknownServerName = true
                },
                certificate,
                requestedServerName))
        {
            errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
        }
    }
}

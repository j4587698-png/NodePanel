using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanTlsServerNamePolicyTests
{
    [Fact]
    public void ShouldReject_returns_false_when_reject_unknown_sni_disabled()
    {
        using var certificate = CreateCertificate(["example.com"]);

        var result = TrojanTlsServerNamePolicy.ShouldReject(
            new TrojanTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = false
            },
            certificate,
            "unknown.example.net");

        Assert.False(result);
    }

    [Fact]
    public void ShouldReject_allows_subject_alternative_names_and_single_label_wildcards()
    {
        using var certificate = CreateCertificate(["example.com", "*.example.com"]);

        Assert.False(TrojanTlsServerNamePolicy.ShouldReject(
            new TrojanTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = true
            },
            certificate,
            "example.com"));
        Assert.False(TrojanTlsServerNamePolicy.ShouldReject(
            new TrojanTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = true
            },
            certificate,
            "api.example.com"));
        Assert.True(TrojanTlsServerNamePolicy.ShouldReject(
            new TrojanTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = true
            },
            certificate,
            "deep.api.example.com"));
    }

    [Fact]
    public void ShouldReject_uses_configured_domain_names_when_present()
    {
        using var certificate = CreateCertificate(["placeholder.invalid"]);

        var result = TrojanTlsServerNamePolicy.ShouldReject(
            new TrojanTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = true,
                ConfiguredServerNames = ["edge.example.com", "cdn.example.com"]
            },
            certificate,
            "cdn.example.com");

        Assert.False(result);
    }

    private static X509Certificate2 CreateCertificate(IReadOnlyList<string> dnsNames)
    {
        using var key = RSA.Create(2048);
        var subjectName = dnsNames.Count == 0 ? "localhost" : dnsNames[0].TrimStart('*', '.');
        var request = new CertificateRequest(
            $"CN={subjectName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            subjectAlternativeNames.AddDnsName(dnsName);
        }

        if (dnsNames.Count > 0)
        {
            request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        }

        var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
#pragma warning disable SYSLIB0057
        return new X509Certificate2(certificate.Export(X509ContentType.Pfx));
#pragma warning restore SYSLIB0057
    }
}

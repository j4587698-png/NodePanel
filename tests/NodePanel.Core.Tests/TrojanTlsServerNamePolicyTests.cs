using System.Security.Cryptography.X509Certificates;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeTlsServerNamePolicyTests
{
    [Fact]
    public void ShouldReject_returns_false_when_reject_unknown_sni_disabled()
    {
        using var certificate = CreateCertificate(["example.com"]);

        var result = RuntimeTlsServerNamePolicy.ShouldReject(
            new RuntimeTlsServerNamePolicyOptions
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

        Assert.False(RuntimeTlsServerNamePolicy.ShouldReject(
            new RuntimeTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = true
            },
            certificate,
            "example.com"));
        Assert.False(RuntimeTlsServerNamePolicy.ShouldReject(
            new RuntimeTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = true
            },
            certificate,
            "api.example.com"));
        Assert.True(RuntimeTlsServerNamePolicy.ShouldReject(
            new RuntimeTlsServerNamePolicyOptions
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

        var result = RuntimeTlsServerNamePolicy.ShouldReject(
            new RuntimeTlsServerNamePolicyOptions
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
        var subjectName = dnsNames.Count == 0 ? "localhost" : dnsNames[0].TrimStart('*', '.');
        return TestCertificateFactory.CreateSelfSignedServerCertificate(
            subjectName,
            dnsNames,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(1));
    }
}

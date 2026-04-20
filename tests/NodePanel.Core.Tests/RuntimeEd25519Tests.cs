using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeEd25519Tests
{
    [Fact]
    public void DerivePublicKey_matches_rfc8032_test_vector_1()
    {
        var privateKey = Convert.FromHexString("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60");
        var expectedPublicKey = Convert.FromHexString("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");

        var publicKey = RuntimeEd25519.DerivePublicKey(privateKey);

        Assert.Equal(expectedPublicKey, publicKey);
    }

    [Fact]
    public void Sign_matches_rfc8032_test_vector_1()
    {
        var privateKey = Convert.FromHexString("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60");
        var expectedSignature = Convert.FromHexString(
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
            "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");

        var signature = RuntimeEd25519.Sign(privateKey, ReadOnlySpan<byte>.Empty);

        Assert.Equal(expectedSignature, signature);
    }

    [Fact]
    public void Verify_accepts_rfc8032_test_vector_1()
    {
        var publicKey = Convert.FromHexString("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
        var signature = Convert.FromHexString(
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
            "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");

        var verified = RuntimeEd25519.Verify(signature, ReadOnlySpan<byte>.Empty, publicKey);

        Assert.True(verified);
    }

    [Fact]
    public void Verify_rejects_modified_signature()
    {
        var publicKey = Convert.FromHexString("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
        var signature = Convert.FromHexString(
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
            "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
        signature[^1] ^= 0x01;

        var verified = RuntimeEd25519.Verify(signature, ReadOnlySpan<byte>.Empty, publicKey);

        Assert.False(verified);
    }

    [Fact]
    public void TryVerifySignature_accepts_ed25519_certificate_verify_signature()
    {
        var publicKey = Convert.FromHexString("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");
        var signature = Convert.FromHexString(
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
            "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B");
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificateFactory.CreateEd25519Certificate(publicKey, new byte[64]));

        var verifier = CreateTryVerifySignatureDelegate();
        var verified = verifier(certificate, 0x0807, [], signature);

        Assert.True(verified);
    }

    private static TryVerifySignatureDelegate CreateTryVerifySignatureDelegate()
    {
        var method = typeof(RuntimeRealityTls13Client).GetMethod(
            "TryVerifySignature",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return method!.CreateDelegate<TryVerifySignatureDelegate>();
    }
    private delegate bool TryVerifySignatureDelegate(
        X509Certificate2 certificate,
        ushort algorithm,
        byte[] data,
        ReadOnlySpan<byte> signature);
}

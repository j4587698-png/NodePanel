using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeRealitySyntheticCertificateValidatorTests
{
    private static readonly byte[] ClientHelloMessage = [0x01, 0x00, 0x00, 0x03, 0x11, 0x22, 0x33];
    private static readonly byte[] ServerHelloMessage = [0x02, 0x00, 0x00, 0x03, 0x44, 0x55, 0x66];

    [Fact]
    public void Validate_accepts_matching_hmac_signature()
    {
        var authKey = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var publicKey = Enumerable.Range(101, 32).Select(static value => (byte)value).ToArray();
        var signature = HMACSHA512.HashData(authKey, publicKey);
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificateFactory.CreateEd25519Certificate(publicKey, signature));

        var result = RuntimeRealitySyntheticCertificateValidator.Validate(
            certificate,
            authKey,
            Array.Empty<byte>(),
            Array.Empty<byte>(),
            RuntimeRealityOptions.Empty);

        Assert.True(result.IsVerified);
        Assert.False(result.CanFallbackToRealCertificate);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Validate_treats_non_matching_hmac_signature_as_real_certificate()
    {
        var authKey = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var publicKey = Enumerable.Range(151, 32).Select(static value => (byte)value).ToArray();
        var signature = HMACSHA512.HashData(authKey, RandomNumberGenerator.GetBytes(32));
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificateFactory.CreateEd25519Certificate(publicKey, signature));

        var result = RuntimeRealitySyntheticCertificateValidator.Validate(
            certificate,
            authKey,
            Array.Empty<byte>(),
            Array.Empty<byte>(),
            RuntimeRealityOptions.Empty);

        Assert.False(result.IsVerified);
        Assert.True(result.CanFallbackToRealCertificate);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Validate_accepts_matching_mldsa65_signature_when_configured()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        var authKey = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var publicKey = Enumerable.Range(201, 32).Select(static value => (byte)value).ToArray();
        var certificateSignature = HMACSHA512.HashData(authKey, publicKey);
        using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var verifyKey = signingKey.ExportMLDsaPublicKey();
        var mldsaSignature = signingKey.SignData(
            BuildMldsa65Payload(authKey, publicKey, ClientHelloMessage, ServerHelloMessage),
            Array.Empty<byte>());
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificateFactory.CreateEd25519Certificate(
            publicKey,
            certificateSignature,
            extensions:
            [
                new X509Extension(new Oid("1.3.6.1.4.1.55555.1"), mldsaSignature, critical: false)
            ]));

        var result = RuntimeRealitySyntheticCertificateValidator.Validate(
            certificate,
            authKey,
            ClientHelloMessage,
            ServerHelloMessage,
            CreateMldsa65Options(verifyKey));

        Assert.True(result.IsVerified);
        Assert.False(result.CanFallbackToRealCertificate);
        Assert.Null(result.Error);
    }

    [Fact]
    public void Validate_rejects_synthetic_certificate_when_mldsa65_extension_is_missing()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        var authKey = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var publicKey = Enumerable.Range(51, 32).Select(static value => (byte)value).ToArray();
        var certificateSignature = HMACSHA512.HashData(authKey, publicKey);
        using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificateFactory.CreateEd25519Certificate(
            publicKey,
            certificateSignature));

        var result = RuntimeRealitySyntheticCertificateValidator.Validate(
            certificate,
            authKey,
            ClientHelloMessage,
            ServerHelloMessage,
            CreateMldsa65Options(signingKey.ExportMLDsaPublicKey()));

        Assert.False(result.IsVerified);
        Assert.False(result.CanFallbackToRealCertificate);
        Assert.Contains("extension", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Validate_rejects_synthetic_certificate_when_mldsa65_verify_key_does_not_match()
    {
        if (!MLDsa.IsSupported)
        {
            return;
        }

        var authKey = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var publicKey = Enumerable.Range(151, 32).Select(static value => (byte)value).ToArray();
        var certificateSignature = HMACSHA512.HashData(authKey, publicKey);
        using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var differentVerifyKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var mldsaSignature = signingKey.SignData(
            BuildMldsa65Payload(authKey, publicKey, ClientHelloMessage, ServerHelloMessage),
            Array.Empty<byte>());
        using var certificate = X509CertificateLoader.LoadCertificate(TestCertificateFactory.CreateEd25519Certificate(
            publicKey,
            certificateSignature,
            extensions:
            [
                new X509Extension(new Oid("1.3.6.1.4.1.55555.1"), mldsaSignature, critical: false)
            ]));

        var result = RuntimeRealitySyntheticCertificateValidator.Validate(
            certificate,
            authKey,
            ClientHelloMessage,
            ServerHelloMessage,
            CreateMldsa65Options(differentVerifyKey.ExportMLDsaPublicKey()));

        Assert.False(result.IsVerified);
        Assert.False(result.CanFallbackToRealCertificate);
        Assert.Contains("verification failed", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    private static RuntimeRealityOptions CreateMldsa65Options(byte[] verifyKey)
        => new()
        {
            Mldsa65Verify = ToBase64Url(verifyKey)
        };

    private static byte[] BuildMldsa65Payload(
        byte[] authKey,
        byte[] publicKey,
        byte[] clientHelloMessage,
        byte[] serverHelloMessage)
    {
        var payload = new byte[publicKey.Length + clientHelloMessage.Length + serverHelloMessage.Length];
        var offset = 0;
        Buffer.BlockCopy(publicKey, 0, payload, offset, publicKey.Length);
        offset += publicKey.Length;
        Buffer.BlockCopy(clientHelloMessage, 0, payload, offset, clientHelloMessage.Length);
        offset += clientHelloMessage.Length;
        Buffer.BlockCopy(serverHelloMessage, 0, payload, offset, serverHelloMessage.Length);
        return HMACSHA512.HashData(authKey, payload);
    }

    private static string ToBase64Url(byte[] value)
        => Convert
            .ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

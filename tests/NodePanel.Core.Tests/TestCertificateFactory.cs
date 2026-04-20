using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Tests;

internal static class TestCertificateFactory
{
    public static TestCertificateLease CreateCurrentUserStoreBackedServerCertificate(
        string commonName,
        IReadOnlyList<string>? dnsNames = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new TestCertificateLease(CreateSelfSignedServerCertificate(commonName, dnsNames, notBefore, notAfter));
        }

        using var certificate = CreateSelfSignedServerCertificate(commonName, dnsNames, notBefore, notAfter);
        return ImportIntoStore(certificate, StoreName.My, StoreLocation.CurrentUser);
    }

    public static X509Certificate2 CreateSelfSignedServerCertificate(
        string commonName,
        IReadOnlyList<string>? dnsNames = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={commonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
            critical: false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new("1.3.6.1.5.5.7.3.1")
            },
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (dnsNames is { Count: > 0 })
        {
            var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
            foreach (var dnsName in dnsNames)
            {
                subjectAlternativeNameBuilder.AddDnsName(dnsName);
            }

            request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());
        }

        using var certificate = request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(30));

        var pfx = certificate.Export(X509ContentType.Pfx);
        return LoadServerCertificate(pfx);
    }

    public static X509Certificate2 CreateSelfSignedEcdsaServerCertificate(
        string commonName,
        IReadOnlyList<string>? dnsNames = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            $"CN={commonName}",
            ecdsa,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,
            critical: false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection
            {
                new("1.3.6.1.5.5.7.3.1")
            },
            critical: false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        if (dnsNames is { Count: > 0 })
        {
            var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
            foreach (var dnsName in dnsNames)
            {
                subjectAlternativeNameBuilder.AddDnsName(dnsName);
            }

            request.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());
        }

        using var certificate = request.CreateSelfSigned(
            notBefore ?? DateTimeOffset.UtcNow.AddDays(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(30));

        var pfx = certificate.Export(X509ContentType.Pfx);
        return LoadServerCertificate(pfx);
    }

    public static byte[] CreateEd25519Certificate(
        byte[] publicKey,
        byte[] signature,
        string commonName = "synthetic.example",
        IReadOnlyList<X509Extension>? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

        var subjectName = CreateCommonName(commonName);

        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        tbsWriter.PushSequence();
        var versionTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        tbsWriter.PushSequence(versionTag);
        tbsWriter.WriteInteger(2);
        tbsWriter.PopSequence(versionTag);
        tbsWriter.WriteInteger(1);
        WriteEd25519AlgorithmIdentifier(tbsWriter);
        tbsWriter.WriteEncodedValue(subjectName);
        tbsWriter.PushSequence();
        tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
        tbsWriter.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(7));
        tbsWriter.PopSequence();
        tbsWriter.WriteEncodedValue(subjectName);
        tbsWriter.PushSequence();
        WriteEd25519AlgorithmIdentifier(tbsWriter);
        tbsWriter.WriteBitString(publicKey);
        tbsWriter.PopSequence();
        if (extensions is { Count: > 0 })
        {
            WriteExtensions(tbsWriter, extensions);
        }

        tbsWriter.PopSequence();

        var certificateWriter = new AsnWriter(AsnEncodingRules.DER);
        certificateWriter.PushSequence();
        certificateWriter.WriteEncodedValue(tbsWriter.Encode());
        WriteEd25519AlgorithmIdentifier(certificateWriter);
        certificateWriter.WriteBitString(signature);
        certificateWriter.PopSequence();
        return certificateWriter.Encode();
    }

    private static byte[] CreateCommonName(string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        writer.PushSetOf();
        writer.PushSequence();
        writer.WriteObjectIdentifier("2.5.4.3");
        writer.WriteCharacterString(UniversalTagNumber.UTF8String, value);
        writer.PopSequence();
        writer.PopSetOf();
        writer.PopSequence();
        return writer.Encode();
    }

    private static void WriteEd25519AlgorithmIdentifier(AsnWriter writer)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier("1.3.101.112");
        writer.PopSequence();
    }

    private static void WriteExtensions(AsnWriter writer, IReadOnlyList<X509Extension> extensions)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(extensions);

        var extensionsTag = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);
        writer.PushSequence(extensionsTag);
        writer.PushSequence();
        foreach (var extension in extensions)
        {
            ArgumentNullException.ThrowIfNull(extension);
            ArgumentException.ThrowIfNullOrWhiteSpace(extension.Oid?.Value);

            writer.PushSequence();
            writer.WriteObjectIdentifier(extension.Oid!.Value);
            if (extension.Critical)
            {
                writer.WriteBoolean(true);
            }

            writer.WriteOctetString(extension.RawData);
            writer.PopSequence();
        }

        writer.PopSequence();
        writer.PopSequence(extensionsTag);
    }

    private static X509Certificate2 LoadServerCertificate(byte[] pfx)
    {
        ArgumentNullException.ThrowIfNull(pfx);

        foreach (var flags in GetCandidateKeyStorageFlags())
        {
            try
            {
                return X509CertificateLoader.LoadPkcs12(
                    pfx,
                    password: (string?)null,
                    flags);
            }
            catch (CryptographicException)
            {
            }
        }

        throw new CryptographicException("Unable to load the generated server certificate with a usable private key.");
    }

    private static TestCertificateLease ImportIntoStore(
        X509Certificate2 certificate,
        StoreName storeName,
        StoreLocation storeLocation)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var thumbprint = certificate.Thumbprint;
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadWrite);

        try
        {
            store.Add(certificate);

            var reloadedCertificate = store.Certificates
                .Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                .OfType<X509Certificate2>()
                .FirstOrDefault(static candidate => candidate.HasPrivateKey);

            if (reloadedCertificate is null)
            {
                throw new CryptographicException("Unable to reload the imported certificate from the Windows certificate store.");
            }

            return new TestCertificateLease(
                reloadedCertificate,
                () => RemoveCertificatesFromStore(thumbprint, storeName, storeLocation));
        }
        catch
        {
            RemoveCertificatesFromStore(thumbprint, storeName, storeLocation);
            throw;
        }
    }

    private static void RemoveCertificatesFromStore(
        string thumbprint,
        StoreName storeName,
        StoreLocation storeLocation)
    {
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadWrite);

        var matches = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
        foreach (var match in matches.OfType<X509Certificate2>().ToArray())
        {
            store.Remove(match);
            match.Dispose();
        }
    }

    private static IEnumerable<X509KeyStorageFlags> GetCandidateKeyStorageFlags()
    {
        if (OperatingSystem.IsWindows())
        {
            yield return X509KeyStorageFlags.UserKeySet |
                         X509KeyStorageFlags.PersistKeySet |
                         X509KeyStorageFlags.Exportable;
            yield return X509KeyStorageFlags.MachineKeySet |
                         X509KeyStorageFlags.PersistKeySet |
                         X509KeyStorageFlags.Exportable;
        }

        yield return X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
    }
}

internal sealed class TestCertificateLease : IDisposable
{
    private readonly Action? _cleanup;
    private bool _disposed;

    public TestCertificateLease(X509Certificate2 certificate, Action? cleanup = null)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        _cleanup = cleanup;
    }

    public X509Certificate2 Certificate { get; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            Certificate.Dispose();
        }
        finally
        {
            _cleanup?.Invoke();
            _disposed = true;
        }
    }
}

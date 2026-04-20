using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class RuntimeRealityHandshakeProviders
{
    public static IRuntimeRealityHandshakeProvider Default { get; } = new RuntimeRealityTls13HandshakeProvider();
}

internal sealed class RuntimeRealityTls13HandshakeProvider : IRuntimeRealityHandshakeProvider
{
    public string Identity => "core.reality.tls13.sha256.v1";

    public async ValueTask<RuntimeRealityHandshakeResult> SecureAsync(
        RuntimeRealityHandshakeRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var client = new RuntimeRealityTls13Client(request);
        return await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
    }
}

internal static class RuntimeRealitySyntheticCertificateValidator
{
    private const string Ed25519AlgorithmOid = "1.3.101.112";

    public static RuntimeRealitySyntheticCertificateValidationResult Validate(
        X509Certificate2 certificate,
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> clientHelloMessage,
        ReadOnlySpan<byte> serverHelloMessage,
        RuntimeRealityOptions options)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (!string.Equals(certificate.PublicKey.Oid?.Value, Ed25519AlgorithmOid, StringComparison.Ordinal))
        {
            return RuntimeRealitySyntheticCertificateValidationResult.RealCertificate;
        }

        var publicKey = certificate.GetPublicKey();
        if (publicKey.Length != RuntimeX25519.KeyLength)
        {
            return new RuntimeRealitySyntheticCertificateValidationResult(
                IsVerified: false,
                CanFallbackToRealCertificate: false,
                Error: "REALITY synthetic certificate public key is invalid.");
        }

        byte[] signature;
        try
        {
            signature = ReadCertificateSignature(certificate);
        }
        catch (AsnContentException ex)
        {
            return new RuntimeRealitySyntheticCertificateValidationResult(
                IsVerified: false,
                CanFallbackToRealCertificate: false,
                Error: $"REALITY synthetic certificate signature is malformed: {ex.Message}");
        }

        if (signature.Length == 0)
        {
            return new RuntimeRealitySyntheticCertificateValidationResult(
                IsVerified: false,
                CanFallbackToRealCertificate: false,
                Error: "REALITY synthetic certificate signature is missing.");
        }

        var expected = HMACSHA512.HashData(authKey.ToArray(), publicKey);
        if (!CryptographicOperations.FixedTimeEquals(expected, signature))
        {
            return RuntimeRealitySyntheticCertificateValidationResult.RealCertificate;
        }

        if (!string.IsNullOrWhiteSpace(options.Mldsa65Verify))
        {
            if (!MLDsa.IsSupported)
            {
                return new RuntimeRealitySyntheticCertificateValidationResult(
                    IsVerified: false,
                    CanFallbackToRealCertificate: false,
                    Error: "REALITY ML-DSA-65 verification is not supported on the current .NET runtime.");
            }

            if (clientHelloMessage.Length == 0 ||
                serverHelloMessage.Length == 0)
            {
                return new RuntimeRealitySyntheticCertificateValidationResult(
                    IsVerified: false,
                    CanFallbackToRealCertificate: false,
                    Error: "REALITY synthetic certificate ML-DSA-65 verification requires raw ClientHello and ServerHello messages.");
            }

            if (!RuntimeRealityOptions.TryDecodeBase64Url(options.Mldsa65Verify, out var verifyKey) ||
                verifyKey.Length != MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes)
            {
                return new RuntimeRealitySyntheticCertificateValidationResult(
                    IsVerified: false,
                    CanFallbackToRealCertificate: false,
                    Error: "REALITY ML-DSA-65 verify key is invalid.");
            }

            if (certificate.Extensions.Count == 0)
            {
                return new RuntimeRealitySyntheticCertificateValidationResult(
                    IsVerified: false,
                    CanFallbackToRealCertificate: false,
                    Error: "REALITY synthetic certificate ML-DSA-65 signature extension is missing.");
            }

            var mldsaSignature = certificate.Extensions[0].RawData;
            if (mldsaSignature.Length == 0)
            {
                return new RuntimeRealitySyntheticCertificateValidationResult(
                    IsVerified: false,
                    CanFallbackToRealCertificate: false,
                    Error: "REALITY synthetic certificate ML-DSA-65 signature is missing.");
            }

            var mldsaPayload = BuildMldsa65Payload(authKey, publicKey, clientHelloMessage, serverHelloMessage);
            try
            {
                using var verifier = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, verifyKey);
                if (!verifier.VerifyData(mldsaPayload, mldsaSignature, ReadOnlySpan<byte>.Empty))
                {
                    return new RuntimeRealitySyntheticCertificateValidationResult(
                        IsVerified: false,
                        CanFallbackToRealCertificate: false,
                        Error: "REALITY synthetic certificate ML-DSA-65 verification failed.");
                }
            }
            catch (CryptographicException ex)
            {
                return new RuntimeRealitySyntheticCertificateValidationResult(
                    IsVerified: false,
                    CanFallbackToRealCertificate: false,
                    Error: $"REALITY synthetic certificate ML-DSA-65 verification failed: {ex.Message}");
            }
        }

        return new RuntimeRealitySyntheticCertificateValidationResult(
            IsVerified: true,
            CanFallbackToRealCertificate: false,
            Error: null);
    }

    private static byte[] BuildMldsa65Payload(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> clientHelloMessage,
        ReadOnlySpan<byte> serverHelloMessage)
    {
        var payload = new byte[publicKey.Length + clientHelloMessage.Length + serverHelloMessage.Length];
        var offset = 0;
        publicKey.CopyTo(payload);
        offset += publicKey.Length;
        clientHelloMessage.CopyTo(payload.AsSpan(offset));
        offset += clientHelloMessage.Length;
        serverHelloMessage.CopyTo(payload.AsSpan(offset));
        return HMACSHA512.HashData(authKey.ToArray(), payload);
    }

    private static byte[] ReadCertificateSignature(X509Certificate2 certificate)
    {
        var reader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        _ = sequence.ReadEncodedValue();
        _ = sequence.ReadEncodedValue();
        var signature = sequence.ReadBitString(out var unusedBitCount);
        if (unusedBitCount != 0)
        {
            throw new AsnContentException("REALITY synthetic certificate signature contains unused bits.");
        }

        sequence.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        return signature;
    }
}

internal sealed record RuntimeRealitySyntheticCertificateValidationResult(
    bool IsVerified,
    bool CanFallbackToRealCertificate,
    string? Error)
{
    public static RuntimeRealitySyntheticCertificateValidationResult RealCertificate { get; }
        = new(
            IsVerified: false,
            CanFallbackToRealCertificate: true,
            Error: null);
}

internal static class RuntimeRealityPeerCertificateLoader
{
    private const string Ed25519AlgorithmOid = "1.3.101.112";

    public static X509Certificate2 LoadCertificate(byte[] rawCertificate)
    {
        ArgumentNullException.ThrowIfNull(rawCertificate);

        try
        {
            return X509CertificateLoader.LoadCertificate(rawCertificate);
        }
        catch (CryptographicException)
            when (TryCreateSyntheticEd25519CompatibilityCertificate(rawCertificate, out var compatibilityCertificate) &&
                  compatibilityCertificate.Length > 0)
        {
            return X509CertificateLoader.LoadCertificate(compatibilityCertificate);
        }
    }

    private static bool TryCreateSyntheticEd25519CompatibilityCertificate(
        ReadOnlySpan<byte> rawCertificate,
        out byte[] compatibilityCertificate)
    {
        compatibilityCertificate = [];

        try
        {
            var reader = new AsnReader(rawCertificate.ToArray(), AsnEncodingRules.DER);
            var certificateSequence = reader.ReadSequence();
            var tbsCertificate = certificateSequence.ReadEncodedValue().ToArray();
            _ = certificateSequence.ReadEncodedValue();
            var signature = certificateSequence.ReadBitString(out var signatureUnusedBitCount);
            certificateSequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            if (signatureUnusedBitCount != 0 ||
                signature.Length == 0)
            {
                return false;
            }

            var tbsReader = new AsnReader(tbsCertificate, AsnEncodingRules.DER);
            var tbsSequence = tbsReader.ReadSequence();
            if (tbsSequence.HasData &&
                tbsSequence.PeekTag().TagClass == TagClass.ContextSpecific &&
                tbsSequence.PeekTag().TagValue == 0)
            {
                _ = tbsSequence.ReadEncodedValue();
            }

            _ = tbsSequence.ReadEncodedValue();
            _ = tbsSequence.ReadEncodedValue();
            _ = tbsSequence.ReadEncodedValue();
            _ = tbsSequence.ReadEncodedValue();
            _ = tbsSequence.ReadEncodedValue();

            var subjectPublicKeyInfo = tbsSequence.ReadEncodedValue();
            if (!TryReadSubjectPublicKeyInfo(subjectPublicKeyInfo.Span, out var algorithmOid, out var publicKey) ||
                !string.Equals(algorithmOid, Ed25519AlgorithmOid, StringComparison.Ordinal) ||
                publicKey.Length != RuntimeEd25519.PublicKeyLength)
            {
                return false;
            }

            var extensions = ReadExtensions(tbsSequence);
            tbsSequence.ThrowIfNotEmpty();
            tbsReader.ThrowIfNotEmpty();

            compatibilityCertificate = RuntimeRealitySyntheticCertificateFactory.CreateEd25519Certificate(
                publicKey,
                signature.ToArray(),
                extensions);
            return true;
        }
        catch (AsnContentException)
        {
            compatibilityCertificate = [];
            return false;
        }
    }

    private static bool TryReadSubjectPublicKeyInfo(
        ReadOnlySpan<byte> encodedSubjectPublicKeyInfo,
        out string algorithmOid,
        out byte[] publicKey)
    {
        algorithmOid = string.Empty;
        publicKey = [];

        try
        {
            var reader = new AsnReader(encodedSubjectPublicKeyInfo.ToArray(), AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            var algorithm = sequence.ReadSequence();
            algorithmOid = algorithm.ReadObjectIdentifier();
            while (algorithm.HasData)
            {
                _ = algorithm.ReadEncodedValue();
            }

            publicKey = sequence.ReadBitString(out var unusedBitCount);
            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return unusedBitCount == 0;
        }
        catch (AsnContentException)
        {
            algorithmOid = string.Empty;
            publicKey = [];
            return false;
        }
    }

    private static IReadOnlyList<X509Extension>? ReadExtensions(AsnReader tbsSequence)
    {
        List<X509Extension>? extensions = null;

        while (tbsSequence.HasData)
        {
            var nextTag = tbsSequence.PeekTag();
            if (nextTag.TagClass == TagClass.ContextSpecific &&
                nextTag.TagValue == 3)
            {
                var extensionsContainer = tbsSequence.ReadSequence(
                    new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true));
                var extensionsSequence = extensionsContainer.ReadSequence();
                extensions = [];
                while (extensionsSequence.HasData)
                {
                    var extension = extensionsSequence.ReadSequence();
                    var oid = extension.ReadObjectIdentifier();
                    var critical = extension.HasData &&
                                   extension.PeekTag().TagClass == TagClass.Universal &&
                                   extension.PeekTag().TagValue == (int)UniversalTagNumber.Boolean &&
                                   extension.ReadBoolean();
                    var rawData = extension.ReadOctetString();
                    extension.ThrowIfNotEmpty();
                    extensions.Add(new X509Extension(new Oid(oid), rawData, critical));
                }

                extensionsSequence.ThrowIfNotEmpty();
                extensionsContainer.ThrowIfNotEmpty();
                return extensions;
            }

            _ = tbsSequence.ReadEncodedValue();
        }

        return null;
    }
}

internal enum RuntimeTls13RecordType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
}

internal enum RuntimeTls13HandshakeType : byte
{
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24
}

internal static class RuntimeTlsNamedGroups
{
    public const ushort Secp256r1 = 0x0017;
    public const ushort Secp384r1 = 0x0018;
    public const ushort Secp521r1 = 0x0019;
    public const ushort X25519 = 0x001D;
    public const ushort X25519Kyber768Draft00 = RuntimeX25519Kyber768Draft00.GroupId;
    public const ushort X25519MLKem768 = RuntimeX25519MlKem768.GroupId;
    public const ushort Secp256r1MLKem768 = RuntimeSecp256r1MlKem768.GroupId;
    public const ushort Secp384r1MLKem1024 = RuntimeSecp384r1MlKem1024.GroupId;
}

internal sealed class RuntimeRealityTls13Client
{
    public RuntimeRealityTls13Client(
        RuntimeRealityHandshakeRequest request,
        RuntimeRealityTls13ClientHelloProfile? clientHelloProfileOverride = null)
    {
        _request = request ?? throw new ArgumentNullException(nameof(request));
        _transportStream = request.TransportStream;
        _clientHelloProfileOverride = clientHelloProfileOverride;
    }

    private readonly RuntimeRealityHandshakeRequest _request;
    private readonly Stream _transportStream;
    private readonly RuntimeRealityTls13ClientHelloProfile? _clientHelloProfileOverride;

    public async Task<RuntimeRealityHandshakeResult> ConnectAsync(CancellationToken cancellationToken)
    {
        EnsureTls13IsEnabled();

        if (!_request.RealityOptions.TryValidateForReality(
                out var normalizedRealityOptions,
                out var validationError))
        {
            throw new NotSupportedException(
                string.IsNullOrWhiteSpace(validationError)
                    ? "REALITY options are invalid."
                    : validationError);
        }

        var clientHelloProfile =
            _clientHelloProfileOverride ??
            RuntimeRealityTls13ClientHelloProfileCatalog.Resolve(normalizedRealityOptions.Fingerprint);
        var keyShareRequirements = RuntimeTls13KeyShareNegotiation.ResolveClientKeyShareRequirements(clientHelloProfile);
        var localAddress = RuntimeRealityDebugLogger.DescribeLocalEndPoint(_transportStream);

        using var x25519KeyPair = RuntimeX25519.CreateKeyPair();
        var usesX25519HybridGroup =
            keyShareRequirements.UsesX25519Kyber768Draft00 ||
            keyShareRequirements.UsesX25519MlKem768;
        var reuseHybridClassicalX25519KeyShare = clientHelloProfile.ReuseHybridClassicalX25519KeyShare;
        using var x25519HybridKeyPair = usesX25519HybridGroup && !reuseHybridClassicalX25519KeyShare
            ? RuntimeX25519.CreateKeyPair()
            : null;
        using var x25519MlKem768KeyPair = usesX25519HybridGroup
            ? RuntimeX25519MlKem768.CreateMlKemKeyPair()
            : null;
        using var secp256r1KeyPair = RuntimeSecp256r1.CreateKeyPair();
        using var secp256r1MlKem768KeyPair = keyShareRequirements.UsesSecp256r1MlKem768
            ? RuntimeSecp256r1MlKem768.CreateMlKemKeyPair()
            : null;
        using var secp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        using var secp384r1MlKem1024KeyPair = keyShareRequirements.UsesSecp384r1MlKem1024
            ? RuntimeSecp384r1MlKem1024.CreateMlKemKeyPair()
            : null;
        using var secp521r1KeyPair = keyShareRequirements.UsesSecp521r1
            ? RuntimeSecp521r1.CreateKeyPair()
            : null;
        var x25519HybridPublicKey = reuseHybridClassicalX25519KeyShare
            ? x25519KeyPair.PublicKey
            : x25519HybridKeyPair?.PublicKey ?? Array.Empty<byte>();
        var x25519HybridPrivateKey = reuseHybridClassicalX25519KeyShare
            ? x25519KeyPair.PrivateKey
            : x25519HybridKeyPair?.PrivateKey ?? Array.Empty<byte>();
        var keyShares = BuildClientKeyShares(
            x25519KeyPair.PublicKey,
            x25519HybridPublicKey,
            x25519MlKem768KeyPair?.PublicKey ?? Array.Empty<byte>(),
            secp256r1KeyPair.PublicKey,
            secp256r1MlKem768KeyPair?.PublicKey ?? Array.Empty<byte>(),
            secp384r1KeyPair.PublicKey,
            secp521r1KeyPair?.PublicKey ?? Array.Empty<byte>(),
            secp384r1MlKem1024KeyPair?.PublicKey ?? Array.Empty<byte>(),
            reuseHybridClassicalX25519KeyShare);
        var rawClientHello = RuntimeRealityTls13ClientHelloBuilder.Build(
            _request,
            clientHelloProfile,
            keyShares);
        var realityAuthPrivateKey =
            clientHelloProfile.KeyShareGroups.Contains(RuntimeTlsNamedGroups.X25519) ||
            reuseHybridClassicalX25519KeyShare
                ? x25519KeyPair.PrivateKey
                : x25519HybridPrivateKey.Length > 0
                    ? x25519HybridPrivateKey
                    : x25519KeyPair.PrivateKey;
        if (!RuntimeRealityClientHelloProtector.TryProtect(
                rawClientHello,
                realityAuthPrivateKey,
                normalizedRealityOptions,
                DateTimeOffset.UtcNow,
                out var protectedClientHello,
                out var protectionError) ||
            protectedClientHello is null)
        {
            throw new AuthenticationException(
                string.IsNullOrWhiteSpace(protectionError)
                    ? "REALITY client hello protection failed."
                    : protectionError);
        }

        RuntimeRealityDebugLogger.TryWriteLine(
            normalizedRealityOptions.Show,
            $"REALITY localAddr: {localAddress}\thello.SessionId[:16]: {RuntimeRealityDebugLogger.FormatHexPrefix(protectedClientHello.PlainSessionId, 16)}");
        RuntimeRealityDebugLogger.TryWriteLine(
            normalizedRealityOptions.Show,
            $"REALITY localAddr: {localAddress}\tuConn.AuthKey[:16]: {RuntimeRealityDebugLogger.FormatHexPrefix(protectedClientHello.AuthKey, 16)}\tAEAD: {nameof(AesGcm)}");

        var currentClientHelloMessage = protectedClientHello.ProtectedClientHello.AsSpan(5).ToArray();
        var sentCompatibilityChangeCipherSpec = false;

        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(protectedClientHello.ProtectedClientHello.AsSpan(5));

        await _transportStream
            .WriteAsync(protectedClientHello.ProtectedClientHello.AsMemory(0, protectedClientHello.ProtectedClientHello.Length), cancellationToken)
            .ConfigureAwait(false);
        await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var serverHelloMessage = await ReadServerHelloAsync(cancellationToken).ConfigureAwait(false);
        var serverHello = RuntimeTls13ServerHello.Parse(serverHelloMessage);
        if (serverHello.IsHelloRetryRequest)
        {
            var helloRetryRequestCipherSuite = RuntimeTls13CipherSuite.Resolve(serverHello.CipherSuite);
            transcript.ReplaceClientHelloWithMessageHashAndAppendHelloRetryRequest(
                helloRetryRequestCipherSuite.HashAlgorithm,
                serverHelloMessage);

            await WriteCompatibilityChangeCipherSpecAsync(cancellationToken).ConfigureAwait(false);
            await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            sentCompatibilityChangeCipherSpec = true;

            var retryClientHello = CreateHelloRetryRequestClientHello(
                protectedClientHello.ProtectedClientHello,
                protectedClientHello.EncryptedSessionId,
                serverHello,
                keyShares);
            currentClientHelloMessage = retryClientHello.AsSpan(5).ToArray();
            transcript.Append(retryClientHello.AsSpan(5));

            await _transportStream
                .WriteAsync(retryClientHello.AsMemory(0, retryClientHello.Length), cancellationToken)
                .ConfigureAwait(false);
            await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            serverHelloMessage = await ReadServerHelloAsync(cancellationToken).ConfigureAwait(false);
            serverHello = RuntimeTls13ServerHello.Parse(serverHelloMessage);
            if (serverHello.IsHelloRetryRequest)
            {
                throw new AuthenticationException("TLS 1.3 received multiple HelloRetryRequest messages.");
            }

            if (serverHello.CipherSuite != helloRetryRequestCipherSuite.Id)
            {
                throw new AuthenticationException(
                    "TLS 1.3 final ServerHello cipher suite did not match HelloRetryRequest.");
            }
        }

        transcript.Append(serverHelloMessage);
        if (!sentCompatibilityChangeCipherSpec)
        {
            await WriteCompatibilityChangeCipherSpecAsync(cancellationToken).ConfigureAwait(false);
            await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        var cipherSuite = RuntimeTls13CipherSuite.Resolve(serverHello.CipherSuite);
        RuntimeRealityDebugLogger.TryWriteLine(
            normalizedRealityOptions.Show,
            $"REALITY localAddr: {localAddress}\tis using X25519MLKEM768 for TLS' communication: {serverHello.KeyShareGroup == RuntimeTlsNamedGroups.X25519MLKem768}");
        RuntimeRealityDebugLogger.TryWriteLine(
            normalizedRealityOptions.Show,
            $"REALITY localAddr: {localAddress}\tis using ML-DSA-65 for cert's extra verification: {!string.IsNullOrWhiteSpace(normalizedRealityOptions.Mldsa65Verify)}");
        var handshakeSharedSecret = serverHello.KeyShareGroup switch
        {
            RuntimeTlsNamedGroups.X25519 => RuntimeX25519.DeriveSharedSecret(x25519KeyPair.PrivateKey, serverHello.KeyShare),
            RuntimeTlsNamedGroups.X25519Kyber768Draft00 when x25519HybridPrivateKey.Length > 0 && x25519MlKem768KeyPair is not null
                => RuntimeX25519Kyber768Draft00.DeriveSharedSecret(
                    x25519HybridPrivateKey,
                    x25519MlKem768KeyPair.Key,
                    serverHello.KeyShare),
            RuntimeTlsNamedGroups.X25519MLKem768 when x25519HybridPrivateKey.Length > 0 && x25519MlKem768KeyPair is not null
                => RuntimeX25519MlKem768.DeriveSharedSecret(
                    x25519HybridPrivateKey,
                    x25519MlKem768KeyPair.Key,
                    serverHello.KeyShare),
            RuntimeTlsNamedGroups.Secp256r1 => RuntimeSecp256r1.DeriveSharedSecret(secp256r1KeyPair.PrivateKey, serverHello.KeyShare),
            RuntimeTlsNamedGroups.Secp256r1MLKem768 when secp256r1MlKem768KeyPair is not null
                => RuntimeSecp256r1MlKem768.DeriveSharedSecret(
                    secp256r1KeyPair.PrivateKey,
                    secp256r1MlKem768KeyPair.Key,
                    serverHello.KeyShare),
            RuntimeTlsNamedGroups.Secp384r1 => RuntimeSecp384r1.DeriveSharedSecret(secp384r1KeyPair.PrivateKey, serverHello.KeyShare),
            RuntimeTlsNamedGroups.Secp521r1 when secp521r1KeyPair is not null
                => RuntimeSecp521r1.DeriveSharedSecret(secp521r1KeyPair.PrivateKey, serverHello.KeyShare),
            RuntimeTlsNamedGroups.Secp384r1MLKem1024 when secp384r1MlKem1024KeyPair is not null
                => RuntimeSecp384r1MlKem1024.DeriveSharedSecret(
                    secp384r1KeyPair.PrivateKey,
                    secp384r1MlKem1024KeyPair.Key,
                    serverHello.KeyShare),
            _ => throw new AuthenticationException(
                $"TLS 1.3 ServerHello selected unsupported key share group 0x{serverHello.KeyShareGroup:X4}.")
        };
        var keySchedule = RuntimeTls13KeySchedule.Create(
            cipherSuite,
            handshakeSharedSecret,
            transcript.GetHash(cipherSuite.HashAlgorithm));

        using var serverHandshakeProtector = RuntimeTls13TrafficProtector.Create(cipherSuite, keySchedule.ServerHandshakeTrafficSecret);
        using var clientHandshakeProtector = RuntimeTls13TrafficProtector.Create(cipherSuite, keySchedule.ClientHandshakeTrafficSecret);

        var serverPeer = await ReceiveServerHandshakeAsync(
                serverHandshakeProtector,
                transcript,
                protectedClientHello.AuthKey,
                currentClientHelloMessage,
                serverHelloMessage,
                normalizedRealityOptions,
                cipherSuite,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (serverPeer.ServerRequestedClientCertificate)
            {
                var clientCertificateMessage = CreateEmptyClientCertificateMessage(serverPeer.ClientCertificateRequestContext);
                await WriteEncryptedHandshakeAsync(clientHandshakeProtector, clientCertificateMessage, cancellationToken).ConfigureAwait(false);
                transcript.Append(clientCertificateMessage);
            }

            var clientFinishedMessage = RuntimeTls13KeySchedule.CreateFinishedMessage(
                keySchedule.ClientHandshakeTrafficSecret,
                transcript.GetHash(cipherSuite.HashAlgorithm),
                cipherSuite);
            var applicationSecrets = keySchedule.CreateApplicationSecrets(
                transcript.GetHash(cipherSuite.HashAlgorithm));
            await WriteEncryptedHandshakeAsync(clientHandshakeProtector, clientFinishedMessage, cancellationToken).ConfigureAwait(false);
            transcript.Append(clientFinishedMessage);
            var applicationReadProtector = RuntimeTls13TrafficProtector.Create(
                cipherSuite,
                applicationSecrets.ServerApplicationTrafficSecret);
            var applicationWriteProtector = RuntimeTls13TrafficProtector.Create(
                cipherSuite,
                applicationSecrets.ClientApplicationTrafficSecret);
            if (RuntimeRealityClientHelloDocument.TryParse(
                    protectedClientHello.ProtectedClientHello,
                    out var initialClientHello,
                    out _) &&
                initialClientHello is not null)
            {
                RuntimeTlsKeyLogWriter.TryAppendTls13Secrets(
                    normalizedRealityOptions.MasterKeyLog,
                    initialClientHello.Random,
                    keySchedule.ClientHandshakeTrafficSecret,
                    keySchedule.ServerHandshakeTrafficSecret,
                    applicationSecrets.ClientApplicationTrafficSecret,
                    applicationSecrets.ServerApplicationTrafficSecret,
                    normalizedRealityOptions.Show);
            }

            var transportStream = new RuntimeTls13DuplexStream(
                _transportStream,
                applicationReadProtector,
                applicationWriteProtector);
            RuntimeRealityDebugLogger.TryWriteLine(
                normalizedRealityOptions.Show,
                $"REALITY localAddr: {localAddress}\tuConn.Verified: {serverPeer.SyntheticVerified}");

            if (!serverPeer.SyntheticVerified)
            {
                await RuntimeRealitySpider
                    .ProcessInvalidConnectionAsync(
                        transportStream,
                        _request.ServerName,
                        normalizedRealityOptions,
                        localAddress,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var remoteCertificate = X509CertificateLoader.LoadCertificate(serverPeer.LeafCertificate!.RawData);
            return new RuntimeRealityHandshakeResult
            {
                TransportStream = transportStream,
                SecurityState = RuntimeInternetSecurityState.Create(
                    RuntimeInternetSecurityTypes.Reality,
                    SslProtocols.Tls13,
                    serverPeer.NegotiatedApplicationProtocol,
                    remoteCertificate)
            };
        }
        finally
        {
            serverPeer.Dispose();
        }
    }

    private void EnsureTls13IsEnabled()
    {
        if ((_request.EnabledSslProtocols & SslProtocols.Tls13) == 0)
        {
            throw new AuthenticationException("REALITY requires TLS 1.3 support.");
        }
    }

    private ValueTask WriteCompatibilityChangeCipherSpecAsync(CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> record = new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        return _transportStream.WriteAsync(record, cancellationToken);
    }

    private static Dictionary<ushort, byte[]> BuildClientKeyShares(
        ReadOnlySpan<byte> x25519PublicKey,
        ReadOnlySpan<byte> x25519HybridPublicKey,
        ReadOnlySpan<byte> x25519HybridMlKem768PublicKey,
        ReadOnlySpan<byte> secp256r1PublicKey,
        ReadOnlySpan<byte> secp256r1MlKem768PublicKey,
        ReadOnlySpan<byte> secp384r1PublicKey,
        ReadOnlySpan<byte> secp521r1PublicKey,
        ReadOnlySpan<byte> secp384r1MlKem1024PublicKey,
        bool reuseHybridClassicalX25519KeyShare)
    {
        var keyShares = new Dictionary<ushort, byte[]>
        {
            [RuntimeTlsNamedGroups.X25519] = x25519PublicKey.ToArray(),
            [RuntimeTlsNamedGroups.Secp256r1] = secp256r1PublicKey.ToArray(),
            [RuntimeTlsNamedGroups.Secp384r1] = secp384r1PublicKey.ToArray()
        };
        if (secp521r1PublicKey.Length > 0)
        {
            keyShares[RuntimeTlsNamedGroups.Secp521r1] = secp521r1PublicKey.ToArray();
        }

        var x25519HybridClassicalPublicKey = reuseHybridClassicalX25519KeyShare
            ? x25519PublicKey
            : x25519HybridPublicKey;
        if (x25519HybridClassicalPublicKey.Length > 0 &&
            x25519HybridMlKem768PublicKey.Length > 0)
        {
            keyShares[RuntimeTlsNamedGroups.X25519Kyber768Draft00] =
                RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
                    x25519HybridClassicalPublicKey,
                    x25519HybridMlKem768PublicKey);
            keyShares[RuntimeTlsNamedGroups.X25519MLKem768] =
                RuntimeX25519MlKem768.BuildClientKeyShare(
                    x25519HybridClassicalPublicKey,
                    x25519HybridMlKem768PublicKey);
        }

        if (secp256r1MlKem768PublicKey.Length > 0)
        {
            keyShares[RuntimeTlsNamedGroups.Secp256r1MLKem768] =
                RuntimeSecp256r1MlKem768.BuildClientKeyShare(
                    secp256r1PublicKey,
                    secp256r1MlKem768PublicKey);
        }

        if (secp384r1MlKem1024PublicKey.Length > 0)
        {
            keyShares[RuntimeTlsNamedGroups.Secp384r1MLKem1024] =
                RuntimeSecp384r1MlKem1024.BuildClientKeyShare(
                    secp384r1PublicKey,
                    secp384r1MlKem1024PublicKey);
        }

        return keyShares;
    }

    private static byte[] CreateHelloRetryRequestClientHello(
        ReadOnlySpan<byte> protectedClientHello,
        ReadOnlySpan<byte> encryptedSessionId,
        RuntimeTls13ServerHello helloRetryRequest,
        IReadOnlyDictionary<ushort, byte[]> keyShares)
    {
        if (!helloRetryRequest.IsHelloRetryRequest)
        {
            throw new ArgumentException("The supplied ServerHello is not a HelloRetryRequest.", nameof(helloRetryRequest));
        }

        if (!RuntimeRealityClientHelloDocument.TryParse(protectedClientHello, out var clientHello, out var error) ||
            clientHello is null)
        {
            throw new AuthenticationException(
                string.IsNullOrWhiteSpace(error)
                    ? "TLS 1.3 retry ClientHello parsing failed."
                    : error);
        }

        var retryKeyShare = helloRetryRequest.KeyShareGroup switch
        {
            0 => Array.Empty<byte>(),
            _ when keyShares.TryGetValue(helloRetryRequest.KeyShareGroup, out var keyShare) => keyShare,
            _ => throw new AuthenticationException(
                $"TLS 1.3 HelloRetryRequest selected unsupported key share group 0x{helloRetryRequest.KeyShareGroup:X4}.")
        };

        return clientHello.CreateHelloRetryRequestResponse(
            encryptedSessionId,
            helloRetryRequest.KeyShareGroup,
            retryKeyShare,
            helloRetryRequest.HelloRetryRequestCookieExtensionPayload);
    }

    private async Task<byte[]> ReadServerHelloAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(_transportStream, allowEof: false, cancellationToken).ConfigureAwait(false)
                ?? throw new EndOfStreamException("Unexpected EOF while waiting for the TLS 1.3 ServerHello.");

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls13AlertExceptionFactory.Create(record.Payload, encrypted: false);
                case RuntimeTls13RecordType.Handshake:
                    return ParseSingleServerHello(record.Payload);
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' while waiting for the ServerHello.");
            }
        }
    }

    private async Task<RuntimeTls13ServerPeer> ReceiveServerHandshakeAsync(
        RuntimeTls13TrafficProtector serverHandshakeProtector,
        RuntimeTls13HandshakeTranscript transcript,
        byte[] authKey,
        byte[] clientHelloMessage,
        byte[] serverHelloMessage,
        RuntimeRealityOptions normalizedRealityOptions,
        RuntimeTls13CipherSuite cipherSuite,
        CancellationToken cancellationToken)
    {
        var peer = new RuntimeTls13ServerPeer();
        var handshakeBuffer = new ResizableByteQueue();
        var seenCertificate = false;
        var seenFinished = false;

        while (!seenFinished)
        {
            var record = await RuntimeTls13Record.ReadAsync(_transportStream, allowEof: false, cancellationToken).ConfigureAwait(false)
                ?? throw new EndOfStreamException("Unexpected EOF while reading encrypted TLS 1.3 handshake records.");

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls13AlertExceptionFactory.Create(record.Payload, encrypted: false);
                case RuntimeTls13RecordType.ApplicationData:
                    var plaintext = serverHandshakeProtector.Decrypt(record.Payload);
                    switch (plaintext.ContentType)
                    {
                        case RuntimeTls13RecordType.Handshake:
                            handshakeBuffer.Append(plaintext.Content);
                            while (TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
                            {
                                var handshakeType = (RuntimeTls13HandshakeType)handshakeMessage[0];
                                switch (handshakeType)
                                {
                                    case RuntimeTls13HandshakeType.EncryptedExtensions:
                                        peer.NegotiatedApplicationProtocol = ParseEncryptedExtensions(handshakeMessage);
                                        transcript.Append(handshakeMessage);
                                        break;
                                    case RuntimeTls13HandshakeType.CertificateRequest:
                                        if (peer.ServerRequestedClientCertificate)
                                        {
                                            throw new AuthenticationException("TLS 1.3 CertificateRequest was received multiple times.");
                                        }

                                        peer.ServerRequestedClientCertificate = true;
                                        peer.ClientCertificateRequestContext = ParseCertificateRequestContext(handshakeMessage);
                                        transcript.Append(handshakeMessage);
                                        break;
                                    case RuntimeTls13HandshakeType.Certificate:
                                        if (seenCertificate)
                                        {
                                            throw new AuthenticationException("TLS 1.3 Certificate was received multiple times.");
                                        }

                                        seenCertificate = true;
                                        ParseCertificateMessage(handshakeMessage, peer);
                                        var syntheticValidation = RuntimeRealitySyntheticCertificateValidator.Validate(
                                            peer.LeafCertificate!,
                                            authKey,
                                            clientHelloMessage,
                                            serverHelloMessage,
                                            normalizedRealityOptions);
                                        if (!string.IsNullOrWhiteSpace(syntheticValidation.Error))
                                        {
                                            throw new NotSupportedException(syntheticValidation.Error);
                                        }

                                        if (syntheticValidation.IsVerified)
                                        {
                                            peer.SyntheticVerified = true;
                                        }
                                        else if (syntheticValidation.CanFallbackToRealCertificate)
                                        {
                                            var realCertificateAccepted = RuntimeServerCertificateValidation.ValidateStrictly(
                                                _request.ServerName,
                                                peer.LeafCertificate,
                                                peer.CertificateChain,
                                                out var errors);
                                            if (!realCertificateAccepted)
                                            {
                                                throw new AuthenticationException(
                                                    $"REALITY real-certificate fallback validation failed: {errors}.");
                                            }
                                        }

                                        transcript.Append(handshakeMessage);
                                        break;
                                    case RuntimeTls13HandshakeType.CertificateVerify:
                                        if (!seenCertificate)
                                        {
                                            throw new AuthenticationException(
                                                "TLS 1.3 CertificateVerify arrived before Certificate.");
                                        }

                                        VerifyCertificateVerify(
                                            handshakeMessage,
                                            peer,
                                            transcript.GetHash(cipherSuite.HashAlgorithm));
                                        transcript.Append(handshakeMessage);
                                        break;
                                    case RuntimeTls13HandshakeType.Finished:
                                        VerifyServerFinished(
                                            handshakeMessage,
                                            transcript.GetHash(cipherSuite.HashAlgorithm),
                                            serverHandshakeProtector.TrafficSecret,
                                            cipherSuite);
                                        transcript.Append(handshakeMessage);
                                        seenFinished = true;
                                        break;
                                    default:
                                        throw new AuthenticationException(
                                            $"Unexpected TLS 1.3 handshake message '{handshakeType}' before handshake completion.");
                                }
                            }

                            break;
                        case RuntimeTls13RecordType.Alert:
                            throw RuntimeTls13AlertExceptionFactory.Create(plaintext.Content, encrypted: true);
                        default:
                            throw new AuthenticationException(
                                $"Unexpected TLS 1.3 content type '{plaintext.ContentType}' before handshake completion.");
                    }

                    break;
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' before handshake completion.");
            }
        }

        return peer;
    }

    private async ValueTask WriteEncryptedHandshakeAsync(
        RuntimeTls13TrafficProtector protector,
        byte[] handshakeMessage,
        CancellationToken cancellationToken)
    {
        var record = protector.Encrypt(RuntimeTls13RecordType.Handshake, handshakeMessage);
        await _transportStream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken).ConfigureAwait(false);
        await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string ParseEncryptedExtensions(ReadOnlySpan<byte> handshakeMessage)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.EncryptedExtensions);
        if (body.Length < 2)
        {
            throw new AuthenticationException("TLS 1.3 EncryptedExtensions payload is truncated.");
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body[..2]);
        var position = 2;
        var end = position + extensionsLength;
        if (end > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 EncryptedExtensions payload is truncated.");
        }

        while (position + 4 <= end)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            var extensionPayloadLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position + 2, 2));
            position += 4;
            if (position + extensionPayloadLength > end)
            {
                throw new AuthenticationException("TLS 1.3 EncryptedExtensions extension payload is truncated.");
            }

            if (extensionType == 0x0010)
            {
                return ParseSelectedAlpn(body.Slice(position, extensionPayloadLength));
            }

            position += extensionPayloadLength;
        }

        return string.Empty;
    }

    private static string ParseSelectedAlpn(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 3)
        {
            return string.Empty;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        if (listLength <= 0 || 2 + listLength > payload.Length)
        {
            return string.Empty;
        }

        var nameLength = payload[2];
        if (nameLength == 0 || 3 + nameLength > payload.Length)
        {
            return string.Empty;
        }

        return Encoding.ASCII.GetString(payload.Slice(3, nameLength)).Trim().ToLowerInvariant();
    }

    private static void ParseCertificateMessage(ReadOnlySpan<byte> handshakeMessage, RuntimeTls13ServerPeer peer)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.Certificate);
        if (body.Length < 4)
        {
            throw new AuthenticationException("TLS 1.3 Certificate payload is truncated.");
        }

        var contextLength = body[0];
        var position = 1 + contextLength;
        if (position + 3 > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 Certificate list is truncated.");
        }

        var certificateListLength = ReadUInt24(body.Slice(position, 3));
        position += 3;
        var end = position + certificateListLength;
        if (end > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 Certificate list is truncated.");
        }

        while (position + 3 <= end)
        {
            var certificateLength = ReadUInt24(body.Slice(position, 3));
            position += 3;
            if (position + certificateLength > end)
            {
                throw new AuthenticationException("TLS 1.3 certificate entry is truncated.");
            }

            var rawCertificate = body.Slice(position, certificateLength).ToArray();
            position += certificateLength;
            if (position + 2 > end)
            {
                throw new AuthenticationException("TLS 1.3 certificate entry extensions are truncated.");
            }

            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            position += 2;
            if (position + extensionsLength > end)
            {
                throw new AuthenticationException("TLS 1.3 certificate entry extensions are truncated.");
            }

            position += extensionsLength;
            peer.CertificateChain.Add(RuntimeRealityPeerCertificateLoader.LoadCertificate(rawCertificate));
        }

        if (peer.CertificateChain.Count == 0)
        {
            throw new AuthenticationException("TLS 1.3 Certificate message did not include any certificates.");
        }

        peer.LeafCertificate = peer.CertificateChain[0];
    }

    private static byte[] ParseCertificateRequestContext(ReadOnlySpan<byte> handshakeMessage)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.CertificateRequest);
        if (body.IsEmpty)
        {
            throw new AuthenticationException("TLS 1.3 CertificateRequest payload is truncated.");
        }

        var contextLength = body[0];
        if (1 + contextLength > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 CertificateRequest context is truncated.");
        }

        return body.Slice(1, contextLength).ToArray();
    }

    private static void VerifyCertificateVerify(
        ReadOnlySpan<byte> handshakeMessage,
        RuntimeTls13ServerPeer peer,
        byte[] transcriptHash)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.CertificateVerify);
        if (body.Length < 4)
        {
            throw new AuthenticationException("TLS 1.3 CertificateVerify payload is truncated.");
        }

        var algorithm = BinaryPrimitives.ReadUInt16BigEndian(body[..2]);
        var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(2, 2));
        if (4 + signatureLength > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 CertificateVerify signature is truncated.");
        }

        var signature = body.Slice(4, signatureLength);
        if (peer.SyntheticVerified)
        {
            if (algorithm != 0x0807)
            {
                throw new AuthenticationException(
                    $"REALITY synthetic certificate expected Ed25519 CertificateVerify, got 0x{algorithm:X4}.");
            }
        }

        var signedData = BuildCertificateVerifyData("TLS 1.3, server CertificateVerify", transcriptHash);
        if (!TryVerifySignature(peer.LeafCertificate!, algorithm, signedData, signature))
        {
            throw new AuthenticationException(
                $"TLS 1.3 CertificateVerify validation failed for algorithm 0x{algorithm:X4}.");
        }
    }

    private static void VerifyServerFinished(
        ReadOnlySpan<byte> handshakeMessage,
        byte[] transcriptHash,
        ReadOnlySpan<byte> serverHandshakeTrafficSecret,
        RuntimeTls13CipherSuite cipherSuite)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.Finished);
        if (body.Length != cipherSuite.HashLength)
        {
            throw new AuthenticationException("TLS 1.3 Finished verify_data has an unexpected length.");
        }

        var finishedKey = RuntimeHkdf.ExpandLabel(
            cipherSuite.HashAlgorithm,
            cipherSuite.HashLength,
            serverHandshakeTrafficSecret,
            "finished",
            ReadOnlySpan<byte>.Empty,
            cipherSuite.HashLength);
        var expected = RuntimeCryptographicHashes.Hmac(cipherSuite.HashAlgorithm, finishedKey, transcriptHash);
        if (!CryptographicOperations.FixedTimeEquals(expected.AsSpan(0, cipherSuite.HashLength), body))
        {
            throw new AuthenticationException("TLS 1.3 Finished verification failed.");
        }
    }

    private static bool TryVerifySignature(
        X509Certificate2 certificate,
        ushort algorithm,
        byte[] data,
        ReadOnlySpan<byte> signature)
        => algorithm switch
        {
            0x0403 => VerifyEcdsa(certificate, data, signature, HashAlgorithmName.SHA256),
            0x0503 => VerifyEcdsa(certificate, data, signature, HashAlgorithmName.SHA384),
            0x0603 => VerifyEcdsa(certificate, data, signature, HashAlgorithmName.SHA512),
            0x0807 => VerifyEd25519(certificate, data, signature),
            0x0804 or 0x0809 => VerifyRsaPss(certificate, data, signature, HashAlgorithmName.SHA256),
            0x0805 or 0x080A => VerifyRsaPss(certificate, data, signature, HashAlgorithmName.SHA384),
            0x0806 or 0x080B => VerifyRsaPss(certificate, data, signature, HashAlgorithmName.SHA512),
            _ => throw new NotSupportedException(
                $"TLS 1.3 signature algorithm 0x{algorithm:X4} is not supported by the built-in REALITY client.")
        };

    private static bool VerifyEcdsa(
        X509Certificate2 certificate,
        byte[] data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa is not null && ecdsa.VerifyData(data, signature, hashAlgorithm);
    }

    private static bool VerifyRsaPss(
        X509Certificate2 certificate,
        byte[] data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        using var rsa = certificate.GetRSAPublicKey();
        return rsa is not null &&
               rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pss);
    }

    private static bool VerifyEd25519(
        X509Certificate2 certificate,
        byte[] data,
        ReadOnlySpan<byte> signature)
    {
        var publicKey = certificate.GetPublicKey();
        return publicKey.Length == RuntimeEd25519.PublicKeyLength &&
               RuntimeEd25519.Verify(signature, data, publicKey);
    }

    private static byte[] BuildCertificateVerifyData(string context, byte[] transcriptHash)
    {
        var contextBytes = Encoding.ASCII.GetBytes(context);
        var message = new byte[64 + contextBytes.Length + 1 + transcriptHash.Length];
        message.AsSpan(0, 64).Fill(0x20);
        contextBytes.CopyTo(message, 64);
        transcriptHash.CopyTo(message, 64 + contextBytes.Length + 1);
        return message;
    }

    private static byte[] CreateEmptyClientCertificateMessage(ReadOnlySpan<byte> requestContext)
    {
        var body = new byte[1 + requestContext.Length + 3];
        body[0] = checked((byte)requestContext.Length);
        requestContext.CopyTo(body.AsSpan(1, requestContext.Length));
        return CreateHandshakeMessage(RuntimeTls13HandshakeType.Certificate, body);
    }

    private static byte[] CreateHandshakeMessage(RuntimeTls13HandshakeType handshakeType, ReadOnlySpan<byte> body)
    {
        var message = new byte[4 + body.Length];
        message[0] = (byte)handshakeType;
        message[1] = (byte)((body.Length >> 16) & 0xFF);
        message[2] = (byte)((body.Length >> 8) & 0xFF);
        message[3] = (byte)(body.Length & 0xFF);
        body.CopyTo(message.AsSpan(4));
        return message;
    }

    private static byte[] ParseSingleServerHello(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 4 || payload[0] != (byte)RuntimeTls13HandshakeType.ServerHello)
        {
            throw new AuthenticationException("The TLS peer did not return a ServerHello.");
        }

        var messageLength = ReadUInt24(payload.Slice(1, 3));
        var totalLength = 4 + messageLength;
        if (totalLength > payload.Length)
        {
            throw new AuthenticationException("The TLS ServerHello is truncated.");
        }

        return payload.Slice(0, totalLength).ToArray();
    }

    private static bool TryReadHandshakeMessage(ResizableByteQueue buffer, out byte[] message)
    {
        message = Array.Empty<byte>();
        if (buffer.Length < 4)
        {
            return false;
        }

        var header = buffer.Slice(0, 4);
        var bodyLength = ReadUInt24(header[1..]);
        var totalLength = 4 + bodyLength;
        if (buffer.Length < totalLength)
        {
            return false;
        }

        message = buffer.Slice(0, totalLength).ToArray();
        buffer.Consume(totalLength);
        return true;
    }

    private static ReadOnlySpan<byte> GetHandshakeBody(
        ReadOnlySpan<byte> handshakeMessage,
        RuntimeTls13HandshakeType expectedType)
    {
        if (handshakeMessage.Length < 4)
        {
            throw new AuthenticationException("TLS 1.3 handshake message is truncated.");
        }

        if (handshakeMessage[0] != (byte)expectedType)
        {
            throw new AuthenticationException(
                $"Expected TLS 1.3 handshake message '{expectedType}', but received '{(RuntimeTls13HandshakeType)handshakeMessage[0]}'.");
        }

        var bodyLength = ReadUInt24(handshakeMessage.Slice(1, 3));
        if (bodyLength != handshakeMessage.Length - 4)
        {
            throw new AuthenticationException(
                $"TLS 1.3 handshake message '{expectedType}' length is invalid.");
        }

        return handshakeMessage[4..];
    }

    private static int ReadUInt24(ReadOnlySpan<byte> payload)
        => (payload[0] << 16) | (payload[1] << 8) | payload[2];
}

internal sealed class RuntimeTls13HandshakeTranscript
{
    private readonly MemoryStream _buffer = new();

    public void Append(ReadOnlySpan<byte> handshakeMessage)
    {
        if (handshakeMessage.Length == 0)
        {
            return;
        }

        _buffer.Write(handshakeMessage);
    }

    public void ReplaceClientHelloWithMessageHashAndAppendHelloRetryRequest(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> helloRetryRequest)
    {
        if (helloRetryRequest.Length == 0)
        {
            throw new ArgumentException("The HelloRetryRequest handshake message cannot be empty.", nameof(helloRetryRequest));
        }

        var currentTranscript = _buffer.ToArray();
        var clientHelloHash = RuntimeCryptographicHashes.Hash(hashAlgorithm, currentTranscript);
        var messageHash = new byte[4 + clientHelloHash.Length];
        messageHash[0] = 0xFE;
        messageHash[1] = (byte)((clientHelloHash.Length >> 16) & 0xFF);
        messageHash[2] = (byte)((clientHelloHash.Length >> 8) & 0xFF);
        messageHash[3] = (byte)(clientHelloHash.Length & 0xFF);
        clientHelloHash.CopyTo(messageHash.AsSpan(4));

        _buffer.SetLength(0);
        _buffer.Write(messageHash);
        _buffer.Write(helloRetryRequest);
    }

    public byte[] GetHash(HashAlgorithmName hashAlgorithm)
        => RuntimeCryptographicHashes.Hash(hashAlgorithm, _buffer.ToArray());
}

internal sealed record RuntimeTls13ServerHello(
    ushort CipherSuite,
    ushort KeyShareGroup,
    byte[] KeyShare,
    bool IsHelloRetryRequest = false,
    byte[]? HelloRetryRequestCookieExtensionPayload = null)
{
    private static readonly byte[] HelloRetryRequestRandom =
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ];

    internal static ReadOnlySpan<byte> HelloRetryRequestRandomBytes => HelloRetryRequestRandom;

    public static RuntimeTls13ServerHello Parse(ReadOnlySpan<byte> handshakeMessage)
    {
        if (handshakeMessage.Length < 4 || handshakeMessage[0] != (byte)RuntimeTls13HandshakeType.ServerHello)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello is invalid.");
        }

        var bodyLength = (handshakeMessage[1] << 16) | (handshakeMessage[2] << 8) | handshakeMessage[3];
        if (bodyLength != handshakeMessage.Length - 4)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello length is invalid.");
        }

        var body = handshakeMessage[4..];
        if (body.Length < 38)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello is truncated.");
        }

        var isHelloRetryRequest = body.Slice(2, 32).SequenceEqual(HelloRetryRequestRandom);

        var sessionIdLength = body[34];
        var position = 35 + sessionIdLength;
        if (position + 5 > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello is truncated.");
        }

        var cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
        position += 2;
        var compressionMethod = body[position++];
        if (compressionMethod != 0)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello advertised an unexpected compression method.");
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
        position += 2;
        var end = position + extensionsLength;
        if (end > body.Length)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello extensions are truncated.");
        }

        var selectedVersion = 0;
        ushort keyShareGroup = 0;
        byte[]? keyShare = null;
        byte[]? helloRetryRequestCookieExtensionPayload = null;
        while (position + 4 <= end)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            var extensionPayloadLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position + 2, 2));
            position += 4;
            if (position + extensionPayloadLength > end)
            {
                throw new AuthenticationException("TLS 1.3 ServerHello extension payload is truncated.");
            }

            var extensionPayload = body.Slice(position, extensionPayloadLength);
            switch (extensionType)
            {
                case 0x002B:
                    if (extensionPayloadLength != 2)
                    {
                        throw new AuthenticationException("TLS 1.3 supported_versions extension is invalid.");
                    }

                    selectedVersion = BinaryPrimitives.ReadUInt16BigEndian(extensionPayload);
                    break;
                case 0x002C when isHelloRetryRequest:
                    ValidateHelloRetryRequestCookie(extensionPayload);
                    helloRetryRequestCookieExtensionPayload = extensionPayload.ToArray();
                    break;
                case 0x0033:
                    if (isHelloRetryRequest)
                    {
                        keyShareGroup = ParseHelloRetryRequestSelectedGroup(extensionPayload);
                    }
                    else
                    {
                        (keyShareGroup, keyShare) = ParseServerKeyShare(extensionPayload);
                    }

                    break;
            }

            position += extensionPayloadLength;
        }

        if (selectedVersion != 0x0304)
        {
            throw new AuthenticationException("REALITY requires a TLS 1.3 ServerHello.");
        }

        if (isHelloRetryRequest)
        {
            if (keyShareGroup == 0 && helloRetryRequestCookieExtensionPayload is null)
            {
                throw new AuthenticationException("TLS 1.3 HelloRetryRequest did not request a retry parameter.");
            }

            return new RuntimeTls13ServerHello(
                cipherSuite,
                keyShareGroup,
                Array.Empty<byte>(),
                IsHelloRetryRequest: true,
                HelloRetryRequestCookieExtensionPayload: helloRetryRequestCookieExtensionPayload ?? Array.Empty<byte>());
        }

        if (keyShare is null)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello did not include a supported key share.");
        }

        return new RuntimeTls13ServerHello(cipherSuite, keyShareGroup, keyShare);
    }

    private static ushort ParseHelloRetryRequestSelectedGroup(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 2)
        {
            throw new AuthenticationException("TLS 1.3 HelloRetryRequest key_share extension is invalid.");
        }

        return BinaryPrimitives.ReadUInt16BigEndian(payload);
    }

    private static void ValidateHelloRetryRequestCookie(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            throw new AuthenticationException("TLS 1.3 HelloRetryRequest cookie extension is truncated.");
        }

        var cookieLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        if (cookieLength == 0 || cookieLength != payload.Length - 2)
        {
            throw new AuthenticationException("TLS 1.3 HelloRetryRequest cookie extension is invalid.");
        }
    }

    private static (ushort Group, byte[] KeyShare) ParseServerKeyShare(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 4)
        {
            throw new AuthenticationException("TLS 1.3 key_share extension is truncated.");
        }

        var group = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var keyExchangeLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        if (4 + keyExchangeLength > payload.Length)
        {
            throw new AuthenticationException("TLS 1.3 ServerHello key_share is invalid.");
        }

        var keyExchange = payload.Slice(4, keyExchangeLength).ToArray();
        var isValid = group switch
        {
            RuntimeTlsNamedGroups.X25519 => keyExchangeLength == RuntimeX25519.KeyLength,
            RuntimeTlsNamedGroups.X25519Kyber768Draft00 => keyExchangeLength == RuntimeX25519Kyber768Draft00.ServerKeyShareLength,
            RuntimeTlsNamedGroups.X25519MLKem768 => keyExchangeLength == RuntimeX25519MlKem768.ServerKeyShareLength,
            RuntimeTlsNamedGroups.Secp256r1MLKem768 => keyExchangeLength == RuntimeSecp256r1MlKem768.ServerKeyShareLength,
            RuntimeTlsNamedGroups.Secp256r1 => keyExchangeLength == RuntimeSecp256r1.PublicKeyLength && keyExchange[0] == 0x04,
            RuntimeTlsNamedGroups.Secp384r1MLKem1024 => keyExchangeLength == RuntimeSecp384r1MlKem1024.ServerKeyShareLength,
            RuntimeTlsNamedGroups.Secp384r1 => keyExchangeLength == RuntimeSecp384r1.PublicKeyLength && keyExchange[0] == 0x04,
            RuntimeTlsNamedGroups.Secp521r1 => keyExchangeLength == RuntimeSecp521r1.PublicKeyLength && keyExchange[0] == 0x04,
            _ => false
        };
        if (!isValid)
        {
            throw new AuthenticationException(
                $"TLS 1.3 ServerHello key_share group 0x{group:X4} is not supported.");
        }

        return (group, keyExchange);
    }
}

internal sealed record RuntimeTls13ApplicationSecrets(
    byte[] ClientApplicationTrafficSecret,
    byte[] ServerApplicationTrafficSecret);

internal sealed class RuntimeTls13KeySchedule
{
    private readonly RuntimeTls13CipherSuite _cipherSuite;

    private RuntimeTls13KeySchedule(
        RuntimeTls13CipherSuite cipherSuite,
        byte[] clientHandshakeTrafficSecret,
        byte[] serverHandshakeTrafficSecret,
        byte[] masterSecret)
    {
        _cipherSuite = cipherSuite;
        ClientHandshakeTrafficSecret = clientHandshakeTrafficSecret;
        ServerHandshakeTrafficSecret = serverHandshakeTrafficSecret;
        MasterSecret = masterSecret;
    }

    public byte[] ClientHandshakeTrafficSecret { get; }

    public byte[] ServerHandshakeTrafficSecret { get; }

    public byte[] MasterSecret { get; }

    public static RuntimeTls13KeySchedule Create(
        RuntimeTls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> handshakeSharedSecret,
        ReadOnlySpan<byte> transcriptHash)
    {
        // RFC 8446 Section 7.1 requires absent PSK/(EC)DHE inputs to be Hash.length zero bytes,
        // not an empty byte string. Using an empty IKM derives different traffic secrets.
        var zeroSecret = new byte[cipherSuite.HashLength];
        var emptyHash = RuntimeCryptographicHashes.Hash(cipherSuite.HashAlgorithm, Array.Empty<byte>());
        var earlySecret = RuntimeHkdf.Extract(cipherSuite.HashAlgorithm, zeroSecret, new byte[cipherSuite.HashLength]);
        var derivedEarly = DeriveSecret(cipherSuite, earlySecret, "derived", emptyHash);
        var handshakeSecret = RuntimeHkdf.Extract(cipherSuite.HashAlgorithm, handshakeSharedSecret, derivedEarly);
        var clientHandshakeTrafficSecret = DeriveSecret(
            cipherSuite,
            handshakeSecret,
            "c hs traffic",
            transcriptHash);
        var serverHandshakeTrafficSecret = DeriveSecret(
            cipherSuite,
            handshakeSecret,
            "s hs traffic",
            transcriptHash);
        var derivedHandshake = DeriveSecret(cipherSuite, handshakeSecret, "derived", emptyHash);
        var masterSecret = RuntimeHkdf.Extract(cipherSuite.HashAlgorithm, zeroSecret, derivedHandshake);
        return new RuntimeTls13KeySchedule(
            cipherSuite,
            clientHandshakeTrafficSecret,
            serverHandshakeTrafficSecret,
            masterSecret);
    }

    public RuntimeTls13ApplicationSecrets CreateApplicationSecrets(ReadOnlySpan<byte> transcriptHash)
        => new(
            DeriveSecret(_cipherSuite, MasterSecret, "c ap traffic", transcriptHash),
            DeriveSecret(_cipherSuite, MasterSecret, "s ap traffic", transcriptHash));

    public static byte[] AdvanceTrafficSecret(
        RuntimeTls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> trafficSecret)
        => RuntimeHkdf.ExpandLabel(
            cipherSuite.HashAlgorithm,
            cipherSuite.HashLength,
            trafficSecret,
            "traffic upd",
            ReadOnlySpan<byte>.Empty,
            cipherSuite.HashLength);

    public static byte[] CreateFinishedMessage(
        ReadOnlySpan<byte> trafficSecret,
        ReadOnlySpan<byte> transcriptHash,
        RuntimeTls13CipherSuite cipherSuite)
    {
        var finishedKey = RuntimeHkdf.ExpandLabel(
            cipherSuite.HashAlgorithm,
            cipherSuite.HashLength,
            trafficSecret,
            "finished",
            ReadOnlySpan<byte>.Empty,
            cipherSuite.HashLength);
        var verifyData = RuntimeCryptographicHashes.Hmac(cipherSuite.HashAlgorithm, finishedKey, transcriptHash)
            .AsSpan(0, cipherSuite.HashLength)
            .ToArray();
        var message = new byte[4 + verifyData.Length];
        message[0] = (byte)RuntimeTls13HandshakeType.Finished;
        WriteUInt24(message.AsSpan(1, 3), verifyData.Length);
        verifyData.CopyTo(message.AsSpan(4));
        return message;
    }

    private static byte[] DeriveSecret(
        RuntimeTls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> transcriptHash)
        => RuntimeHkdf.ExpandLabel(
            cipherSuite.HashAlgorithm,
            cipherSuite.HashLength,
            secret,
            label,
            transcriptHash,
            cipherSuite.HashLength);

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }
}

internal sealed record RuntimeTls13CipherSuite(
    ushort Id,
    string Name,
    bool UseAes,
    int KeyLength,
    int HashLength,
    HashAlgorithmName HashAlgorithm)
{
    public static RuntimeTls13CipherSuite Resolve(ushort id)
        => id switch
        {
            0x1301 => new RuntimeTls13CipherSuite(id, "TLS_AES_128_GCM_SHA256", UseAes: true, KeyLength: 16, HashLength: 32, HashAlgorithmName.SHA256),
            0x1302 => new RuntimeTls13CipherSuite(id, "TLS_AES_256_GCM_SHA384", UseAes: true, KeyLength: 32, HashLength: 48, HashAlgorithmName.SHA384),
            0x1303 => new RuntimeTls13CipherSuite(id, "TLS_CHACHA20_POLY1305_SHA256", UseAes: false, KeyLength: 32, HashLength: 32, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException(
                $"TLS 1.3 cipher suite 0x{id:X4} is not supported by the built-in REALITY client.")
        };
}

internal sealed class RuntimeTls13TrafficProtector : IDisposable
{
    private AesGcm? _aesGcm;
    private ChaCha20Poly1305? _chacha20Poly1305;
    private byte[] _iv;
    private readonly RuntimeTls13CipherSuite _cipherSuite;
    private ulong _sequenceNumber;

    private RuntimeTls13TrafficProtector(
        RuntimeTls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> trafficSecret)
    {
        _cipherSuite = cipherSuite;
        _iv = [];
        ReplaceTrafficSecret(trafficSecret);
    }

    public byte[] TrafficSecret { get; private set; } = [];

    public static RuntimeTls13TrafficProtector Create(
        RuntimeTls13CipherSuite cipherSuite,
        ReadOnlySpan<byte> trafficSecret)
        => new(cipherSuite, trafficSecret);

    public void AdvanceTrafficSecret()
        => ReplaceTrafficSecret(RuntimeTls13KeySchedule.AdvanceTrafficSecret(_cipherSuite, TrafficSecret));

    public byte[] Encrypt(RuntimeTls13RecordType innerContentType, ReadOnlySpan<byte> content)
    {
        var plaintext = new byte[content.Length + 1];
        content.CopyTo(plaintext);
        plaintext[^1] = (byte)innerContentType;

        var recordLength = plaintext.Length + 16;
        var record = new byte[5 + recordLength];
        record[0] = (byte)RuntimeTls13RecordType.ApplicationData;
        record[1] = 0x03;
        record[2] = 0x03;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), checked((ushort)recordLength));

        Span<byte> ciphertext = record.AsSpan(5, plaintext.Length);
        Span<byte> tag = record.AsSpan(5 + plaintext.Length, 16);
        var nonce = ComputeNonce(_sequenceNumber++);
        if (_cipherSuite.UseAes)
        {
            _aesGcm!.Encrypt(nonce, plaintext, ciphertext, tag, record.AsSpan(0, 5));
        }
        else
        {
            _chacha20Poly1305!.Encrypt(nonce, plaintext, ciphertext, tag, record.AsSpan(0, 5));
        }

        return record;
    }

    public RuntimeTls13Plaintext Decrypt(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 16)
        {
            throw new AuthenticationException("TLS 1.3 encrypted record is too short.");
        }

        var plaintext = new byte[payload.Length - 16];
        Span<byte> header = stackalloc byte[5];
        header[0] = (byte)RuntimeTls13RecordType.ApplicationData;
        header[1] = 0x03;
        header[2] = 0x03;
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(3, 2), checked((ushort)payload.Length));

        var nonce = ComputeNonce(_sequenceNumber++);
        if (_cipherSuite.UseAes)
        {
            _aesGcm!.Decrypt(nonce, payload[..^16], payload[^16..], plaintext, header);
        }
        else
        {
            _chacha20Poly1305!.Decrypt(nonce, payload[..^16], payload[^16..], plaintext, header);
        }

        var contentTypeIndex = plaintext.Length - 1;
        while (contentTypeIndex >= 0 && plaintext[contentTypeIndex] == 0)
        {
            contentTypeIndex--;
        }

        if (contentTypeIndex < 0)
        {
            throw new AuthenticationException("TLS 1.3 inner plaintext is invalid.");
        }

        var contentType = (RuntimeTls13RecordType)plaintext[contentTypeIndex];
        var content = plaintext.AsSpan(0, contentTypeIndex).ToArray();
        return new RuntimeTls13Plaintext(contentType, content);
    }

    private byte[] ComputeNonce(ulong sequenceNumber)
    {
        var nonce = _iv.ToArray();
        Span<byte> sequenceBytes = stackalloc byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceBytes.Slice(4, 8), sequenceNumber);
        for (var index = 0; index < nonce.Length; index++)
        {
            nonce[index] ^= sequenceBytes[index];
        }

        return nonce;
    }

    private void ReplaceTrafficSecret(ReadOnlySpan<byte> trafficSecret)
    {
        _aesGcm?.Dispose();
        _aesGcm = null;
        _chacha20Poly1305?.Dispose();
        _chacha20Poly1305 = null;

        var key = RuntimeHkdf.ExpandLabel(
            _cipherSuite.HashAlgorithm,
            _cipherSuite.HashLength,
            trafficSecret,
            "key",
            ReadOnlySpan<byte>.Empty,
            _cipherSuite.KeyLength);
        _iv = RuntimeHkdf.ExpandLabel(
            _cipherSuite.HashAlgorithm,
            _cipherSuite.HashLength,
            trafficSecret,
            "iv",
            ReadOnlySpan<byte>.Empty,
            12);
        TrafficSecret = trafficSecret.ToArray();
        _sequenceNumber = 0;

        if (_cipherSuite.UseAes)
        {
            _aesGcm = new AesGcm(key, tagSizeInBytes: 16);
            return;
        }

        _chacha20Poly1305 = new ChaCha20Poly1305(key);
    }

    public void Dispose()
    {
        _aesGcm?.Dispose();
        _chacha20Poly1305?.Dispose();
    }
}

internal sealed record RuntimeTls13Plaintext(
    RuntimeTls13RecordType ContentType,
    byte[] Content);

internal sealed record RuntimeTls13Record(
    RuntimeTls13RecordType Type,
    byte[] Payload)
{
    public static async Task<RuntimeTls13Record?> ReadAsync(
        Stream stream,
        bool allowEof,
        CancellationToken cancellationToken)
    {
        var header = new byte[5];
        var headerRead = 0;
        while (headerRead < header.Length)
        {
            var current = await stream.ReadAsync(header.AsMemory(headerRead, header.Length - headerRead), cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                if (allowEof && headerRead == 0)
                {
                    return null;
                }

                throw new EndOfStreamException("Unexpected EOF while reading a TLS record header.");
            }

            headerRead += current;
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3, 2));
        var payload = new byte[length];
        if (length > 0)
        {
            await stream.ReadExactlyAsync(payload.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }

        return new RuntimeTls13Record((RuntimeTls13RecordType)header[0], payload);
    }

    public static bool IsCompatibilityChangeCipherSpec(ReadOnlySpan<byte> payload)
        => payload.Length == 1 && payload[0] == 0x01;
}

internal sealed class RuntimeTls13DuplexStream : Stream
{
    public RuntimeTls13DuplexStream(
        Stream innerStream,
        RuntimeTls13TrafficProtector readProtector,
        RuntimeTls13TrafficProtector writeProtector)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _readProtector = readProtector ?? throw new ArgumentNullException(nameof(readProtector));
        _writeProtector = writeProtector ?? throw new ArgumentNullException(nameof(writeProtector));
    }

    private readonly Stream _innerStream;
    private readonly RuntimeTls13TrafficProtector _readProtector;
    private readonly RuntimeTls13TrafficProtector _writeProtector;
    private readonly ResizableByteQueue _applicationBuffer = new();
    private readonly ResizableByteQueue _postHandshakeBuffer = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    private int _disposed;
    private bool _receivedCloseNotify;

    public override bool CanRead => _innerStream.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => _innerStream.CanWrite;

    public override bool CanTimeout => _innerStream.CanTimeout;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int ReadTimeout
    {
        get => _innerStream.ReadTimeout;
        set => _innerStream.ReadTimeout = value;
    }

    public override int WriteTimeout
    {
        get => _innerStream.WriteTimeout;
        set => _innerStream.WriteTimeout = value;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => ReadCoreAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadCoreAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => WriteCoreAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteCoreAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush() => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _innerStream.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            await TrySendCloseNotifyAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        _writeProtector.Dispose();
        _readProtector.Dispose();
        _writeLock.Dispose();
        await _innerStream.DisposeAsync().ConfigureAwait(false);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }

    private async ValueTask<int> ReadCoreAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
        {
            return 0;
        }

        if (_applicationBuffer.Length > 0)
        {
            return _applicationBuffer.Read(buffer.Span);
        }

        while (true)
        {
            if (_receivedCloseNotify)
            {
                return 0;
            }

            var record = await RuntimeTls13Record.ReadAsync(_innerStream, allowEof: true, cancellationToken).ConfigureAwait(false);
            if (record is null)
            {
                return 0;
            }

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls13AlertExceptionFactory.Create(record.Payload, encrypted: false);
                case RuntimeTls13RecordType.ApplicationData:
                    var plaintext = _readProtector.Decrypt(record.Payload);
                    switch (plaintext.ContentType)
                    {
                        case RuntimeTls13RecordType.ApplicationData:
                            _applicationBuffer.Append(plaintext.Content);
                            return _applicationBuffer.Read(buffer.Span);
                        case RuntimeTls13RecordType.Alert:
                            HandleAlert(plaintext.Content);
                            if (_receivedCloseNotify)
                            {
                                return 0;
                            }

                            continue;
                        case RuntimeTls13RecordType.Handshake:
                            await HandlePostHandshakeMessagesAsync(plaintext.Content, cancellationToken).ConfigureAwait(false);
                            continue;
                        default:
                            throw new InvalidDataException(
                                $"Unexpected post-handshake TLS 1.3 content type '{plaintext.ContentType}'.");
                    }
                default:
                    throw new InvalidDataException(
                        $"Unexpected TLS record '{record.Type}' after REALITY handshake completion.");
            }
        }
    }

    private async ValueTask WriteCoreAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        if (buffer.Length == 0)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var remaining = buffer;
            while (remaining.Length > 0)
            {
                var currentLength = Math.Min(remaining.Length, 16 * 1024);
                var record = _writeProtector.Encrypt(RuntimeTls13RecordType.ApplicationData, remaining.Span[..currentLength]);
                await _innerStream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken).ConfigureAwait(false);
                remaining = remaining[currentLength..];
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private void HandleAlert(ReadOnlySpan<byte> payload)
    {
        if (payload.Length >= 2 && payload[1] == 0x00)
        {
            _receivedCloseNotify = true;
            return;
        }

        throw RuntimeTls13AlertExceptionFactory.Create(payload, encrypted: true);
    }

    private async ValueTask HandlePostHandshakeMessagesAsync(
        byte[] payload,
        CancellationToken cancellationToken)
    {
        _postHandshakeBuffer.Append(payload);
        while (TryReadHandshakeMessage(_postHandshakeBuffer, out var handshakeMessage))
        {
            var handshakeType = (RuntimeTls13HandshakeType)handshakeMessage[0];
            switch (handshakeType)
            {
                case RuntimeTls13HandshakeType.NewSessionTicket:
                    continue;
                case RuntimeTls13HandshakeType.KeyUpdate:
                    await HandleKeyUpdateAsync(handshakeMessage, cancellationToken).ConfigureAwait(false);
                    continue;
                default:
                    throw new InvalidDataException(
                        $"Unexpected TLS 1.3 post-handshake message '{handshakeType}'.");
            }
        }
    }

    private async ValueTask HandleKeyUpdateAsync(
        byte[] handshakeMessage,
        CancellationToken cancellationToken)
    {
        if (handshakeMessage.Length != 5)
        {
            throw new InvalidDataException("TLS 1.3 KeyUpdate payload is invalid.");
        }

        var updateRequested = handshakeMessage[4] switch
        {
            0x00 => false,
            0x01 => true,
            _ => throw new InvalidDataException("TLS 1.3 KeyUpdate request_update is invalid.")
        };

        _readProtector.AdvanceTrafficSecret();
        if (!updateRequested)
        {
            return;
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var record = _writeProtector.Encrypt(
                RuntimeTls13RecordType.Handshake,
                CreateKeyUpdateMessage(updateRequested: false));
            await _innerStream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken).ConfigureAwait(false);
            await _innerStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            _writeProtector.AdvanceTrafficSecret();
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static bool TryReadHandshakeMessage(ResizableByteQueue buffer, out byte[] message)
    {
        message = Array.Empty<byte>();
        if (buffer.Length < 4)
        {
            return false;
        }

        var header = buffer.Slice(0, 4);
        var bodyLength = (header[1] << 16) | (header[2] << 8) | header[3];
        var totalLength = 4 + bodyLength;
        if (buffer.Length < totalLength)
        {
            return false;
        }

        message = buffer.Slice(0, totalLength).ToArray();
        buffer.Consume(totalLength);
        return true;
    }

    private static byte[] CreateKeyUpdateMessage(bool updateRequested)
        => [(
                byte)RuntimeTls13HandshakeType.KeyUpdate,
            0x00,
            0x00,
            0x01,
            updateRequested ? (byte)0x01 : (byte)0x00];

    private async Task TrySendCloseNotifyAsync()
    {
        if (!_innerStream.CanWrite || _receivedCloseNotify)
        {
            return;
        }

        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            var record = _writeProtector.Encrypt(RuntimeTls13RecordType.Alert, [0x01, 0x00]);
            await _innerStream.WriteAsync(record.AsMemory(0, record.Length)).ConfigureAwait(false);
            await _innerStream.FlushAsync().ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(RuntimeTls13DuplexStream));
        }
    }
}

internal sealed class RuntimeTls13ServerPeer : IDisposable
{
    public List<X509Certificate2> CertificateChain { get; } = [];

    public X509Certificate2? LeafCertificate { get; set; }

    public string NegotiatedApplicationProtocol { get; set; } = string.Empty;

    public bool SyntheticVerified { get; set; }

    public bool ServerRequestedClientCertificate { get; set; }

    public byte[] ClientCertificateRequestContext { get; set; } = [];

    public void Dispose()
    {
        foreach (var certificate in CertificateChain)
        {
            certificate.Dispose();
        }

        CertificateChain.Clear();
        LeafCertificate = null;
        ClientCertificateRequestContext = [];
    }
}

internal static class RuntimeTls13AlertExceptionFactory
{
    public static Exception Create(ReadOnlySpan<byte> payload, bool encrypted)
    {
        var prefix = encrypted
            ? "Encrypted TLS 1.3 alert"
            : "TLS 1.3 alert";
        if (payload.Length < 2)
        {
            return new AuthenticationException($"{prefix}: payload is truncated.");
        }

        return new AuthenticationException(
            $"{prefix}: {Describe(payload[1])} (0x{payload[1]:X2}).");
    }

    private static string Describe(byte description)
        => description switch
        {
            0x00 => "close_notify",
            0x28 => "handshake_failure",
            0x2A => "bad_certificate",
            0x2B => "unsupported_certificate",
            0x2F => "illegal_parameter",
            0x32 => "decode_error",
            0x33 => "decrypt_error",
            0x46 => "protocol_version",
            0x6D => "missing_extension",
            0x70 => "unsupported_extension",
            0x78 => "no_application_protocol",
            _ => "unknown_alert"
        };
}

internal static class RuntimeRealityTls13ClientHelloBuilder
{
    private readonly record struct RuntimeTlsGreaseValues(
        ushort CipherSuite,
        ushort Group,
        ushort Extension1,
        ushort Extension2,
        ushort SupportedVersion);

    public static byte[] Build(
        RuntimeRealityHandshakeRequest request,
        RuntimeRealityTls13ClientHelloProfile profile,
        IReadOnlyDictionary<ushort, byte[]> keyShares)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(keyShares);
        var greaseValues = profile.UseGrease ? CreateGreaseValues() : default;
        var cipherSuites = MaterializeCipherSuites(profile.CipherSuites, profile.ShuffleCipherSuites);
        var supportedGroups = MaterializeValues(profile.SupportedGroups, profile.ShuffleSupportedGroups);
        var keyShareGroups = MaterializeValues(profile.KeyShareGroups, profile.ShuffleKeyShares);
        var extensionsOrder = MaterializeExtensions(profile.Extensions, profile.ShuffleExtensions);
        var sessionId = profile.UseRandomSessionId
            ? RandomNumberGenerator.GetBytes(32)
            : new byte[32];
        var cipherSuiteCount = cipherSuites.Length + (profile.UseGrease ? 1 : 0);

        using var measuredExtensions = new MemoryStream();
        var measuredGreaseExtensionCount = 0;
        foreach (var extension in extensionsOrder)
        {
            if (extension == RuntimeRealityTls13ExtensionKind.Padding)
            {
                continue;
            }

            WriteClientHelloExtension(
                measuredExtensions,
                extension,
                request,
                profile,
                supportedGroups,
                keyShareGroups,
                keyShares,
                greaseValues,
                ref measuredGreaseExtensionCount,
                paddingLength: 0);
        }

        var paddingLength = ResolvePaddingLength(
            profile,
            sessionId.Length,
            cipherSuiteCount,
            checked((int)measuredExtensions.Length));

        using var extensions = new MemoryStream();
        var greaseExtensionCount = 0;
        foreach (var extension in extensionsOrder)
        {
            WriteClientHelloExtension(
                extensions,
                extension,
                request,
                profile,
                supportedGroups,
                keyShareGroups,
                keyShares,
                greaseValues,
                ref greaseExtensionCount,
                paddingLength);
        }

        var extensionsBytes = extensions.ToArray();
        using var handshakeBody = new MemoryStream();
        WriteUInt16(handshakeBody, profile.ClientHelloLegacyVersion);
        handshakeBody.Write(RandomNumberGenerator.GetBytes(32));
        handshakeBody.WriteByte(checked((byte)sessionId.Length));
        handshakeBody.Write(sessionId, 0, sessionId.Length);
        WriteUInt16(handshakeBody, checked((ushort)(cipherSuiteCount * 2)));
        if (profile.UseGrease)
        {
            WriteUInt16(handshakeBody, greaseValues.CipherSuite);
        }

        foreach (var cipherSuite in cipherSuites)
        {
            WriteUInt16(handshakeBody, cipherSuite);
        }

        handshakeBody.WriteByte(1);
        handshakeBody.WriteByte(0);
        WriteUInt16(handshakeBody, checked((ushort)extensionsBytes.Length));
        handshakeBody.Write(extensionsBytes);

        var body = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte((byte)RuntimeTls13RecordType.Handshake);
        WriteUInt16(record, 0x0301);
        WriteUInt16(record, checked((ushort)(body.Length + 4)));
        record.WriteByte((byte)RuntimeTls13HandshakeType.ClientHello);
        WriteUInt24(record, body.Length);
        record.Write(body);
        return record.ToArray();
    }

    private static void WriteClientHelloExtension(
        Stream stream,
        RuntimeRealityTls13ExtensionKind extension,
        RuntimeRealityHandshakeRequest request,
        RuntimeRealityTls13ClientHelloProfile profile,
        ReadOnlySpan<ushort> supportedGroups,
        ReadOnlySpan<ushort> keyShareGroups,
        IReadOnlyDictionary<ushort, byte[]> keyShares,
        RuntimeTlsGreaseValues greaseValues,
        ref int greaseExtensionCount,
        int paddingLength)
    {
        switch (extension)
        {
            case RuntimeRealityTls13ExtensionKind.Grease when profile.UseGrease:
                greaseExtensionCount++;
                switch (greaseExtensionCount)
                {
                    case 1:
                        WriteGreaseExtension(stream, greaseValues.Extension1, []);
                        break;
                    case 2:
                        WriteGreaseExtension(stream, greaseValues.Extension2, [0x00]);
                        break;
                    default:
                        throw new NotSupportedException("REALITY fingerprint requested more than two GREASE extensions.");
                }
                break;
            case RuntimeRealityTls13ExtensionKind.ServerName:
                WriteServerNameExtension(stream, request.ServerName);
                break;
            case RuntimeRealityTls13ExtensionKind.ExtendedMasterSecret:
                WriteExtendedMasterSecretExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.RenegotiationInfo:
                WriteRenegotiationInfoExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.SupportedGroups:
                WriteSupportedGroupsExtension(stream, supportedGroups, profile.UseGrease, greaseValues.Group);
                break;
            case RuntimeRealityTls13ExtensionKind.EcPointFormats:
                WriteEcPointFormatsExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.SessionTicket:
                WriteSessionTicketExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.ApplicationProtocols:
                WriteApplicationProtocolsExtension(
                    stream,
                    ResolveClientHelloApplicationProtocols(request, profile));
                break;
            case RuntimeRealityTls13ExtensionKind.StatusRequest:
                WriteStatusRequestExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.DelegatedCredentials:
                WriteDelegatedCredentialsExtension(stream, profile.DelegatedCredentialSignatureAlgorithms);
                break;
            case RuntimeRealityTls13ExtensionKind.SignatureAlgorithms:
                WriteSignatureAlgorithmsExtension(stream, extensionType: 0x000D, profile.SignatureAlgorithms);
                break;
            case RuntimeRealityTls13ExtensionKind.SignedCertificateTimestamp:
                WriteSignedCertificateTimestampExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.SupportedVersions:
                WriteSupportedVersionsExtension(stream, profile.SupportedVersions, profile.UseGrease, greaseValues.SupportedVersion);
                break;
            case RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes:
                WritePskKeyExchangeModesExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.SignatureAlgorithmsCert:
                WriteSignatureAlgorithmsExtension(stream, extensionType: 0x0032, profile.SignatureAlgorithmsCert);
                break;
            case RuntimeRealityTls13ExtensionKind.RecordSizeLimit:
                WriteRecordSizeLimitExtension(stream, profile.RecordSizeLimit);
                break;
            case RuntimeRealityTls13ExtensionKind.CompressCertificate:
                WriteCompressCertificateExtension(stream, profile.CompressCertificateAlgorithms);
                break;
            case RuntimeRealityTls13ExtensionKind.ApplicationSettings:
                WriteApplicationSettingsExtension(stream, 17513, new[] { "h2" });
                break;
            case RuntimeRealityTls13ExtensionKind.ApplicationSettingsNew:
                WriteApplicationSettingsExtension(stream, 17613, new[] { "h2" });
                break;
            case RuntimeRealityTls13ExtensionKind.EchGrease:
                WriteEchGreaseExtension(
                    stream,
                    profile.EchGreaseCandidateAeads,
                    profile.EchGreaseCandidatePayloadLengths);
                break;
            case RuntimeRealityTls13ExtensionKind.NextProtocolNegotiation:
                WriteNextProtocolNegotiationExtension(stream);
                break;
            case RuntimeRealityTls13ExtensionKind.FakeChannelId:
                WriteFakeChannelIdExtension(stream, oldExtensionId: false);
                break;
            case RuntimeRealityTls13ExtensionKind.FakeOldChannelId:
                WriteFakeChannelIdExtension(stream, oldExtensionId: true);
                break;
            case RuntimeRealityTls13ExtensionKind.KeyShare:
                WriteKeyShareExtension(
                    stream,
                    keyShareGroups,
                    keyShares,
                    profile.IncludeGreaseKeyShare && profile.UseGrease,
                    greaseValues.Group);
                break;
            case RuntimeRealityTls13ExtensionKind.Padding when paddingLength > 0:
                WritePaddingExtension(stream, paddingLength);
                break;
        }
    }

    private static int ResolvePaddingLength(
        RuntimeRealityTls13ClientHelloProfile profile,
        int sessionIdLength,
        int cipherSuiteCount,
        int nonPaddingExtensionsLength)
    {
        if (profile.PaddingLength > 0)
        {
            return profile.PaddingLength;
        }

        if (!profile.UseBoringPadding)
        {
            return 0;
        }

        var unpaddedLength =
            2 +
            32 +
            1 + sessionIdLength +
            2 + (cipherSuiteCount * 2) +
            1 + 1 +
            2 +
            nonPaddingExtensionsLength +
            4;
        return TryResolveBoringPaddingLength(unpaddedLength, out var paddingLength)
            ? paddingLength
            : 0;
    }

    private static bool TryResolveBoringPaddingLength(int unpaddedLength, out int paddingLength)
    {
        if (unpaddedLength > 0xFF &&
            unpaddedLength < 0x200)
        {
            paddingLength = 0x200 - unpaddedLength;
            paddingLength = paddingLength >= 5
                ? paddingLength - 4
                : 1;
            return true;
        }

        paddingLength = 0;
        return false;
    }

    private static ushort[] MaterializeCipherSuites(IReadOnlyList<ushort> values, bool shuffle)
    {
        var materialized = values.ToArray();
        if (!shuffle ||
            materialized.Length <= 2)
        {
            return materialized;
        }

        var lastIndex = materialized.Length - 1;
        var keepLast = materialized[lastIndex] == 0x00FF;
        var shuffleCount = keepLast ? lastIndex : materialized.Length;
        for (var index = shuffleCount - 1; index > 0; index--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(index + 1);
            (materialized[index], materialized[swapIndex]) = (materialized[swapIndex], materialized[index]);
        }

        return materialized;
    }

    private static ushort[] MaterializeValues(IReadOnlyList<ushort> values, bool shuffle)
    {
        var materialized = values.ToArray();
        if (shuffle &&
            materialized.Length > 1)
        {
            ShuffleInPlace(materialized);
        }

        return materialized;
    }

    private static RuntimeRealityTls13ExtensionKind[] MaterializeExtensions(
        IReadOnlyList<RuntimeRealityTls13ExtensionKind> values,
        bool shuffle)
    {
        var materialized = values.ToArray();
        if (!shuffle ||
            materialized.Length <= 1)
        {
            return materialized;
        }

        // Match uTLS shuffle semantics: keep GREASE/padding positionally fixed
        // and only shuffle the remaining extension slots.
        for (var index = materialized.Length - 1; index > 0; index--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(index + 1);
            if (IsPositionInvariantExtension(materialized[index]) ||
                IsPositionInvariantExtension(materialized[swapIndex]))
            {
                continue;
            }

            (materialized[index], materialized[swapIndex]) = (materialized[swapIndex], materialized[index]);
        }

        return materialized;
    }

    private static bool IsPositionInvariantExtension(RuntimeRealityTls13ExtensionKind extension)
        => extension is RuntimeRealityTls13ExtensionKind.Grease or RuntimeRealityTls13ExtensionKind.Padding;

    private static void WriteServerNameExtension(Stream stream, string serverName)
    {
        if (string.IsNullOrWhiteSpace(serverName) || IPAddress.TryParse(serverName, out _))
        {
            return;
        }

        var hostBytes = Encoding.ASCII.GetBytes(serverName.Trim());
        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)(hostBytes.Length + 3)));
        payload.WriteByte(0);
        WriteUInt16(payload, checked((ushort)hostBytes.Length));
        payload.Write(hostBytes);
        WriteExtension(stream, 0x0000, payload.ToArray());
    }

    private static void WriteSupportedGroupsExtension(
        Stream stream,
        ReadOnlySpan<ushort> supportedGroups,
        bool includeGrease,
        ushort greaseValue)
    {
        using var payload = new MemoryStream();
        var groupCount = supportedGroups.Length + (includeGrease ? 1 : 0);
        WriteUInt16(payload, checked((ushort)(groupCount * 2)));
        if (includeGrease)
        {
            WriteUInt16(payload, greaseValue);
        }

        foreach (var supportedGroup in supportedGroups)
        {
            WriteUInt16(payload, supportedGroup);
        }

        WriteExtension(stream, 0x000A, payload.ToArray());
    }

    private static void WriteEcPointFormatsExtension(Stream stream)
        => WriteExtension(stream, 0x000B, [0x01, 0x00]);

    private static void WriteExtendedMasterSecretExtension(Stream stream)
        => WriteExtension(stream, 0x0017, []);

    private static void WriteRenegotiationInfoExtension(Stream stream)
        => WriteExtension(stream, 0xFF01, [0x00]);

    private static void WriteSessionTicketExtension(Stream stream)
        => WriteExtension(stream, 0x0023, []);

    private static void WriteSignatureAlgorithmsExtension(
        Stream stream,
        ushort extensionType,
        IReadOnlyList<ushort> signatureAlgorithms)
    {
        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)(signatureAlgorithms.Count * 2)));
        foreach (var algorithm in signatureAlgorithms)
        {
            WriteUInt16(payload, algorithm);
        }

        WriteExtension(stream, extensionType, payload.ToArray());
    }

    private static IReadOnlyList<string> ResolveClientHelloApplicationProtocols(
        RuntimeRealityHandshakeRequest request,
        RuntimeRealityTls13ClientHelloProfile profile)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(profile);

        if (RuntimeInternetTransportProtocols.UsesHttp11OnlyApplicationProtocols(request.TransportProtocol))
        {
            return ["http/1.1"];
        }

        return profile.ClientHelloApplicationProtocols ?? request.ApplicationProtocols;
    }

    private static void WriteApplicationProtocolsExtension(Stream stream, IReadOnlyList<string> protocols)
    {
        if (protocols.Count == 0)
        {
            return;
        }

        using var protocolList = new MemoryStream();
        foreach (var current in protocols)
        {
            if (string.IsNullOrWhiteSpace(current))
            {
                continue;
            }

            var bytes = Encoding.ASCII.GetBytes(current.Trim().ToLowerInvariant());
            protocolList.WriteByte(checked((byte)bytes.Length));
            protocolList.Write(bytes);
        }

        if (protocolList.Length == 0)
        {
            return;
        }

        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)protocolList.Length));
        payload.Write(protocolList.GetBuffer(), 0, checked((int)protocolList.Length));
        WriteExtension(stream, 0x0010, payload.ToArray());
    }

    private static void WriteStatusRequestExtension(Stream stream)
        => WriteExtension(stream, 0x0005, [0x01, 0x00, 0x00, 0x00, 0x00]);

    private static void WriteSupportedVersionsExtension(
        Stream stream,
        IReadOnlyList<ushort> supportedVersions,
        bool includeGrease,
        ushort greaseValue)
    {
        using var payload = new MemoryStream();
        var versionCount = supportedVersions.Count + (includeGrease ? 1 : 0);
        payload.WriteByte(checked((byte)(versionCount * 2)));
        if (includeGrease)
        {
            WriteUInt16(payload, greaseValue);
        }

        foreach (var supportedVersion in supportedVersions)
        {
            WriteUInt16(payload, supportedVersion);
        }

        WriteExtension(stream, 0x002B, payload.ToArray());
    }

    private static void WritePskKeyExchangeModesExtension(Stream stream)
    {
        WriteExtension(stream, 0x002D, [0x01, 0x01]);
    }

    private static void WriteSignedCertificateTimestampExtension(Stream stream)
        => WriteExtension(stream, 0x0012, []);

    private static void WriteDelegatedCredentialsExtension(
        Stream stream,
        IReadOnlyList<ushort>? signatureAlgorithms)
    {
        if (signatureAlgorithms is null || signatureAlgorithms.Count == 0)
        {
            return;
        }

        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)(signatureAlgorithms.Count * 2)));
        foreach (var algorithm in signatureAlgorithms)
        {
            WriteUInt16(payload, algorithm);
        }

        WriteExtension(stream, 0x0022, payload.ToArray());
    }

    private static void WriteRecordSizeLimitExtension(Stream stream, int? recordSizeLimit)
    {
        if (!recordSizeLimit.HasValue)
        {
            return;
        }

        if (recordSizeLimit.Value is <= 0 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(recordSizeLimit),
                "REALITY TLS 1.3 record_size_limit must be between 1 and 65535.");
        }

        WriteExtension(stream, 0x001C, [(byte)(recordSizeLimit.Value >> 8), (byte)recordSizeLimit.Value]);
    }

    private static void WriteCompressCertificateExtension(
        Stream stream,
        IReadOnlyList<ushort>? compressionAlgorithms)
    {
        if (compressionAlgorithms is null || compressionAlgorithms.Count == 0)
        {
            return;
        }

        var algorithmsLength = checked(compressionAlgorithms.Count * 2);
        if (algorithmsLength > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(compressionAlgorithms),
                "REALITY TLS 1.3 compress_certificate algorithms must fit in an 8-bit length field.");
        }

        using var payload = new MemoryStream();
        payload.WriteByte(checked((byte)algorithmsLength));
        foreach (var algorithm in compressionAlgorithms)
        {
            WriteUInt16(payload, algorithm);
        }

        WriteExtension(stream, 0x001B, payload.ToArray());
    }

    private static void WriteApplicationSettingsExtension(
        Stream stream,
        ushort extensionType,
        IReadOnlyList<string> protocols)
    {
        using var protocolList = new MemoryStream();
        foreach (var current in protocols)
        {
            if (string.IsNullOrWhiteSpace(current))
            {
                continue;
            }

            var bytes = Encoding.ASCII.GetBytes(current.Trim().ToLowerInvariant());
            protocolList.WriteByte(checked((byte)bytes.Length));
            protocolList.Write(bytes);
        }

        if (protocolList.Length == 0)
        {
            return;
        }

        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)protocolList.Length));
        payload.Write(protocolList.GetBuffer(), 0, checked((int)protocolList.Length));
        WriteExtension(stream, extensionType, payload.ToArray());
    }

    private static void WriteEchGreaseExtension(
        Stream stream,
        IReadOnlyList<ushort>? candidateAeads,
        IReadOnlyList<ushort>? candidatePayloadLengths)
    {
        var aeadId = SelectEchGreaseCandidate(candidateAeads, 0x0001);
        var encodedHelloInnerLength = SelectEchGreaseCandidate(candidatePayloadLengths, 128);
        var encapsulatedKey = RandomNumberGenerator.GetBytes(32);
        var echPayload = RandomNumberGenerator.GetBytes(
            GetEchGreaseCiphertextLength(aeadId, encodedHelloInnerLength));

        using var payload = new MemoryStream();
        payload.WriteByte(0x00);
        WriteUInt16(payload, 0x0001);
        WriteUInt16(payload, aeadId);
        payload.WriteByte(RandomNumberGenerator.GetBytes(1)[0]);
        WriteUInt16(payload, checked((ushort)encapsulatedKey.Length));
        payload.Write(encapsulatedKey);
        WriteUInt16(payload, checked((ushort)echPayload.Length));
        payload.Write(echPayload);
        WriteExtension(stream, 0xFE0D, payload.ToArray());
    }

    private static void WriteNextProtocolNegotiationExtension(Stream stream)
        => WriteExtension(stream, 13172, []);

    private static void WriteFakeChannelIdExtension(Stream stream, bool oldExtensionId)
        => WriteExtension(stream, oldExtensionId ? (ushort)30031 : (ushort)30032, []);

    private static ushort SelectEchGreaseCandidate(IReadOnlyList<ushort>? candidates, ushort fallback)
    {
        if (candidates is null || candidates.Count == 0)
        {
            return fallback;
        }

        return candidates[RandomNumberGenerator.GetInt32(candidates.Count)];
    }

    private static int GetEchGreaseCiphertextLength(ushort aeadId, ushort encodedHelloInnerLength)
        => checked(encodedHelloInnerLength + GetEchGreaseAeadOverhead(aeadId));

    private static int GetEchGreaseAeadOverhead(ushort aeadId)
        => aeadId switch
        {
            0x0001 or 0x0002 or 0x0003 => 16,
            _ => throw new NotSupportedException(
                $"REALITY fingerprint requested unsupported ECH GREASE AEAD 0x{aeadId:X4}.")
        };

    private static void WriteKeyShareExtension(
        Stream stream,
        ReadOnlySpan<ushort> keyShareGroups,
        IReadOnlyDictionary<ushort, byte[]> keyShares,
        bool includeGrease,
        ushort greaseValue)
    {
        using var payload = new MemoryStream();
        var entriesLength = includeGrease ? 5 : 0;
        foreach (var group in keyShareGroups)
        {
            if (!keyShares.TryGetValue(group, out var keyShare))
            {
                throw new NotSupportedException(
                    $"REALITY fingerprint requested unsupported key share group 0x{group:X4}.");
            }

            entriesLength += 4 + keyShare.Length;
        }

        WriteUInt16(payload, checked((ushort)entriesLength));
        if (includeGrease)
        {
            WriteUInt16(payload, greaseValue);
            WriteUInt16(payload, 0x0001);
            payload.WriteByte(0x00);
        }

        foreach (var group in keyShareGroups)
        {
            var publicKey = keyShares[group];
            WriteUInt16(payload, group);
            WriteUInt16(payload, checked((ushort)publicKey.Length));
            payload.Write(publicKey);
        }

        WriteExtension(stream, 0x0033, payload.ToArray());
    }

    private static void WritePaddingExtension(Stream stream, int paddingLength)
        => WriteExtension(stream, 0x0015, new byte[paddingLength]);

    private static void WriteExtension(Stream stream, ushort extensionType, byte[] payload)
    {
        WriteUInt16(stream, extensionType);
        WriteUInt16(stream, checked((ushort)payload.Length));
        stream.Write(payload);
    }

    private static void WriteGreaseExtension(
        Stream stream,
        ushort greaseValue,
        byte[] payload)
        => WriteExtension(stream, greaseValue, payload);

    private static RuntimeTlsGreaseValues CreateGreaseValues()
    {
        var extension1 = CreateGreaseValue();
        var extension2 = CreateGreaseValue();
        while (extension2 == extension1)
        {
            extension2 = CreateGreaseValue();
        }

        return new RuntimeTlsGreaseValues(
            CipherSuite: CreateGreaseValue(),
            Group: CreateGreaseValue(),
            Extension1: extension1,
            Extension2: extension2,
            SupportedVersion: CreateGreaseValue());
    }

    private static ushort CreateGreaseValue()
    {
        var value = (byte)(0x0A + (RandomNumberGenerator.GetInt32(16) * 0x10));
        return (ushort)((value << 8) | value);
    }

    private static void ShuffleInPlace<T>(T[] values)
    {
        for (var index = values.Length - 1; index > 0; index--)
        {
            var swapIndex = RandomNumberGenerator.GetInt32(index + 1);
            (values[index], values[swapIndex]) = (values[swapIndex], values[index]);
        }
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }

    private static void WriteUInt24(Stream stream, int value)
    {
        stream.WriteByte((byte)((value >> 16) & 0xFF));
        stream.WriteByte((byte)((value >> 8) & 0xFF));
        stream.WriteByte((byte)(value & 0xFF));
    }
}

#pragma warning disable SYSLIB0039
using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class RuntimeTlsFingerprintCatalog
{
    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();

    public static bool IsKnown(string? value)
        => RuntimeRealityFingerprintCatalog.IsKnown(Normalize(value));

    public static bool ShouldUseSslStreamFallback(string? value)
        => ShouldUseSslStreamFallback(value, SslProtocols.Tls12 | SslProtocols.Tls13);

    public static bool ShouldUseSslStreamFallback(string? value, SslProtocols enabledSslProtocols)
    {
        var normalized = Normalize(value);
        return !IsKnown(normalized) ||
               normalized is "unsafe" ||
               (normalized.Length == 0 && !ShouldTreatEmptyAsDefaultChrome(enabledSslProtocols));
    }

    public static bool ShouldUseCustomClient(string? value)
        => ShouldUseCustomClient(value, SslProtocols.Tls12 | SslProtocols.Tls13);

    public static bool ShouldUseCustomClient(string? value, SslProtocols enabledSslProtocols)
        => !ShouldUseSslStreamFallback(value, enabledSslProtocols);

    public static bool ShouldTreatEmptyAsDefaultChrome(SslProtocols enabledSslProtocols)
        => true;
}

internal sealed record RuntimeTlsFingerprintHandshakeRequest
{
    public required Stream TransportStream { get; init; }

    public required string ServerHost { get; init; }

    public required string ServerName { get; init; }

    public required string TransportProtocol { get; init; }

    public required IReadOnlyList<string> ApplicationProtocols { get; init; }

    public required string Fingerprint { get; init; }

    public bool SkipCertificateValidation { get; init; }

    public RemoteCertificateValidationCallback? CertificateValidationCallback { get; init; }

    public SslProtocols EnabledSslProtocols { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;
}

internal sealed record RuntimeTlsFingerprintHandshakeResult
{
    public required Stream TransportStream { get; init; }

    public SslStream? SslStream { get; init; }

    public required RuntimeInternetSecurityState SecurityState { get; init; }
}

internal sealed class RuntimeTlsFingerprintClient
{
    private readonly RuntimeTlsFingerprintHandshakeRequest _request;
    private readonly Stream _transportStream;

    public RuntimeTlsFingerprintClient(RuntimeTlsFingerprintHandshakeRequest request)
    {
        _request = request ?? throw new ArgumentNullException(nameof(request));
        _transportStream = request.TransportStream;
    }

    public async Task<RuntimeTlsFingerprintHandshakeResult> ConnectAsync(CancellationToken cancellationToken)
    {
        var clientHelloProfile = ConstrainEnabledProtocols(
            EnsureApplicationProtocols(
                RuntimeRealityTls13ClientHelloProfileCatalog.Resolve(_request.Fingerprint),
                _request.TransportProtocol,
                _request.ApplicationProtocols),
            _request.EnabledSslProtocols);
        EnsureSupportedProtocols(clientHelloProfile);

        var keyShareRequirements = RuntimeTls13KeyShareNegotiation.ResolveClientKeyShareRequirements(clientHelloProfile);

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
            new RuntimeRealityHandshakeRequest
            {
                TransportStream = _transportStream,
                ServerHost = _request.ServerHost,
                ServerName = _request.ServerName,
                TransportProtocol = _request.TransportProtocol,
                ApplicationProtocols = _request.ApplicationProtocols,
                RealityOptions = RuntimeRealityOptions.Empty,
                SkipCertificateValidation = _request.SkipCertificateValidation,
                CertificateValidationCallback = _request.CertificateValidationCallback,
                EnabledSslProtocols = _request.EnabledSslProtocols
            },
            clientHelloProfile,
            keyShares);

        var currentClientHello = rawClientHello;
        var currentClientHelloMessage = rawClientHello.AsSpan(5).ToArray();

        await _transportStream
            .WriteAsync(rawClientHello.AsMemory(0, rawClientHello.Length), cancellationToken)
            .ConfigureAwait(false);
        await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var serverHelloFlight = await ReadServerHelloAsync(cancellationToken).ConfigureAwait(false);
        var serverHelloInfo = RuntimeTlsServerHelloInfo.Parse(serverHelloFlight.ServerHelloMessage);
        switch (serverHelloInfo.NegotiatedSslProtocol)
        {
            case SslProtocols.Tls12:
            case SslProtocols.Tls11:
            case SslProtocols.Tls:
                return await RuntimeTls12FingerprintHandshake
                    .CompleteAsync(
                        _request,
                        _transportStream,
                        currentClientHelloMessage,
                        serverHelloInfo,
                        serverHelloFlight.PendingHandshakeMessages,
                        cancellationToken)
                    .ConfigureAwait(false);
            case SslProtocols.Tls13:
                break;
            default:
                throw new AuthenticationException(
                    $"The TLS peer selected an unsupported protocol version '{serverHelloInfo.NegotiatedSslProtocol}'.");
        }

        EnsureTls13WasOffered(clientHelloProfile);
        ValidateNoPendingPlaintextHandshakeBytes(serverHelloFlight.PendingHandshakeMessages);

        var sentCompatibilityChangeCipherSpec = false;
        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(currentClientHelloMessage);

        var serverHelloMessage = serverHelloFlight.ServerHelloMessage;
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
                currentClientHello,
                serverHello,
                keyShares);
            currentClientHello = retryClientHello;
            currentClientHelloMessage = retryClientHello.AsSpan(5).ToArray();
            transcript.Append(retryClientHello.AsSpan(5));

            await _transportStream
                .WriteAsync(retryClientHello.AsMemory(0, retryClientHello.Length), cancellationToken)
                .ConfigureAwait(false);
            await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            serverHelloFlight = await ReadServerHelloAsync(cancellationToken).ConfigureAwait(false);
            ValidateNoPendingPlaintextHandshakeBytes(serverHelloFlight.PendingHandshakeMessages);
            serverHelloMessage = serverHelloFlight.ServerHelloMessage;
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
                currentClientHelloMessage,
                serverHelloMessage,
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
            var transportStream = new RuntimeTls13DuplexStream(
                _transportStream,
                applicationReadProtector,
                applicationWriteProtector);
            var remoteCertificate = X509CertificateLoader.LoadCertificate(serverPeer.LeafCertificate!.RawData);

            return new RuntimeTlsFingerprintHandshakeResult
            {
                TransportStream = transportStream,
                SecurityState = RuntimeInternetSecurityState.Create(
                    RuntimeInternetSecurityTypes.Tls,
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

    private static void EnsureSupportedProtocols(RuntimeRealityTls13ClientHelloProfile profile)
    {
        if (profile.SupportedVersions.Count == 0 &&
            (profile.CipherSuites.Count == 0 ||
             profile.Extensions.Contains(RuntimeRealityTls13ExtensionKind.SupportedVersions) ||
             profile.CipherSuites.All(static cipherSuite => IsTls13CipherSuite(cipherSuite))))
        {
            throw new NotSupportedException("TLS fingerprint handshakes require TLS 1.2 or TLS 1.3 to be enabled.");
        }
    }

    private static void EnsureTls13WasOffered(RuntimeRealityTls13ClientHelloProfile profile)
    {
        if (!profile.SupportedVersions.Any(static version => version == 0x0304))
        {
            throw new AuthenticationException("The TLS peer selected TLS 1.3 even though the ClientHello did not offer TLS 1.3.");
        }
    }

    private static void ValidateNoPendingPlaintextHandshakeBytes(ResizableByteQueue pendingHandshakeMessages)
    {
        ArgumentNullException.ThrowIfNull(pendingHandshakeMessages);
        if (pendingHandshakeMessages.Length > 0)
        {
            throw new AuthenticationException(
                "TLS 1.3 ServerHello record unexpectedly contained additional plaintext handshake bytes.");
        }
    }

    private static RuntimeRealityTls13ClientHelloProfile ConstrainEnabledProtocols(
        RuntimeRealityTls13ClientHelloProfile profile,
        SslProtocols enabledSslProtocols)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var allowTls13 = (enabledSslProtocols & SslProtocols.Tls13) != 0;
        var allowTls12 = (enabledSslProtocols & SslProtocols.Tls12) != 0;
        var allowTls11 = (enabledSslProtocols & SslProtocols.Tls11) != 0;
        var allowTls10 = (enabledSslProtocols & SslProtocols.Tls) != 0;
        var supportedVersions = FilterSupportedVersions(
            profile.SupportedVersions,
            allowTls13,
            allowTls12,
            allowTls11,
            allowTls10);
        var clientHelloLegacyVersion = ResolveClientHelloLegacyVersion(
            supportedVersions,
            allowTls12,
            allowTls11,
            allowTls10);
        if (supportedVersions.Length == 0)
        {
            if (profile.SupportedVersions.Count != 0 || !HasAnyLegacyProtocols(allowTls12, allowTls11, allowTls10))
            {
                return CreateUnsupportedProfile(profile);
            }

            var legacyCipherSuites = profile.CipherSuites
                .Where(cipherSuite => !IsTls13CipherSuite(cipherSuite))
                .ToArray();
            if (legacyCipherSuites.Length == 0)
            {
                return CreateUnsupportedProfile(profile);
            }

            return profile with
            {
                CipherSuites = legacyCipherSuites,
                SupportedGroups = profile.SupportedGroups
                    .Where(group => !IsTls13OnlyNamedGroup(group))
                    .ToArray(),
                KeyShareGroups = Array.Empty<ushort>(),
                SupportedVersions = Array.Empty<ushort>(),
                Extensions = profile.Extensions
                    .Where(extension => extension != RuntimeRealityTls13ExtensionKind.SupportedVersions &&
                                        !IsTls13OnlyExtension(extension))
                    .ToArray(),
                IncludeGreaseKeyShare = false,
                ReuseHybridClassicalX25519KeyShare = false,
                ClientHelloLegacyVersion = clientHelloLegacyVersion
            };
        }

        var removeTls13OnlyFeatures = !allowTls13;
        var cipherSuites = profile.CipherSuites
            .Where(cipherSuite => allowTls13 || !IsTls13CipherSuite(cipherSuite))
            .Where(cipherSuite => HasAnyLegacyProtocols(allowTls12, allowTls11, allowTls10) || IsTls13CipherSuite(cipherSuite))
            .ToArray();
        var supportedGroups = allowTls13
            ? profile.SupportedGroups.ToArray()
            : profile.SupportedGroups
                .Where(group => !IsTls13OnlyNamedGroup(group))
                .ToArray();
        var keyShareGroups = allowTls13
            ? profile.KeyShareGroups.ToArray()
            : Array.Empty<ushort>();
        var extensions = removeTls13OnlyFeatures
            ? profile.Extensions
                .Where(extension => !IsTls13OnlyExtension(extension))
                .ToArray()
            : profile.Extensions.ToArray();
        return profile with
        {
            CipherSuites = cipherSuites,
            SupportedGroups = supportedGroups,
            KeyShareGroups = keyShareGroups,
            SupportedVersions = supportedVersions,
            Extensions = extensions,
            IncludeGreaseKeyShare = allowTls13 && profile.IncludeGreaseKeyShare,
            ReuseHybridClassicalX25519KeyShare = allowTls13 && profile.ReuseHybridClassicalX25519KeyShare,
            ClientHelloLegacyVersion = clientHelloLegacyVersion
        };
    }

    private static ushort[] FilterSupportedVersions(
        IReadOnlyList<ushort> supportedVersions,
        bool allowTls13,
        bool allowTls12,
        bool allowTls11,
        bool allowTls10)
    {
        var maxLegacyVersion = ResolveMaxLegacyEnabledVersion(allowTls12, allowTls11, allowTls10);
        return supportedVersions
            .Where(version =>
                (allowTls13 && version == 0x0304) ||
                (maxLegacyVersion != 0 && version is >= 0x0301 and <= 0x0303 && version <= maxLegacyVersion))
            .ToArray();
    }

    private static bool HasAnyLegacyProtocols(bool allowTls12, bool allowTls11, bool allowTls10)
        => allowTls12 || allowTls11 || allowTls10;

    private static ushort ResolveClientHelloLegacyVersion(
        IReadOnlyList<ushort> supportedVersions,
        bool allowTls12,
        bool allowTls11,
        bool allowTls10)
    {
        var maxLegacyVersion = ResolveMaxLegacyEnabledVersion(allowTls12, allowTls11, allowTls10);
        foreach (var supportedVersion in supportedVersions)
        {
            if (supportedVersion is >= 0x0301 and <= 0x0303)
            {
                return supportedVersion;
            }
        }

        if (maxLegacyVersion != 0)
        {
            return maxLegacyVersion;
        }

        return 0x0303;
    }

    private static ushort ResolveMaxLegacyEnabledVersion(bool allowTls12, bool allowTls11, bool allowTls10)
    {
        if (allowTls12)
        {
            return 0x0303;
        }

        if (allowTls11)
        {
            return 0x0302;
        }

        if (allowTls10)
        {
            return 0x0301;
        }

        return 0;
    }

    private static bool IsTls13CipherSuite(ushort cipherSuite)
        => cipherSuite is >= 0x1301 and <= 0x1305;

    private static bool IsTls13OnlyNamedGroup(ushort namedGroup)
        => namedGroup is RuntimeTlsNamedGroups.X25519Kyber768Draft00 or
            RuntimeTlsNamedGroups.X25519MLKem768 or
            RuntimeTlsNamedGroups.Secp256r1MLKem768 or
            RuntimeTlsNamedGroups.Secp384r1MLKem1024;

    private static bool IsTls13OnlyExtension(RuntimeRealityTls13ExtensionKind extension)
        => extension is RuntimeRealityTls13ExtensionKind.DelegatedCredentials or
           RuntimeRealityTls13ExtensionKind.CompressCertificate or
           RuntimeRealityTls13ExtensionKind.ApplicationSettings or
           RuntimeRealityTls13ExtensionKind.ApplicationSettingsNew or
           RuntimeRealityTls13ExtensionKind.EchGrease or
           RuntimeRealityTls13ExtensionKind.KeyShare or
           RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes;

    private static RuntimeRealityTls13ClientHelloProfile CreateUnsupportedProfile(RuntimeRealityTls13ClientHelloProfile profile)
        => profile with
        {
            SupportedVersions = Array.Empty<ushort>(),
            CipherSuites = Array.Empty<ushort>(),
            KeyShareGroups = Array.Empty<ushort>(),
            Extensions = Array.Empty<RuntimeRealityTls13ExtensionKind>(),
            IncludeGreaseKeyShare = false,
            ReuseHybridClassicalX25519KeyShare = false
        };

    private ValueTask WriteCompatibilityChangeCipherSpecAsync(CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> record = new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        return _transportStream.WriteAsync(record, cancellationToken);
    }

    private static RuntimeRealityTls13ClientHelloProfile EnsureApplicationProtocols(
        RuntimeRealityTls13ClientHelloProfile profile,
        string transportProtocol,
        IReadOnlyList<string> applicationProtocols)
    {
        var usesHttp11OnlyApplicationProtocols =
            RuntimeInternetTransportProtocols.UsesHttp11OnlyApplicationProtocols(transportProtocol);
        if ((!profile.AllowAutomaticApplicationProtocolInjection && !usesHttp11OnlyApplicationProtocols) ||
            (applicationProtocols.Count == 0 && !usesHttp11OnlyApplicationProtocols) ||
            profile.Extensions.Contains(RuntimeRealityTls13ExtensionKind.ApplicationProtocols))
        {
            return profile;
        }

        var extensions = profile.Extensions.ToList();
        var paddingIndex = extensions.FindIndex(static kind => kind == RuntimeRealityTls13ExtensionKind.Padding);
        if (paddingIndex >= 0)
        {
            extensions.Insert(paddingIndex, RuntimeRealityTls13ExtensionKind.ApplicationProtocols);
        }
        else
        {
            extensions.Add(RuntimeRealityTls13ExtensionKind.ApplicationProtocols);
        }

        return profile with
        {
            Extensions = extensions.ToArray()
        };
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
        ReadOnlySpan<byte> clientHello,
        RuntimeTls13ServerHello helloRetryRequest,
        IReadOnlyDictionary<ushort, byte[]> keyShares)
    {
        if (!helloRetryRequest.IsHelloRetryRequest)
        {
            throw new ArgumentException("The supplied ServerHello is not a HelloRetryRequest.", nameof(helloRetryRequest));
        }

        if (!RuntimeRealityClientHelloDocument.TryParse(clientHello, out var document, out var error) ||
            document is null)
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

        return document.CreateHelloRetryRequestResponse(
            document.SessionId,
            helloRetryRequest.KeyShareGroup,
            retryKeyShare,
            helloRetryRequest.HelloRetryRequestCookieExtensionPayload);
    }

    private async Task<RuntimeTlsServerHelloFlight> ReadServerHelloAsync(CancellationToken cancellationToken)
    {
        var handshakeBuffer = new ResizableByteQueue();
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(_transportStream, allowEof: false, cancellationToken).ConfigureAwait(false)
                ?? throw new EndOfStreamException("Unexpected EOF while waiting for the TLS ServerHello.");

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls13AlertExceptionFactory.Create(record.Payload, encrypted: false);
                case RuntimeTls13RecordType.Handshake:
                    handshakeBuffer.Append(record.Payload);
                    if (!TryReadHandshakeMessage(handshakeBuffer, out var serverHelloMessage))
                    {
                        continue;
                    }

                    if (serverHelloMessage[0] != (byte)RuntimeTls13HandshakeType.ServerHello)
                    {
                        throw new AuthenticationException("The TLS peer did not return a ServerHello.");
                    }

                    return new RuntimeTlsServerHelloFlight(serverHelloMessage, handshakeBuffer);
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' while waiting for the ServerHello.");
            }
        }
    }

    private async Task<RuntimeTls13ServerPeer> ReceiveServerHandshakeAsync(
        RuntimeTls13TrafficProtector serverHandshakeProtector,
        RuntimeTls13HandshakeTranscript transcript,
        byte[] clientHelloMessage,
        byte[] serverHelloMessage,
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
                                        ValidateServerCertificate(peer, clientHelloMessage, serverHelloMessage);
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

    private void ValidateServerCertificate(
        RuntimeTls13ServerPeer peer,
        byte[] clientHelloMessage,
        byte[] serverHelloMessage)
    {
        ArgumentNullException.ThrowIfNull(peer);
        _ = clientHelloMessage;
        _ = serverHelloMessage;

        if (peer.LeafCertificate is null)
        {
            throw new AuthenticationException("TLS 1.3 Certificate message did not include a leaf certificate.");
        }

        X509Chain? chain = null;
        try
        {
            if (!RuntimeServerCertificateValidation.Validate(
                    _request.ServerName,
                    _request.SkipCertificateValidation,
                    _request.CertificateValidationCallback,
                    this,
                    peer.LeafCertificate,
                    peer.CertificateChain,
                    out chain!,
                    out var errors))
            {
                throw new AuthenticationException(
                    $"TLS 1.3 server certificate validation failed: {errors}.");
            }
        }
        finally
        {
            chain?.Dispose();
        }
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
            peer.CertificateChain.Add(X509CertificateLoader.LoadCertificate(rawCertificate));
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
                $"TLS 1.3 signature algorithm 0x{algorithm:X4} is not supported by the built-in fingerprint client.")
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
        WriteUInt24(message.AsSpan(1, 3), body.Length);
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

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }
}

#pragma warning restore SYSLIB0039

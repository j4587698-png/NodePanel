using System.Buffers.Binary;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeRealityTls13ClientHelloProfileTests
{
    [Fact]
    public void Build_uses_firefox_profile_distinct_from_chrome()
    {
        var chromePayload = BuildClientHello("chrome");
        var firefoxPayload = BuildClientHello("firefox");

        Assert.True(RuntimeTlsClientHelloParser.TryParse(chromePayload, out var chromeMetadata));
        Assert.True(RuntimeTlsClientHelloParser.TryParse(firefoxPayload, out var firefoxMetadata));
        Assert.NotEqual(chromeMetadata.Ja3Text, firefoxMetadata.Ja3Text);

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(chromePayload, out var chromeHello, out var chromeError), chromeError);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(firefoxPayload, out var firefoxHello, out var firefoxError), firefoxError);
        Assert.NotNull(chromeHello);
        Assert.NotNull(firefoxHello);

        Assert.Contains(chromeHello!.Extensions, static extension => IsGreaseValue(extension.Type));
        Assert.DoesNotContain(firefoxHello!.Extensions, static extension => IsGreaseValue(extension.Type));

        var chromeKeyShares = ParseKeyShares(chromeHello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        var firefoxKeyShares = ParseKeyShares(firefoxHello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Contains(chromeHello.Extensions, static extension => extension.Type == 0x44CD);
        Assert.DoesNotContain(chromeHello.Extensions, static extension => extension.Type == 0x4469);
        Assert.Contains(firefoxHello.Extensions, static extension => extension.Type == 0x0022);
        Assert.Contains(firefoxHello.Extensions, static extension => extension.Type == 0x001C);
        Assert.Contains(firefoxHello.Extensions, static extension => extension.Type == 0x001B);
        Assert.Contains(firefoxHello.Extensions, static extension => extension.Type == 0xFE0D);

        Assert.Equal(RuntimeX25519MlKem768.IsSupported ? 3 : 2, chromeKeyShares.Count);
        Assert.True(IsGreaseValue(chromeKeyShares[0].Group));
        if (RuntimeX25519MlKem768.IsSupported)
        {
            Assert.Equal(RuntimeTlsNamedGroups.X25519MLKem768, chromeKeyShares[1].Group);
            Assert.Equal(RuntimeTlsNamedGroups.X25519, chromeKeyShares[2].Group);

            Assert.Equal(3, firefoxKeyShares.Count);
            Assert.Equal(RuntimeTlsNamedGroups.X25519MLKem768, firefoxKeyShares[0].Group);
            Assert.Equal(RuntimeTlsNamedGroups.X25519, firefoxKeyShares[1].Group);
            Assert.Equal(RuntimeTlsNamedGroups.Secp256r1, firefoxKeyShares[2].Group);
            Assert.Equal(
                firefoxKeyShares[1].KeyExchange,
                firefoxKeyShares[0].KeyExchange[^RuntimeX25519.KeyLength..]);
        }
        else
        {
            Assert.Equal(RuntimeTlsNamedGroups.X25519, chromeKeyShares[1].Group);

            Assert.Equal(2, firefoxKeyShares.Count);
            Assert.Equal(RuntimeTlsNamedGroups.X25519, firefoxKeyShares[0].Group);
            Assert.Equal(RuntimeTlsNamedGroups.Secp256r1, firefoxKeyShares[1].Group);
        }
    }

    [Fact]
    public void Build_omits_alpn_for_randomizednoalpn_fingerprint()
    {
        var payload = BuildClientHello("randomizednoalpn");

        Assert.True(RuntimeTlsClientHelloParser.TryParse(payload, out var metadata));
        Assert.Empty(metadata.ApplicationProtocols);

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.DoesNotContain(hello!.Extensions, static extension => extension.Type == 0x0010);
    }

    [Fact]
    public void Build_uses_x25519kyber_pq_profile_layout_distinct_from_chrome()
    {
        if (!RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        var chromePayload = BuildClientHello("chrome");
        var pqPayload = BuildClientHello("hellochrome_120_pq");

        Assert.True(RuntimeTlsClientHelloParser.TryParse(chromePayload, out var chromeMetadata));
        Assert.True(RuntimeTlsClientHelloParser.TryParse(pqPayload, out var pqMetadata));
        Assert.NotEqual(chromeMetadata.Ja3Text, pqMetadata.Ja3Text);

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(pqPayload, out var pqHello, out var error), error);
        Assert.NotNull(pqHello);
        Assert.DoesNotContain(pqHello!.Extensions, static extension => extension.Type == 0x0015);
        Assert.Contains(pqHello.Extensions, static extension => extension.Type == 0xFE0D);
        Assert.NotNull(pqHello.X25519PublicKey);
        Assert.Equal(RuntimeX25519.KeyLength, pqHello.X25519PublicKey!.Length);

        var keyShares = ParseKeyShares(pqHello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Equal(3, keyShares.Count);
        Assert.True(IsGreaseValue(keyShares[0].Group));
        Assert.Equal(RuntimeTlsNamedGroups.X25519Kyber768Draft00, keyShares[1].Group);
        Assert.Equal(RuntimeX25519Kyber768Draft00.ClientKeyShareLength, keyShares[1].KeyExchange.Length);
        Assert.Equal(RuntimeTlsNamedGroups.X25519, keyShares[2].Group);
        Assert.Equal(RuntimeX25519.KeyLength, keyShares[2].KeyExchange.Length);
        Assert.NotEqual(
            keyShares[2].KeyExchange,
            keyShares[1].KeyExchange[..RuntimeX25519.KeyLength]);
    }

    [Fact]
    public void Build_uses_x25519mlkem768_profile_layout_for_chrome_131()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        var payload = BuildClientHello("hellochrome_131");

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.DoesNotContain(hello!.Extensions, static extension => extension.Type == 0x0015);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0xFE0D);
        Assert.NotNull(hello.X25519PublicKey);
        Assert.Equal(RuntimeX25519.KeyLength, hello.X25519PublicKey!.Length);

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Equal(3, keyShares.Count);
        Assert.True(IsGreaseValue(keyShares[0].Group));
        Assert.Equal(RuntimeTlsNamedGroups.X25519MLKem768, keyShares[1].Group);
        Assert.Equal(RuntimeX25519MlKem768.ClientKeyShareLength, keyShares[1].KeyExchange.Length);
        Assert.Equal(RuntimeTlsNamedGroups.X25519, keyShares[2].Group);
        Assert.Equal(RuntimeX25519.KeyLength, keyShares[2].KeyExchange.Length);
        Assert.NotEqual(
            keyShares[2].KeyExchange,
            keyShares[1].KeyExchange[^RuntimeX25519.KeyLength..]);
    }

    [Fact]
    public void Build_uses_safari_26_3_profile_layout_for_safari_auto()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        var payload = BuildClientHello("safari");

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.DoesNotContain(hello!.Extensions, static extension => extension.Type == 0x0015);
        Assert.DoesNotContain(hello.Extensions, static extension => extension.Type == 0xFE0D);
        Assert.Contains(hello.Extensions, static extension => extension.Type == 0x001B);

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Equal(3, keyShares.Count);
        Assert.True(IsGreaseValue(keyShares[0].Group));
        Assert.Equal(RuntimeTlsNamedGroups.X25519MLKem768, keyShares[1].Group);
        Assert.Equal(RuntimeTlsNamedGroups.X25519, keyShares[2].Group);
    }

    [Fact]
    public void Build_encodes_compress_certificate_extension_with_uint8_algorithm_vector_length()
    {
        var chromePayload = BuildClientHello("chrome");
        var firefoxPayload = BuildClientHello("firefox");

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(chromePayload, out var chromeHello, out var chromeError), chromeError);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(firefoxPayload, out var firefoxHello, out var firefoxError), firefoxError);
        Assert.NotNull(chromeHello);
        Assert.NotNull(firefoxHello);

        var chromeCompressCertificate = chromeHello!.Extensions.Single(static extension => extension.Type == 0x001B);
        Assert.Equal([0x02, 0x00, 0x02], chromeCompressCertificate.Payload);

        var firefoxCompressCertificate = firefoxHello!.Extensions.Single(static extension => extension.Type == 0x001B);
        Assert.Equal([0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03], firefoxCompressCertificate.Payload);
    }

    [Fact]
    public void Build_accepts_custom_secp256r1mlkem768_profile()
    {
        if (!RuntimeSecp256r1MlKem768.IsSupported)
        {
            return;
        }

        var payload = BuildClientHello(CreateHybridProfile(
            RuntimeTlsNamedGroups.Secp256r1MLKem768,
            [
                RuntimeTlsNamedGroups.Secp256r1MLKem768,
                RuntimeTlsNamedGroups.Secp256r1,
                RuntimeTlsNamedGroups.X25519
            ]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.Null(hello!.X25519PublicKey);

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Single(keyShares);
        Assert.Equal(RuntimeTlsNamedGroups.Secp256r1MLKem768, keyShares[0].Group);
        Assert.Equal(RuntimeSecp256r1MlKem768.ClientKeyShareLength, keyShares[0].KeyExchange.Length);
    }

    [Fact]
    public void Build_accepts_custom_secp384r1mlkem1024_profile()
    {
        if (!RuntimeSecp384r1MlKem1024.IsSupported)
        {
            return;
        }

        var payload = BuildClientHello(CreateHybridProfile(
            RuntimeTlsNamedGroups.Secp384r1MLKem1024,
            [
                RuntimeTlsNamedGroups.Secp384r1MLKem1024,
                RuntimeTlsNamedGroups.Secp384r1,
                RuntimeTlsNamedGroups.X25519
            ]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.Null(hello!.X25519PublicKey);

        var keyShares = ParseKeyShares(hello.Extensions.Single(static extension => extension.Type == 0x0033).Payload);
        Assert.Single(keyShares);
        Assert.Equal(RuntimeTlsNamedGroups.Secp384r1MLKem1024, keyShares[0].Group);
        Assert.Equal(RuntimeSecp384r1MlKem1024.ClientKeyShareLength, keyShares[0].KeyExchange.Length);
    }

    [Fact]
    public void Build_treats_empty_fingerprint_like_chrome_profile()
    {
        var emptyProfile = RuntimeRealityTls13ClientHelloProfileCatalog.Resolve(string.Empty);
        var chromeProfile = RuntimeRealityTls13ClientHelloProfileCatalog.Resolve("chrome");

        Assert.Equal(chromeProfile.UseGrease, emptyProfile.UseGrease);
        Assert.Equal(chromeProfile.CipherSuites, emptyProfile.CipherSuites);
        Assert.Equal(chromeProfile.SupportedGroups, emptyProfile.SupportedGroups);
        Assert.Equal(chromeProfile.KeyShareGroups, emptyProfile.KeyShareGroups);
        Assert.Equal(chromeProfile.SupportedVersions, emptyProfile.SupportedVersions);
        Assert.Equal(chromeProfile.SignatureAlgorithms, emptyProfile.SignatureAlgorithms);
        Assert.Equal(chromeProfile.SignatureAlgorithmsCert, emptyProfile.SignatureAlgorithmsCert);
        Assert.Equal(chromeProfile.Extensions, emptyProfile.Extensions);
        Assert.Equal(chromeProfile.PaddingLength, emptyProfile.PaddingLength);
        Assert.Equal(chromeProfile.IncludeGreaseKeyShare, emptyProfile.IncludeGreaseKeyShare);
        Assert.Equal(chromeProfile.ShuffleCipherSuites, emptyProfile.ShuffleCipherSuites);
        Assert.Equal(chromeProfile.ShuffleSupportedGroups, emptyProfile.ShuffleSupportedGroups);
        Assert.Equal(chromeProfile.ShuffleKeyShares, emptyProfile.ShuffleKeyShares);
        Assert.Equal(chromeProfile.ReuseHybridClassicalX25519KeyShare, emptyProfile.ReuseHybridClassicalX25519KeyShare);
        Assert.Equal(chromeProfile.RecordSizeLimit, emptyProfile.RecordSizeLimit);
        Assert.Equal(chromeProfile.DelegatedCredentialSignatureAlgorithms, emptyProfile.DelegatedCredentialSignatureAlgorithms);
        Assert.Equal(chromeProfile.CompressCertificateAlgorithms, emptyProfile.CompressCertificateAlgorithms);
        Assert.Equal(chromeProfile.EchGreaseCandidateAeads, emptyProfile.EchGreaseCandidateAeads);
        Assert.Equal(chromeProfile.EchGreaseCandidatePayloadLengths, emptyProfile.EchGreaseCandidatePayloadLengths);
        Assert.Equal(chromeProfile.UseRandomSessionId, emptyProfile.UseRandomSessionId);
        Assert.Equal(chromeProfile.AllowAutomaticApplicationProtocolInjection, emptyProfile.AllowAutomaticApplicationProtocolInjection);
        Assert.Equal(chromeProfile.UseBoringPadding, emptyProfile.UseBoringPadding);
        Assert.Equal(chromeProfile.ShuffleExtensions, emptyProfile.ShuffleExtensions);
        Assert.Equal(chromeProfile.ClientHelloLegacyVersion, emptyProfile.ClientHelloLegacyVersion);
        Assert.Equal(chromeProfile.ClientHelloApplicationProtocols, emptyProfile.ClientHelloApplicationProtocols);
    }

    private static byte[] BuildClientHello(
        string fingerprint,
        IReadOnlyList<string>? applicationProtocols = null)
        => BuildClientHello(
            RuntimeRealityTls13ClientHelloProfileCatalog.Resolve(fingerprint),
            fingerprint,
            applicationProtocols);

    private static byte[] BuildClientHello(
        RuntimeRealityTls13ClientHelloProfile profile,
        string fingerprint = "custom",
        IReadOnlyList<string>? applicationProtocols = null)
    {
        using var x25519KeyPair = RuntimeX25519.CreateKeyPair();
        var usesX25519HybridGroup = profile.KeyShareGroups.Contains(RuntimeTlsNamedGroups.X25519Kyber768Draft00) ||
                                    profile.KeyShareGroups.Contains(RuntimeTlsNamedGroups.X25519MLKem768);
        using var x25519HybridKeyPair = usesX25519HybridGroup && !profile.ReuseHybridClassicalX25519KeyShare
            ? RuntimeX25519.CreateKeyPair()
            : null;
        using var x25519MlKem768KeyPair = usesX25519HybridGroup
            ? RuntimeX25519MlKem768.CreateMlKemKeyPair()
            : null;
        using var secp256r1KeyPair = RuntimeSecp256r1.CreateKeyPair();
        using var secp256r1MlKem768KeyPair = profile.KeyShareGroups.Contains(RuntimeTlsNamedGroups.Secp256r1MLKem768)
            ? RuntimeSecp256r1MlKem768.CreateMlKemKeyPair()
            : null;
        using var secp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        using var secp384r1MlKem1024KeyPair = profile.KeyShareGroups.Contains(RuntimeTlsNamedGroups.Secp384r1MLKem1024)
            ? RuntimeSecp384r1MlKem1024.CreateMlKemKeyPair()
            : null;
        var x25519HybridPublicKey = profile.ReuseHybridClassicalX25519KeyShare
            ? x25519KeyPair.PublicKey
            : x25519HybridKeyPair?.PublicKey ?? Array.Empty<byte>();
        var keyShares = CreateKeyShares(
            profile.KeyShareGroups,
            x25519KeyPair.PublicKey,
            x25519HybridPublicKey,
            x25519MlKem768KeyPair?.PublicKey ?? Array.Empty<byte>(),
            secp256r1KeyPair.PublicKey,
            secp256r1MlKem768KeyPair?.PublicKey ?? Array.Empty<byte>(),
            secp384r1KeyPair.PublicKey,
            secp384r1MlKem1024KeyPair?.PublicKey ?? Array.Empty<byte>());
        return RuntimeRealityTls13ClientHelloBuilder.Build(
            new RuntimeRealityHandshakeRequest
            {
                TransportStream = Stream.Null,
                ServerHost = "127.0.0.1",
                ServerName = "example.com",
                TransportProtocol = "tcp",
                ApplicationProtocols = applicationProtocols ?? ["h2", "http/1.1"],
                RealityOptions = new RuntimeRealityOptions
                {
                    Fingerprint = fingerprint
                }
            },
            profile,
            keyShares);
    }

    private static RuntimeRealityTls13ClientHelloProfile CreateHybridProfile(
        ushort keyShareGroup,
        IReadOnlyList<ushort> supportedGroups)
        => new(
            UseGrease: true,
            CipherSuites: [0x1301, 0x1302, 0x1303, 0x00FF],
            SupportedGroups: supportedGroups,
            KeyShareGroups: [keyShareGroup],
            SupportedVersions: [0x0304, 0x0303],
            SignatureAlgorithms:
            [
                0x0403,
                0x0804,
                0x0401,
                0x0503,
                0x0805,
                0x0501
            ],
            SignatureAlgorithmsCert:
            [
                0x0403,
                0x0804,
                0x0401,
                0x0503,
                0x0805,
                0x0501
            ],
            Extensions:
            [
                RuntimeRealityTls13ExtensionKind.Grease,
                RuntimeRealityTls13ExtensionKind.ServerName,
                RuntimeRealityTls13ExtensionKind.SupportedGroups,
                RuntimeRealityTls13ExtensionKind.SignatureAlgorithms,
                RuntimeRealityTls13ExtensionKind.SupportedVersions,
                RuntimeRealityTls13ExtensionKind.PskKeyExchangeModes,
                RuntimeRealityTls13ExtensionKind.SignatureAlgorithmsCert,
                RuntimeRealityTls13ExtensionKind.KeyShare
            ]);

    private static IReadOnlyDictionary<ushort, byte[]> CreateKeyShares(
        IReadOnlyList<ushort> keyShareGroups,
        byte[] x25519PublicKey,
        byte[] x25519HybridPublicKey,
        byte[] x25519HybridMlKem768PublicKey,
        byte[] secp256r1PublicKey,
        byte[] secp256r1MlKem768PublicKey,
        byte[] secp384r1PublicKey,
        byte[] secp384r1MlKem1024PublicKey)
    {
        var keyShares = new Dictionary<ushort, byte[]>(keyShareGroups.Count);
        foreach (var group in keyShareGroups)
        {
            if (keyShares.ContainsKey(group))
            {
                continue;
            }

            keyShares[group] = group switch
            {
                RuntimeTlsNamedGroups.X25519 => x25519PublicKey,
                RuntimeTlsNamedGroups.X25519Kyber768Draft00 => RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
                    x25519HybridPublicKey,
                    x25519HybridMlKem768PublicKey),
                RuntimeTlsNamedGroups.X25519MLKem768 => RuntimeX25519MlKem768.BuildClientKeyShare(
                    x25519HybridPublicKey,
                    x25519HybridMlKem768PublicKey),
                RuntimeTlsNamedGroups.Secp256r1 => secp256r1PublicKey,
                RuntimeTlsNamedGroups.Secp256r1MLKem768 => RuntimeSecp256r1MlKem768.BuildClientKeyShare(
                    secp256r1PublicKey,
                    secp256r1MlKem768PublicKey),
                RuntimeTlsNamedGroups.Secp384r1 => secp384r1PublicKey,
                RuntimeTlsNamedGroups.Secp384r1MLKem1024 => RuntimeSecp384r1MlKem1024.BuildClientKeyShare(
                    secp384r1PublicKey,
                    secp384r1MlKem1024PublicKey),
                _ => throw new NotSupportedException($"Unsupported test key share group 0x{group:X4}.")
            };
        }

        return keyShares;
    }

    private static List<KeyShareEntry> ParseKeyShares(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return [];
        }

        var entriesLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var position = 2;
        var end = Math.Min(payload.Length, position + entriesLength);
        var entries = new List<KeyShareEntry>();
        while (position + 4 <= end)
        {
            var group = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
            var keyLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position + 2, 2));
            position += 4;
            if (position + keyLength > end)
            {
                break;
            }

            entries.Add(new KeyShareEntry(group, payload.Slice(position, keyLength).ToArray()));
            position += keyLength;
        }

        return entries;
    }

    private static bool IsGreaseValue(int value)
        => (value & 0x0f0f) == 0x0a0a && ((value >> 8) & 0xff) == (value & 0xff);

    private sealed record KeyShareEntry(int Group, byte[] KeyExchange);
}

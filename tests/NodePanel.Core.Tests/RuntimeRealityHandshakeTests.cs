using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeRealityHandshakeTests
{
    [Fact]
    public void TryParse_and_write_preserve_tls13_x25519_client_hello_shape()
    {
        var clientPrivateKey = CreateFixedKey(0x11);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var random = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2", "http/1.1"],
            random,
            sessionId: [0xAA, 0xBB, 0xCC],
            clientPublicKey);

        var parsed = RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error);

        Assert.True(parsed, error);
        Assert.NotNull(hello);
        Assert.True(hello!.SupportsTls13);
        Assert.Equal(clientPublicKey, hello.X25519PublicKey);
        Assert.Equal([0xAA, 0xBB, 0xCC], hello.SessionId);

        var rewritten = hello.Write(new byte[RuntimeRealityClientHelloProtector.EncryptedSessionIdLength]);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(rewritten, out var rewrittenHello, out error), error);
        Assert.NotNull(rewrittenHello);
        Assert.Equal(RuntimeRealityClientHelloProtector.EncryptedSessionIdLength, rewrittenHello!.SessionId.Length);
        Assert.True(rewrittenHello.SessionId.All(static value => value == 0));
        Assert.Equal(clientPublicKey, rewrittenHello.X25519PublicKey);
        Assert.Equal(hello.CipherSuites, rewrittenHello.CipherSuites);
        Assert.Equal(hello.CompressionMethods, rewrittenHello.CompressionMethods);
        Assert.True(rewritten.Length > payload.Length);
    }

    [Fact]
    public void CreateHelloRetryRequestResponse_inserts_cookie_and_rewrites_key_share()
    {
        var clientPrivateKey = CreateFixedKey(0x12);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
            sessionId: Enumerable.Range(32, RuntimeRealityClientHelloProtector.EncryptedSessionIdLength).Select(static value => (byte)value).ToArray(),
            clientPublicKey);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);

        using var secp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        var retryClientHello = hello!.CreateHelloRetryRequestResponse(
            hello.SessionId,
            RuntimeTlsNamedGroups.Secp384r1,
            secp384r1KeyPair.PublicKey,
            BuildCookieExtensionPayload([0xAA, 0xBB, 0xCC]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(retryClientHello, out var retryHello, out error), error);
        Assert.NotNull(retryHello);
        Assert.Equal(hello.SessionId, retryHello!.SessionId);
        Assert.Equal(hello.Random, retryHello.Random);
        Assert.Equal(hello.CipherSuites, retryHello.CipherSuites);

        var cookieExtension = retryHello.Extensions.Single(static extension => extension.Type == 0x002C);
        Assert.Equal(BuildCookieExtensionPayload([0xAA, 0xBB, 0xCC]), cookieExtension.Payload);

        var keyShareExtension = retryHello.Extensions.Single(static extension => extension.Type == 0x0033);
        Assert.Equal([0x00, 0x65, 0x00, 0x18, 0x00, 0x61], keyShareExtension.Payload[..6].ToArray());
        Assert.Equal(secp384r1KeyPair.PublicKey, keyShareExtension.Payload[6..]);
        Assert.Null(retryHello.X25519PublicKey);
    }

    [Fact]
    public void TryProtect_encrypts_session_id_using_xray_core_reality_rules()
    {
        var clientPrivateKey = CreateFixedKey(0x21);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var serverPrivateKey = CreateFixedKey(0x41);
        var serverPublicKey = RuntimeX25519.DerivePublicKey(serverPrivateKey);
        var random = Enumerable.Range(0, 32).Select(static value => (byte)(0x80 + value)).ToArray();
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            random,
            sessionId: [],
            clientPublicKey);
        var options = new RuntimeRealityOptions
        {
            Fingerprint = "chrome",
            PublicKey = EncodeBase64Url(serverPublicKey),
            ShortId = "a1b2c3d4"
        };
        var timestamp = DateTimeOffset.FromUnixTimeSeconds(1_710_500_000);

        var protectedResult = RuntimeRealityClientHelloProtector.TryProtect(
            payload,
            clientPrivateKey,
            options,
            timestamp,
            out var result,
            out var error);

        Assert.True(protectedResult, error);
        Assert.NotNull(result);
        Assert.Equal(RuntimeRealityClientHelloProtector.EncryptedSessionIdLength, result!.EncryptedSessionId.Length);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(result.ZeroSessionIdClientHello, out var zeroHello, out error), error);
        Assert.NotNull(zeroHello);
        Assert.Equal(RuntimeRealityClientHelloProtector.EncryptedSessionIdLength, zeroHello!.SessionId.Length);
        Assert.True(zeroHello.SessionId.All(static value => value == 0));

        var decrypted = new byte[RuntimeRealityClientHelloProtector.PlainSessionIdLength];
        using var aead = new AesGcm(result.AuthKey, RuntimeRealityClientHelloProtector.EncryptedSessionIdLength - RuntimeRealityClientHelloProtector.PlainSessionIdLength);
        aead.Decrypt(
            random.AsSpan(20, 12),
            result.EncryptedSessionId.AsSpan(0, RuntimeRealityClientHelloProtector.PlainSessionIdLength),
            result.EncryptedSessionId.AsSpan(RuntimeRealityClientHelloProtector.PlainSessionIdLength),
            decrypted,
            result.ZeroSessionIdClientHello.AsSpan(5));

        var expectedPlainSessionId = new byte[RuntimeRealityClientHelloProtector.PlainSessionIdLength];
        expectedPlainSessionId[0] = RuntimeRealityProtocolVersion.Major;
        expectedPlainSessionId[1] = RuntimeRealityProtocolVersion.Minor;
        expectedPlainSessionId[2] = RuntimeRealityProtocolVersion.Patch;
        expectedPlainSessionId[3] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(expectedPlainSessionId.AsSpan(4, 4), checked((uint)timestamp.ToUnixTimeSeconds()));
        Convert.FromHexString("a1b2c3d4").AsSpan().CopyTo(expectedPlainSessionId.AsSpan(8));

        Assert.Equal(expectedPlainSessionId, decrypted);
        Assert.Equal(expectedPlainSessionId, result.PlainSessionId);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(result.ProtectedClientHello, out var protectedHello, out error), error);
        Assert.NotNull(protectedHello);
        Assert.Equal(result.EncryptedSessionId, protectedHello!.SessionId);
        Assert.Equal(clientPublicKey, protectedHello.X25519PublicKey);
    }

    [Fact]
    public void TryProtect_rejects_client_hello_without_tls13_support()
    {
        var clientPrivateKey = CreateFixedKey(0x31);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Repeat((byte)0x44, 32).ToArray(),
            sessionId: [],
            clientPublicKey,
            includeSupportedVersions: false);

        var protectedResult = RuntimeRealityClientHelloProtector.TryProtect(
            payload,
            clientPrivateKey,
            new RuntimeRealityOptions
            {
                PublicKey = EncodeBase64Url(RuntimeX25519.DerivePublicKey(CreateFixedKey(0x51)))
            },
            DateTimeOffset.UnixEpoch,
            out _,
            out var error);

        Assert.False(protectedResult);
        Assert.Contains("TLS 1.3", error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryProtect_rejects_client_hello_without_x25519_key_share()
    {
        var clientPrivateKey = CreateFixedKey(0x61);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Repeat((byte)0x55, 32).ToArray(),
            sessionId: [],
            clientPublicKey,
            includeKeyShare: false);

        var protectedResult = RuntimeRealityClientHelloProtector.TryProtect(
            payload,
            clientPrivateKey,
            new RuntimeRealityOptions
            {
                PublicKey = EncodeBase64Url(RuntimeX25519.DerivePublicKey(CreateFixedKey(0x71)))
            },
            DateTimeOffset.UnixEpoch,
            out _,
            out var error);

        Assert.False(protectedResult);
        Assert.Contains("X25519", error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryParse_prefers_plain_x25519_share_over_hybrid_x25519_component()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        var hybridPrivateKey = CreateFixedKey(0x17);
        var hybridPublicKey = RuntimeX25519.DerivePublicKey(hybridPrivateKey);
        using var mlKem768KeyPair = RuntimeX25519MlKem768.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519MlKem768.BuildClientKeyShare(
            hybridPublicKey,
            mlKem768KeyPair.PublicKey);

        var classicalPrivateKey = CreateFixedKey(0x18);
        var classicalPublicKey = RuntimeX25519.DerivePublicKey(classicalPrivateKey);
        var payload = BuildTls13ClientHello(
            "pq.example.com",
            ["h2", "http/1.1"],
            Enumerable.Repeat((byte)0x33, 32).ToArray(),
            sessionId: [0xAA, 0xBB],
            classicalPublicKey,
            keyShares:
            [
                new KeyShareDefinition(RuntimeTlsNamedGroups.X25519MLKem768, hybridKeyShare),
                new KeyShareDefinition(RuntimeTlsNamedGroups.X25519, classicalPublicKey)
            ],
            supportedGroups:
            [
                RuntimeTlsNamedGroups.X25519MLKem768,
                RuntimeTlsNamedGroups.X25519,
                RuntimeTlsNamedGroups.Secp256r1
            ]);

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.Equal(classicalPublicKey, hello!.X25519PublicKey);
    }

    [Fact]
    public void TryParse_extracts_x25519_public_key_from_x25519mlkem768_key_share()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x19);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        using var mlKem768KeyPair = RuntimeX25519MlKem768.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519MlKem768.BuildClientKeyShare(
            clientPublicKey,
            mlKem768KeyPair.PublicKey);
        var payload = BuildTls13ClientHello(
            "pq.example.com",
            ["h2", "http/1.1"],
            Enumerable.Repeat((byte)0x42, 32).ToArray(),
            sessionId: [0xAA, 0xBB],
            clientPublicKey,
            keyShares:
            [
                new KeyShareDefinition(RuntimeTlsNamedGroups.X25519MLKem768, hybridKeyShare)
            ],
            supportedGroups:
            [
                RuntimeTlsNamedGroups.X25519MLKem768,
                RuntimeTlsNamedGroups.X25519,
                RuntimeTlsNamedGroups.Secp256r1
            ]);

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.Equal(clientPublicKey, hello!.X25519PublicKey);

        var rewritten = hello.Write(new byte[RuntimeRealityClientHelloProtector.EncryptedSessionIdLength]);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(rewritten, out var rewrittenHello, out error), error);
        Assert.NotNull(rewrittenHello);
        Assert.Equal(clientPublicKey, rewrittenHello!.X25519PublicKey);
    }

    [Fact]
    public void TryParse_extracts_x25519_public_key_from_x25519kyber768draft00_key_share()
    {
        if (!RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x1D);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        using var mlKem768KeyPair = RuntimeX25519Kyber768Draft00.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
            clientPublicKey,
            mlKem768KeyPair.PublicKey);
        var payload = BuildTls13ClientHello(
            "pq.example.com",
            ["h2", "http/1.1"],
            Enumerable.Repeat((byte)0x52, 32).ToArray(),
            sessionId: [0xAA, 0xBB],
            clientPublicKey,
            keyShares:
            [
                new KeyShareDefinition(RuntimeTlsNamedGroups.X25519Kyber768Draft00, hybridKeyShare)
            ],
            supportedGroups:
            [
                RuntimeTlsNamedGroups.X25519Kyber768Draft00,
                RuntimeTlsNamedGroups.X25519,
                RuntimeTlsNamedGroups.Secp256r1
            ]);

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);
        Assert.Equal(clientPublicKey, hello!.X25519PublicKey);

        var rewritten = hello.Write(new byte[RuntimeRealityClientHelloProtector.EncryptedSessionIdLength]);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(rewritten, out var rewrittenHello, out error), error);
        Assert.NotNull(rewrittenHello);
        Assert.Equal(clientPublicKey, rewrittenHello!.X25519PublicKey);
    }

    [Fact]
    public void CreateHelloRetryRequestResponse_accepts_x25519mlkem768_key_share()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x1A);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
            sessionId: Enumerable.Range(32, RuntimeRealityClientHelloProtector.EncryptedSessionIdLength).Select(static value => (byte)value).ToArray(),
            clientPublicKey);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);

        using var mlKem768KeyPair = RuntimeX25519MlKem768.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519MlKem768.BuildClientKeyShare(
            clientPublicKey,
            mlKem768KeyPair.PublicKey);
        var retryClientHello = hello!.CreateHelloRetryRequestResponse(
            hello.SessionId,
            RuntimeTlsNamedGroups.X25519MLKem768,
            hybridKeyShare,
            BuildCookieExtensionPayload([0xAA, 0xBB, 0xCC]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(retryClientHello, out var retryHello, out error), error);
        Assert.NotNull(retryHello);
        Assert.Equal(clientPublicKey, retryHello!.X25519PublicKey);

        var keyShareExtension = retryHello.Extensions.Single(static extension => extension.Type == 0x0033);
        Assert.Equal(RuntimeTlsNamedGroups.X25519MLKem768, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(2, 2)));
        Assert.Equal(RuntimeX25519MlKem768.ClientKeyShareLength, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(4, 2)));
    }

    [Fact]
    public void CreateHelloRetryRequestResponse_accepts_x25519kyber768draft00_key_share()
    {
        if (!RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x1E);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
            sessionId: Enumerable.Range(32, RuntimeRealityClientHelloProtector.EncryptedSessionIdLength).Select(static value => (byte)value).ToArray(),
            clientPublicKey);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);

        using var mlKem768KeyPair = RuntimeX25519Kyber768Draft00.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
            clientPublicKey,
            mlKem768KeyPair.PublicKey);
        var retryClientHello = hello!.CreateHelloRetryRequestResponse(
            hello.SessionId,
            RuntimeTlsNamedGroups.X25519Kyber768Draft00,
            hybridKeyShare,
            BuildCookieExtensionPayload([0xAA, 0xBB, 0xCC]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(retryClientHello, out var retryHello, out error), error);
        Assert.NotNull(retryHello);
        Assert.Equal(clientPublicKey, retryHello!.X25519PublicKey);

        var keyShareExtension = retryHello.Extensions.Single(static extension => extension.Type == 0x0033);
        Assert.Equal(RuntimeTlsNamedGroups.X25519Kyber768Draft00, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(2, 2)));
        Assert.Equal(RuntimeX25519Kyber768Draft00.ClientKeyShareLength, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(4, 2)));
    }

    [Fact]
    public void CreateHelloRetryRequestResponse_accepts_secp256r1mlkem768_key_share()
    {
        if (!RuntimeSecp256r1MlKem768.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x1B);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
            sessionId: Enumerable.Range(32, RuntimeRealityClientHelloProtector.EncryptedSessionIdLength).Select(static value => (byte)value).ToArray(),
            clientPublicKey);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);

        using var secp256r1KeyPair = RuntimeSecp256r1.CreateKeyPair();
        using var mlKem768KeyPair = RuntimeSecp256r1MlKem768.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeSecp256r1MlKem768.BuildClientKeyShare(
            secp256r1KeyPair.PublicKey,
            mlKem768KeyPair.PublicKey);
        var retryClientHello = hello!.CreateHelloRetryRequestResponse(
            hello.SessionId,
            RuntimeTlsNamedGroups.Secp256r1MLKem768,
            hybridKeyShare,
            BuildCookieExtensionPayload([0xAA, 0xBB, 0xCC]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(retryClientHello, out var retryHello, out error), error);
        Assert.NotNull(retryHello);
        Assert.Null(retryHello!.X25519PublicKey);

        var keyShareExtension = retryHello.Extensions.Single(static extension => extension.Type == 0x0033);
        Assert.Equal(RuntimeTlsNamedGroups.Secp256r1MLKem768, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(2, 2)));
        Assert.Equal(RuntimeSecp256r1MlKem768.ClientKeyShareLength, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(4, 2)));
    }

    [Fact]
    public void CreateHelloRetryRequestResponse_accepts_secp384r1mlkem1024_key_share()
    {
        if (!RuntimeSecp384r1MlKem1024.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x1C);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray(),
            sessionId: Enumerable.Range(32, RuntimeRealityClientHelloProtector.EncryptedSessionIdLength).Select(static value => (byte)value).ToArray(),
            clientPublicKey);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(payload, out var hello, out var error), error);
        Assert.NotNull(hello);

        using var secp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        using var mlKem1024KeyPair = RuntimeSecp384r1MlKem1024.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeSecp384r1MlKem1024.BuildClientKeyShare(
            secp384r1KeyPair.PublicKey,
            mlKem1024KeyPair.PublicKey);
        var retryClientHello = hello!.CreateHelloRetryRequestResponse(
            hello.SessionId,
            RuntimeTlsNamedGroups.Secp384r1MLKem1024,
            hybridKeyShare,
            BuildCookieExtensionPayload([0xAA, 0xBB, 0xCC]));

        Assert.True(RuntimeRealityClientHelloDocument.TryParse(retryClientHello, out var retryHello, out error), error);
        Assert.NotNull(retryHello);
        Assert.Null(retryHello!.X25519PublicKey);

        var keyShareExtension = retryHello.Extensions.Single(static extension => extension.Type == 0x0033);
        Assert.Equal(RuntimeTlsNamedGroups.Secp384r1MLKem1024, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(2, 2)));
        Assert.Equal(RuntimeSecp384r1MlKem1024.ClientKeyShareLength, BinaryPrimitives.ReadUInt16BigEndian(keyShareExtension.Payload.AsSpan(4, 2)));
    }

    [Fact]
    public void TryProtect_accepts_client_hello_with_x25519mlkem768_key_share()
    {
        if (!RuntimeX25519MlKem768.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x21);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        using var mlKem768KeyPair = RuntimeX25519MlKem768.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519MlKem768.BuildClientKeyShare(
            clientPublicKey,
            mlKem768KeyPair.PublicKey);
        var serverPrivateKey = CreateFixedKey(0x41);
        var serverPublicKey = RuntimeX25519.DerivePublicKey(serverPrivateKey);
        var random = Enumerable.Range(0, 32).Select(static value => (byte)(0x80 + value)).ToArray();
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            random,
            sessionId: [],
            clientPublicKey,
            keyShares:
            [
                new KeyShareDefinition(RuntimeTlsNamedGroups.X25519MLKem768, hybridKeyShare)
            ],
            supportedGroups:
            [
                RuntimeTlsNamedGroups.X25519MLKem768,
                RuntimeTlsNamedGroups.X25519,
                RuntimeTlsNamedGroups.Secp256r1
            ]);
        var options = new RuntimeRealityOptions
        {
            Fingerprint = "hellochrome_131",
            PublicKey = EncodeBase64Url(serverPublicKey),
            ShortId = "a1b2c3d4"
        };

        var protectedResult = RuntimeRealityClientHelloProtector.TryProtect(
            payload,
            clientPrivateKey,
            options,
            DateTimeOffset.FromUnixTimeSeconds(1_710_500_000),
            out var result,
            out var error);

        Assert.True(protectedResult, error);
        Assert.NotNull(result);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(result!.ProtectedClientHello, out var protectedHello, out error), error);
        Assert.NotNull(protectedHello);
        Assert.Equal(clientPublicKey, protectedHello!.X25519PublicKey);
    }

    [Fact]
    public void TryProtect_accepts_client_hello_with_x25519kyber768draft00_key_share()
    {
        if (!RuntimeX25519Kyber768Draft00.IsSupported)
        {
            return;
        }

        var clientPrivateKey = CreateFixedKey(0x22);
        var clientPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        using var mlKem768KeyPair = RuntimeX25519Kyber768Draft00.CreateMlKemKeyPair();
        var hybridKeyShare = RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
            clientPublicKey,
            mlKem768KeyPair.PublicKey);
        var serverPrivateKey = CreateFixedKey(0x42);
        var serverPublicKey = RuntimeX25519.DerivePublicKey(serverPrivateKey);
        var random = Enumerable.Range(0, 32).Select(static value => (byte)(0x70 + value)).ToArray();
        var payload = BuildTls13ClientHello(
            "edge.example.com",
            ["h2"],
            random,
            sessionId: [],
            clientPublicKey,
            keyShares:
            [
                new KeyShareDefinition(RuntimeTlsNamedGroups.X25519Kyber768Draft00, hybridKeyShare)
            ],
            supportedGroups:
            [
                RuntimeTlsNamedGroups.X25519Kyber768Draft00,
                RuntimeTlsNamedGroups.X25519,
                RuntimeTlsNamedGroups.Secp256r1
            ]);
        var options = new RuntimeRealityOptions
        {
            Fingerprint = "hellochrome_120_pq",
            PublicKey = EncodeBase64Url(serverPublicKey),
            ShortId = "a1b2c3d4"
        };

        var protectedResult = RuntimeRealityClientHelloProtector.TryProtect(
            payload,
            clientPrivateKey,
            options,
            DateTimeOffset.FromUnixTimeSeconds(1_710_500_100),
            out var result,
            out var error);

        Assert.True(protectedResult, error);
        Assert.NotNull(result);
        Assert.True(RuntimeRealityClientHelloDocument.TryParse(result!.ProtectedClientHello, out var protectedHello, out error), error);
        Assert.NotNull(protectedHello);
        Assert.Equal(clientPublicKey, protectedHello!.X25519PublicKey);
    }

    private static byte[] BuildTls13ClientHello(
        string host,
        IReadOnlyList<string> applicationProtocols,
        byte[] random,
        byte[] sessionId,
        byte[] clientPublicKey,
        bool includeSupportedVersions = true,
        bool includeKeyShare = true,
        IReadOnlyList<KeyShareDefinition>? keyShares = null,
        IReadOnlyList<ushort>? supportedGroups = null)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        var cipherSuites = new ushort[] { 0x1301, 0x1302, 0x1303 };
        var signatureAlgorithms = new ushort[] { 0x0403, 0x0804, 0x0805, 0x0806, 0x0807 };
        var effectiveSupportedGroups = supportedGroups ?? [0x001D, 0x0017];
        var effectiveKeyShares = keyShares ?? [new KeyShareDefinition(RuntimeTlsNamedGroups.X25519, clientPublicKey)];

        using var handshakeBody = new MemoryStream();
        WriteUInt16(handshakeBody, 0x0303);
        handshakeBody.Write(random);
        handshakeBody.WriteByte(checked((byte)sessionId.Length));
        if (sessionId.Length > 0)
        {
            handshakeBody.Write(sessionId);
        }

        WriteUInt16(handshakeBody, checked((ushort)(cipherSuites.Length * 2)));
        foreach (var cipherSuite in cipherSuites)
        {
            WriteUInt16(handshakeBody, cipherSuite);
        }

        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x00);

        using var extensions = new MemoryStream();
        WriteExtension(extensions, 0x0000, extension =>
        {
            WriteUInt16(extension, checked((ushort)(hostBytes.Length + 3)));
            extension.WriteByte(0x00);
            WriteUInt16(extension, checked((ushort)hostBytes.Length));
            extension.Write(hostBytes);
        });
        WriteExtension(extensions, 0x0010, extension =>
        {
            using var protocols = new MemoryStream();
            foreach (var applicationProtocol in applicationProtocols)
            {
                var protocolBytes = Encoding.ASCII.GetBytes(applicationProtocol);
                protocols.WriteByte(checked((byte)protocolBytes.Length));
                protocols.Write(protocolBytes);
            }

            var protocolList = protocols.ToArray();
            WriteUInt16(extension, checked((ushort)protocolList.Length));
            extension.Write(protocolList);
        });
        WriteExtension(extensions, 0x000A, extension =>
        {
            WriteUInt16(extension, checked((ushort)(effectiveSupportedGroups.Count * 2)));
            foreach (var supportedGroup in effectiveSupportedGroups)
            {
                WriteUInt16(extension, supportedGroup);
            }
        });
        WriteExtension(extensions, 0x000B, extension =>
        {
            extension.WriteByte(0x01);
            extension.WriteByte(0x00);
        });
        WriteExtension(extensions, 0x000D, extension =>
        {
            WriteUInt16(extension, checked((ushort)(signatureAlgorithms.Length * 2)));
            foreach (var signatureAlgorithm in signatureAlgorithms)
            {
                WriteUInt16(extension, signatureAlgorithm);
            }
        });
        WriteExtension(extensions, 0x002D, extension =>
        {
            extension.WriteByte(0x01);
            extension.WriteByte(0x01);
        });
        if (includeSupportedVersions)
        {
            WriteExtension(extensions, 0x002B, extension =>
            {
                extension.WriteByte(0x02);
                WriteUInt16(extension, 0x0304);
            });
        }

        if (includeKeyShare)
        {
            WriteExtension(extensions, 0x0033, extension =>
            {
                var keySharesLength = 0;
                foreach (var keyShare in effectiveKeyShares)
                {
                    keySharesLength += 4 + keyShare.KeyExchange.Length;
                }

                WriteUInt16(extension, checked((ushort)keySharesLength));
                foreach (var keyShare in effectiveKeyShares)
                {
                    WriteUInt16(extension, keyShare.Group);
                    WriteUInt16(extension, checked((ushort)keyShare.KeyExchange.Length));
                    extension.Write(keyShare.KeyExchange);
                }
            });
        }

        var extensionBytes = extensions.ToArray();
        WriteUInt16(handshakeBody, checked((ushort)extensionBytes.Length));
        handshakeBody.Write(extensionBytes);

        var handshakeBytes = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        record.WriteByte(0x03);
        record.WriteByte(0x01);
        WriteUInt16(record, checked((ushort)(handshakeBytes.Length + 4)));
        record.WriteByte(0x01);
        record.WriteByte((byte)((handshakeBytes.Length >> 16) & 0xFF));
        record.WriteByte((byte)((handshakeBytes.Length >> 8) & 0xFF));
        record.WriteByte((byte)(handshakeBytes.Length & 0xFF));
        record.Write(handshakeBytes);
        return record.ToArray();
    }

    private static byte[] CreateFixedKey(byte seed)
        => Enumerable.Range(0, RuntimeX25519.KeyLength)
            .Select(index => unchecked((byte)(seed + index)))
            .ToArray();

    private static string EncodeBase64Url(ReadOnlySpan<byte> value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] BuildCookieExtensionPayload(ReadOnlySpan<byte> cookie)
    {
        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)cookie.Length));
        payload.Write(cookie);
        return payload.ToArray();
    }

    private static void WriteExtension(MemoryStream destination, ushort extensionType, Action<MemoryStream> writer)
    {
        using var payload = new MemoryStream();
        writer(payload);
        var payloadBytes = payload.ToArray();

        WriteUInt16(destination, extensionType);
        WriteUInt16(destination, checked((ushort)payloadBytes.Length));
        destination.Write(payloadBytes);
    }

    private static void WriteUInt16(Stream destination, ushort value)
    {
        destination.WriteByte((byte)(value >> 8));
        destination.WriteByte((byte)value);
    }

    private sealed record KeyShareDefinition(ushort Group, byte[] KeyExchange);
}

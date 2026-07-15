using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal static class RuntimeRealityProtocolVersion
{
    public const byte Major = 1;
    public const byte Minor = 8;
    public const byte Patch = 1;
}

internal sealed record RuntimeRealityClientHelloExtension(
    ushort Type,
    byte[] Payload);

internal sealed class RuntimeRealityClientHelloDocument
{
    private const ushort CookieExtensionType = 0x002C;
    private const ushort SupportedGroupsExtensionType = 0x000A;
    private const ushort SupportedVersionsExtensionType = 0x002B;
    private const ushort KeyShareExtensionType = 0x0033;
    private const ushort Tls13Version = 0x0304;
    private const ushort X25519Group = 0x001D;
    private const ushort X25519MlKem768Group = RuntimeTlsNamedGroups.X25519MLKem768;

    private RuntimeRealityClientHelloDocument(
        ushort recordVersion,
        ushort legacyVersion,
        byte[] random,
        byte[] sessionId,
        byte[] originalRecord,
        int sessionIdOffset,
        byte[] cipherSuites,
        byte[] compressionMethods,
        IReadOnlyList<RuntimeRealityClientHelloExtension> extensions,
        IReadOnlyList<ushort> supportedGroups,
        IReadOnlyList<ushort> supportedVersions,
        byte[]? x25519PublicKey)
    {
        RecordVersion = recordVersion;
        LegacyVersion = legacyVersion;
        Random = random;
        SessionId = sessionId;
        OriginalRecord = originalRecord;
        SessionIdOffset = sessionIdOffset;
        CipherSuites = cipherSuites;
        CompressionMethods = compressionMethods;
        Extensions = extensions;
        SupportedGroups = supportedGroups;
        SupportedVersions = supportedVersions;
        X25519PublicKey = x25519PublicKey;
    }

    public ushort RecordVersion { get; }

    public ushort LegacyVersion { get; }

    public byte[] Random { get; }

    public byte[] SessionId { get; }

    public byte[] OriginalRecord { get; }

    public int SessionIdOffset { get; }

    public byte[] CipherSuites { get; }

    public byte[] CompressionMethods { get; }

    public IReadOnlyList<RuntimeRealityClientHelloExtension> Extensions { get; }

    public IReadOnlyList<ushort> SupportedGroups { get; }

    public IReadOnlyList<ushort> SupportedVersions { get; }

    public byte[]? X25519PublicKey { get; }

    public bool SupportsTls13
        => SupportedVersions.Contains(Tls13Version);

    public byte[] Write(ReadOnlySpan<byte> sessionId)
        => Write(sessionId, Extensions);

    public byte[] Write(
        ReadOnlySpan<byte> sessionId,
        IReadOnlyList<RuntimeRealityClientHelloExtension> extensions)
    {
        if (sessionId.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(sessionId), "The TLS session ID must be 255 bytes or fewer.");
        }

        if (ReferenceEquals(extensions, Extensions) &&
            OriginalRecord.Length > 0 &&
            sessionId.Length == SessionId.Length)
        {
            var rewritten = OriginalRecord.ToArray();
            if (sessionId.Length > 0)
            {
                sessionId.CopyTo(rewritten.AsSpan(SessionIdOffset, sessionId.Length));
            }

            return rewritten;
        }

        using var extensionBuffer = new MemoryStream();
        foreach (var extension in extensions)
        {
            WriteUInt16(extensionBuffer, extension.Type);
            WriteUInt16(extensionBuffer, checked((ushort)extension.Payload.Length));
            extensionBuffer.Write(extension.Payload);
        }

        var extensionBytes = extensionBuffer.ToArray();
        using var handshakeBody = new MemoryStream();
        WriteUInt16(handshakeBody, LegacyVersion);
        handshakeBody.Write(Random);
        handshakeBody.WriteByte(checked((byte)sessionId.Length));
        if (sessionId.Length > 0)
        {
            handshakeBody.Write(sessionId);
        }

        WriteUInt16(handshakeBody, checked((ushort)CipherSuites.Length));
        handshakeBody.Write(CipherSuites);
        handshakeBody.WriteByte(checked((byte)CompressionMethods.Length));
        handshakeBody.Write(CompressionMethods);
        WriteUInt16(handshakeBody, checked((ushort)extensionBytes.Length));
        handshakeBody.Write(extensionBytes);

        var handshakeBytes = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        WriteUInt16(record, RecordVersion);
        WriteUInt16(record, checked((ushort)(handshakeBytes.Length + 4)));
        record.WriteByte(0x01);
        record.WriteByte((byte)((handshakeBytes.Length >> 16) & 0xFF));
        record.WriteByte((byte)((handshakeBytes.Length >> 8) & 0xFF));
        record.WriteByte((byte)(handshakeBytes.Length & 0xFF));
        record.Write(handshakeBytes);
        return record.ToArray();
    }

    public byte[] CreateHelloRetryRequestResponse(
        ReadOnlySpan<byte> sessionId,
        ushort selectedGroup,
        ReadOnlySpan<byte> keyShare,
        ReadOnlySpan<byte> cookieExtensionPayload)
    {
        var rewrittenExtensions = new List<RuntimeRealityClientHelloExtension>(Extensions.Count + 1);
        var cookieAdded = false;
        var keyShareRewritten = false;

        foreach (var extension in Extensions)
        {
            if (extension.Type == CookieExtensionType)
            {
                if (cookieExtensionPayload.Length > 0)
                {
                    rewrittenExtensions.Add(new RuntimeRealityClientHelloExtension(
                        CookieExtensionType,
                        cookieExtensionPayload.ToArray()));
                    cookieAdded = true;
                }
                else
                {
                    rewrittenExtensions.Add(extension);
                }

                continue;
            }

            if (extension.Type == KeyShareExtensionType)
            {
                if (!cookieAdded && cookieExtensionPayload.Length > 0)
                {
                    rewrittenExtensions.Add(new RuntimeRealityClientHelloExtension(
                        CookieExtensionType,
                        cookieExtensionPayload.ToArray()));
                    cookieAdded = true;
                }

                if (selectedGroup == 0)
                {
                    rewrittenExtensions.Add(extension);
                }
                else
                {
                    rewrittenExtensions.Add(new RuntimeRealityClientHelloExtension(
                        KeyShareExtensionType,
                        BuildClientKeyShareExtensionPayload(selectedGroup, keyShare)));
                    keyShareRewritten = true;
                }

                continue;
            }

            rewrittenExtensions.Add(extension);
        }

        if (!cookieAdded && cookieExtensionPayload.Length > 0)
        {
            rewrittenExtensions.Add(new RuntimeRealityClientHelloExtension(
                CookieExtensionType,
                cookieExtensionPayload.ToArray()));
        }

        if (!keyShareRewritten && selectedGroup != 0)
        {
            rewrittenExtensions.Add(new RuntimeRealityClientHelloExtension(
                KeyShareExtensionType,
                BuildClientKeyShareExtensionPayload(selectedGroup, keyShare)));
        }

        return Write(sessionId, rewrittenExtensions);
    }

    public static bool TryParse(
        ReadOnlySpan<byte> payload,
        out RuntimeRealityClientHelloDocument? document,
        out string? error)
    {
        document = null;
        if (payload.Length < 9)
        {
            error = "REALITY client hello payload is incomplete.";
            return false;
        }

        if (payload[0] != 0x16 || payload[5] != 0x01)
        {
            error = "REALITY requires a TLS ClientHello record.";
            return false;
        }

        var recordVersion = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(1, 2));
        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        var availableLength = Math.Min(payload.Length, recordLength + 5);
        var handshakeLength =
            (payload[6] << 16) |
            (payload[7] << 8) |
            payload[8];
        var handshakeEnd = Math.Min(availableLength, 9 + handshakeLength);
        if (handshakeEnd < 44)
        {
            error = "REALITY client hello handshake payload is incomplete.";
            return false;
        }

        var position = 9;
        var legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;

        var random = payload.Slice(position, 32).ToArray();
        position += 32;

        var sessionIdLength = payload[position];
        position++;
        if (position + sessionIdLength > handshakeEnd)
        {
            error = "REALITY client hello session ID is truncated.";
            return false;
        }

        var sessionIdOffset = position;
        var sessionId = payload.Slice(position, sessionIdLength).ToArray();
        position += sessionIdLength;

        if (position + 2 > handshakeEnd)
        {
            error = "REALITY client hello cipher suites are missing.";
            return false;
        }

        var cipherSuitesLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;
        if (position + cipherSuitesLength > handshakeEnd || (cipherSuitesLength & 1) != 0)
        {
            error = "REALITY client hello cipher suites are invalid.";
            return false;
        }

        var cipherSuites = payload.Slice(position, cipherSuitesLength).ToArray();
        position += cipherSuitesLength;

        if (position >= handshakeEnd)
        {
            error = "REALITY client hello compression methods are missing.";
            return false;
        }

        var compressionMethodsLength = payload[position];
        position++;
        if (position + compressionMethodsLength > handshakeEnd)
        {
            error = "REALITY client hello compression methods are invalid.";
            return false;
        }

        var compressionMethods = payload.Slice(position, compressionMethodsLength).ToArray();
        position += compressionMethodsLength;

        if (position + 2 > handshakeEnd)
        {
            error = "REALITY client hello extensions are missing.";
            return false;
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;
        if (position + extensionsLength > handshakeEnd)
        {
            error = "REALITY client hello extensions are truncated.";
            return false;
        }

        var extensionsEnd = position + extensionsLength;
        var extensions = new List<RuntimeRealityClientHelloExtension>();
        List<ushort>? supportedGroups = null;
        List<ushort>? supportedVersions = null;
        byte[]? x25519PublicKey = null;

        while (position + 4 <= extensionsEnd)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
            var extensionPayloadLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position + 2, 2));
            position += 4;
            if (position + extensionPayloadLength > extensionsEnd)
            {
                error = "REALITY client hello extension payload is truncated.";
                return false;
            }

            var extensionPayload = payload.Slice(position, extensionPayloadLength).ToArray();
            extensions.Add(new RuntimeRealityClientHelloExtension(extensionType, extensionPayload));

            if (extensionType == SupportedGroupsExtensionType)
            {
                supportedGroups = ParseSupportedGroups(extensionPayload);
            }
            else if (extensionType == SupportedVersionsExtensionType)
            {
                supportedVersions = ParseSupportedVersions(extensionPayload);
            }
            else if (extensionType == KeyShareExtensionType)
            {
                x25519PublicKey = ParseX25519PublicKey(extensionPayload);
            }

            position += extensionPayloadLength;
        }

        if (position != extensionsEnd)
        {
            error = "REALITY client hello extensions contain trailing bytes.";
            return false;
        }

        document = new RuntimeRealityClientHelloDocument(
            recordVersion,
            legacyVersion,
            random,
            sessionId,
            payload.Slice(0, availableLength).ToArray(),
            sessionIdOffset,
            cipherSuites,
            compressionMethods,
            extensions,
            supportedGroups ?? (IReadOnlyList<ushort>)Array.Empty<ushort>(),
            supportedVersions ?? (IReadOnlyList<ushort>)Array.Empty<ushort>(),
            x25519PublicKey);
        error = null;
        return true;
    }

    private static List<ushort> ParseSupportedGroups(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return [];
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var end = Math.Min(payload.Length, 2 + listLength);
        var groups = new List<ushort>((end - 2) / 2);
        for (var position = 2; position + 1 < end; position += 2)
        {
            groups.Add(BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2)));
        }

        return groups;
    }

    private static List<ushort> ParseSupportedVersions(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0)
        {
            return [];
        }

        var listLength = Math.Min(payload[0], payload.Length - 1);
        var versions = new List<ushort>(listLength / 2);
        for (var offset = 0; offset + 1 < listLength; offset += 2)
        {
            versions.Add(BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(1 + offset, 2)));
        }

        return versions;
    }

    private static byte[]? ParseX25519PublicKey(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            return null;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(payload[..2]);
        var position = 2;
        var listEnd = Math.Min(payload.Length, position + listLength);
        byte[]? hybridFallbackX25519PublicKey = null;
        while (position + 4 <= listEnd)
        {
            var group = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
            var keyExchangeLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position + 2, 2));
            position += 4;
            if (position + keyExchangeLength > listEnd)
            {
                return null;
            }

            if (group == X25519Group && keyExchangeLength == RuntimeX25519.KeyLength)
            {
                return payload.Slice(position, keyExchangeLength).ToArray();
            }

            if (group == RuntimeTlsNamedGroups.X25519Kyber768Draft00 &&
                RuntimeX25519Kyber768Draft00.TryExtractClientX25519PublicKey(
                    payload.Slice(position, keyExchangeLength),
                    out var x25519KyberPublicKey))
            {
                hybridFallbackX25519PublicKey ??= x25519KyberPublicKey;
            }

            if (group == X25519MlKem768Group &&
                RuntimeX25519MlKem768.TryExtractClientX25519PublicKey(
                    payload.Slice(position, keyExchangeLength),
                    out var x25519PublicKey))
            {
                hybridFallbackX25519PublicKey ??= x25519PublicKey;
            }

            position += keyExchangeLength;
        }

        return hybridFallbackX25519PublicKey;
    }

    private static byte[] BuildClientKeyShareExtensionPayload(
        ushort selectedGroup,
        ReadOnlySpan<byte> keyShare)
    {
        if (selectedGroup == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(selectedGroup), "The TLS named group cannot be zero.");
        }

        if (!IsValidKeyShare(selectedGroup, keyShare))
        {
            throw new ArgumentOutOfRangeException(
                nameof(keyShare),
                $"The TLS key share for group 0x{selectedGroup:X4} is invalid.");
        }

        using var payload = new MemoryStream();
        WriteUInt16(payload, checked((ushort)(4 + keyShare.Length)));
        WriteUInt16(payload, selectedGroup);
        WriteUInt16(payload, checked((ushort)keyShare.Length));
        payload.Write(keyShare);
        return payload.ToArray();
    }

    private static bool IsValidKeyShare(ushort selectedGroup, ReadOnlySpan<byte> keyShare)
        => selectedGroup switch
        {
            RuntimeTlsNamedGroups.X25519 => keyShare.Length == RuntimeX25519.KeyLength,
            RuntimeTlsNamedGroups.X25519Kyber768Draft00 => keyShare.Length == RuntimeX25519Kyber768Draft00.ClientKeyShareLength,
            RuntimeTlsNamedGroups.X25519MLKem768 => keyShare.Length == RuntimeX25519MlKem768.ClientKeyShareLength,
            RuntimeTlsNamedGroups.Secp256r1MLKem768 => keyShare.Length == RuntimeSecp256r1MlKem768.ClientKeyShareLength,
            RuntimeTlsNamedGroups.Secp256r1 => keyShare.Length == RuntimeSecp256r1.PublicKeyLength && keyShare[0] == 0x04,
            RuntimeTlsNamedGroups.Secp384r1MLKem1024 => keyShare.Length == RuntimeSecp384r1MlKem1024.ClientKeyShareLength,
            RuntimeTlsNamedGroups.Secp384r1 => keyShare.Length == RuntimeSecp384r1.PublicKeyLength && keyShare[0] == 0x04,
            RuntimeTlsNamedGroups.Secp521r1 => keyShare.Length == RuntimeSecp521r1.PublicKeyLength && keyShare[0] == 0x04,
            _ => false
        };

    private static void WriteUInt16(Stream stream, ushort value)
    {
        stream.WriteByte((byte)(value >> 8));
        stream.WriteByte((byte)value);
    }
}

internal sealed record RuntimeRealityClientHelloProtectionResult(
    RuntimeRealityOptions Options,
    byte[] ZeroSessionIdClientHello,
    byte[] ProtectedClientHello,
    byte[] PlainSessionId,
    byte[] EncryptedSessionId,
    byte[] AuthKey);

internal static class RuntimeRealityClientHelloProtector
{
    public const int PlainSessionIdLength = 16;
    public const int EncryptedSessionIdLength = 32;
    private const int ShortIdLength = 8;

    public static bool TryProtect(
        ReadOnlySpan<byte> clientHello,
        ReadOnlySpan<byte> clientPrivateKey,
        RuntimeRealityOptions options,
        DateTimeOffset utcNow,
        out RuntimeRealityClientHelloProtectionResult? result,
        out string? error)
    {
        if (!RuntimeRealityOptions.Normalize(options, applyRealityDefaults: true)
                .TryValidateForReality(out var normalizedOptions, out error))
        {
            result = null;
            return false;
        }

        if (!RuntimeRealityClientHelloDocument.TryParse(clientHello, out var hello, out error) || hello is null)
        {
            result = null;
            return false;
        }

        if (!hello.SupportsTls13)
        {
            result = null;
            error = "REALITY client hello must advertise TLS 1.3 support.";
            return false;
        }

        if (hello.X25519PublicKey is null)
        {
            result = null;
            error = "REALITY client hello must include an X25519 key share.";
            return false;
        }

        byte[] localPublicKey;
        try
        {
            localPublicKey = RuntimeX25519.DerivePublicKey(clientPrivateKey);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            result = null;
            error = ex.Message;
            return false;
        }

        if (!CryptographicOperations.FixedTimeEquals(localPublicKey, hello.X25519PublicKey))
        {
            result = null;
            error = "REALITY client private key does not match the X25519 key share in ClientHello.";
            return false;
        }

        if (!RuntimeRealityOptions.TryDecodeBase64Url(normalizedOptions.PublicKey, out var serverPublicKey) ||
            serverPublicKey.Length != RuntimeX25519.KeyLength)
        {
            result = null;
            error = "REALITY public key is invalid.";
            return false;
        }

        var zeroSessionIdClientHello = hello.Write(new byte[EncryptedSessionIdLength]);
        var sharedSecret = RuntimeX25519.DeriveSharedSecret(clientPrivateKey, serverPublicKey);
        var authKey = RuntimeHkdf.ExtractAndExpandSha256(
            sharedSecret,
            hello.Random.AsSpan(0, 20),
            "REALITY"u8,
            RuntimeX25519.KeyLength);
        var plainSessionId = BuildPlainSessionId(normalizedOptions.ShortId, utcNow);
        var encryptedSessionId = EncryptSessionId(
            authKey,
            hello.Random.AsSpan(20, 12),
            plainSessionId,
            zeroSessionIdClientHello.AsSpan(5));
        var protectedClientHello = hello.Write(encryptedSessionId);

        result = new RuntimeRealityClientHelloProtectionResult(
            normalizedOptions,
            zeroSessionIdClientHello,
            protectedClientHello,
            plainSessionId,
            encryptedSessionId,
            authKey);
        error = null;
        return true;
    }

    private static byte[] BuildPlainSessionId(string shortIdHex, DateTimeOffset utcNow)
    {
        var plainSessionId = new byte[PlainSessionIdLength];
        plainSessionId[0] = RuntimeRealityProtocolVersion.Major;
        plainSessionId[1] = RuntimeRealityProtocolVersion.Minor;
        plainSessionId[2] = RuntimeRealityProtocolVersion.Patch;
        plainSessionId[3] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(
            plainSessionId.AsSpan(4, 4),
            checked((uint)utcNow.ToUnixTimeSeconds()));

        if (shortIdHex.Length > 0 &&
            RuntimeRealityOptions.TryDecodeHex(shortIdHex, out var shortIdBytes))
        {
            shortIdBytes.AsSpan(0, Math.Min(shortIdBytes.Length, ShortIdLength)).CopyTo(plainSessionId.AsSpan(8, ShortIdLength));
        }

        return plainSessionId;
    }

    private static byte[] EncryptSessionId(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plainSessionId,
        ReadOnlySpan<byte> associatedData)
    {
        var ciphertext = new byte[PlainSessionIdLength];
        var tag = new byte[EncryptedSessionIdLength - PlainSessionIdLength];
        using var aead = new AesGcm(authKey.ToArray(), tag.Length);
        aead.Encrypt(nonce, plainSessionId, ciphertext, tag, associatedData);

        var encrypted = new byte[EncryptedSessionIdLength];
        ciphertext.CopyTo(encrypted, 0);
        tag.CopyTo(encrypted, ciphertext.Length);
        return encrypted;
    }
}

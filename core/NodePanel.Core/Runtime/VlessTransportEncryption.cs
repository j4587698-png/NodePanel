using System.Security.Cryptography;
using Blake3;

namespace NodePanel.Core.Runtime;

internal sealed class VlessTransportEncryption
{
    private static readonly byte[] MaxNonce = Enumerable.Repeat((byte)0xFF, 12).ToArray();
    private const string CtrDeriveKeyContext = "VLESS";
    private const int CipherChunkLength = 8192;
    private const int HeaderLength = 5;
    private const int TagLength = 16;
    private const int MaxCipherRecordLength = 16640;
    private const int MinCipherRecordLength = 17;
    private const int PfsCiphertextLength = 1088;
    private const int X25519KeyLength = 32;
    private const int TicketLength = 16;

    private readonly Dictionary<string, ResumeState> _resumeStates = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ServerState> _serverStates = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    public static bool IsEnabled(string? encryption)
        => !string.IsNullOrWhiteSpace(encryption);

    public async ValueTask ApplyAsync(
        VlessClientConnection connection,
        VlessClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(options);

        if (!IsEnabled(options.Encryption))
        {
            return;
        }

        var profile = Profile.Parse(options);
        var resumeState = GetOrCreateResumeState(profile.CreateResumeKey(options));
        var encryptedStream = await HandshakeAsync(
            connection.Stream,
            profile,
            resumeState,
            cancellationToken).ConfigureAwait(false);
        connection.UseApplicationStream(encryptedStream);
    }

    public async ValueTask<Stream> AcceptAsync(
        Stream stream,
        VlessInboundSessionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var cacheKey = ServerProfile.CreateCacheKey(options);
        if (cacheKey.Length == 0)
        {
            return stream;
        }

        var serverState = GetOrCreateServerState(cacheKey, static current => ServerProfile.Parse(current), options);
        return await HandshakeAsync(
            stream,
            serverState.Profile,
            serverState.ResumeState,
            cancellationToken).ConfigureAwait(false);
    }

    internal static string NormalizeEncryption(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return string.Join(
            ".",
            value.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(static segment => !string.IsNullOrWhiteSpace(segment)));
    }

    internal static string NormalizeDecryption(string? value)
    {
        var normalized = NormalizeEncryption(value);
        return string.Equals(normalized, "none", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : normalized;
    }

    internal static string NormalizePaddingValue(string? value)
        => value?.Trim() ?? string.Empty;

    internal static bool TryValidateConfiguration(
        string? encryption,
        string? padding,
        out string? error)
    {
        error = null;
        var normalizedEncryption = NormalizeEncryption(encryption);
        if (normalizedEncryption.Length == 0)
        {
            return true;
        }

        try
        {
            _ = ParsePublicKeys(normalizedEncryption);
            _ = ParsePadding(NormalizePadding(padding));
            return true;
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or NotSupportedException or PlatformNotSupportedException)
        {
            error = ex.Message;
            return false;
        }
    }

    internal static bool TryValidateServerConfiguration(
        string? decryption,
        string? padding,
        out string? error)
    {
        error = null;
        var normalizedDecryption = NormalizeDecryption(decryption);
        if (normalizedDecryption.Length == 0)
        {
            return true;
        }

        try
        {
            _ = ParsePrivateKeys(normalizedDecryption);
            _ = ParsePadding(NormalizePaddingValue(padding));
            return true;
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException or NotSupportedException or PlatformNotSupportedException or CryptographicException)
        {
            error = ex.Message;
            return false;
        }
    }

    private async ValueTask<Stream> HandshakeAsync(
        Stream stream,
        Profile profile,
        ResumeState resumeState,
        CancellationToken cancellationToken)
    {
        using var prepared = await PrepareHandshakeAsync(profile, resumeState, cancellationToken).ConfigureAwait(false);
        var transportStream = prepared.CreateTransportStream(stream);
        var iv = prepared.PreWrite.AsSpan(0, TicketLength).ToArray();

        if (prepared.Mode == HandshakeMode.ZeroRttResume)
        {
            var resumeWriteCipher = prepared.WriteCipher ?? throw new InvalidOperationException("VLESS encryption resume handshake did not create a write cipher.");
            prepared.WriteCipher = null;

            if (profile.XorMode == 2)
            {
                transportStream.ConfigureXor(
                    prepared.UnitedKey,
                    iv,
                    prepared.PreWrite.Length,
                    inboundSeed: null,
                    inboundSkip: TicketLength);
            }

            return new EncryptedStream(
                transportStream,
                prepared.UnitedKey,
                resumeWriteCipher,
                readCipher: null,
                preWrite: prepared.PreWrite,
                peerPaddingLength: 0,
                resumeState,
                canRetryResume: true);
        }

        await WriteFragmentedAsync(
            transportStream,
            prepared.PreWrite,
            prepared.PaddingLengths,
            prepared.PaddingGaps,
            cancellationToken).ConfigureAwait(false);

        var encryptedServerPfs = await ReadExactAsync(
            transportStream,
            PfsCiphertextLength + X25519KeyLength + TagLength,
            cancellationToken).ConfigureAwait(false);

        var pfsPlain = new byte[PfsCiphertextLength + X25519KeyLength];
        prepared.NfsCipher.Decrypt(
            encryptedServerPfs,
            ReadOnlySpan<byte>.Empty,
            pfsPlain,
            MaxNonce);

        var serverMlkemCiphertext = pfsPlain.AsSpan(0, PfsCiphertextLength).ToArray();
        var serverX25519Public = pfsPlain.AsSpan(PfsCiphertextLength, X25519KeyLength).ToArray();
        var mlkemSharedSecret = prepared.PfsMlkemKey!.Decapsulate(serverMlkemCiphertext);
        var x25519SharedSecret = DeriveX25519SharedSecret(prepared.PfsX25519Key!, serverX25519Public);
        var pfsKey = Combine(mlkemSharedSecret, x25519SharedSecret);
        var unitedKey = Combine(pfsKey, prepared.NfsKey);

        var writeCipher = RecordCipher.Create(prepared.PfsPublicKey, unitedKey, prepared.UseAes);
        var readCipher = RecordCipher.Create(pfsPlain, unitedKey, prepared.UseAes);

        var encryptedTicket = await ReadExactAsync(
            transportStream,
            TicketLength + TagLength,
            cancellationToken).ConfigureAwait(false);
        var ticket = new byte[TicketLength];
        readCipher.Decrypt(encryptedTicket, ReadOnlySpan<byte>.Empty, ticket);

        var encryptedPaddingLength = await ReadExactAsync(
            transportStream,
            2 + TagLength,
            cancellationToken).ConfigureAwait(false);
        var paddingLengthBytes = new byte[2];
        readCipher.Decrypt(encryptedPaddingLength, ReadOnlySpan<byte>.Empty, paddingLengthBytes);
        var peerPaddingLength = DecodeLength(paddingLengthBytes);

        resumeState.StoreTicket(profile.Seconds, pfsKey, ticket);

        if (profile.XorMode == 2)
        {
            transportStream.ConfigureXor(
                unitedKey,
                iv,
                outboundSkip: 0,
                ticket,
                peerPaddingLength);
        }

        return new EncryptedStream(
            transportStream,
            unitedKey,
            writeCipher,
            readCipher,
            preWrite: null,
            peerPaddingLength,
            resumeState,
            canRetryResume: false);
    }

    private async ValueTask<Stream> HandshakeAsync(
        Stream stream,
        ServerProfile profile,
        ServerResumeState resumeState,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(resumeState);

        var ivAndRelays = await ReadExactAsync(
            stream,
            TicketLength + profile.RelaysLength,
            cancellationToken).ConfigureAwait(false);
        var iv = ivAndRelays.AsSpan(0, TicketLength).ToArray();
        var relays = ivAndRelays.AsSpan(TicketLength).ToArray();
        byte[]? nfsKey = null;
        CtrTransform? lastRelayCtr = null;

        try
        {
            var cursor = 0;
            for (var index = 0; index < profile.PrivateKeys.Count; index++)
            {
                var key = profile.PrivateKeys[index];
                if (lastRelayCtr is not null)
                {
                    lastRelayCtr.Xor(relays.AsSpan(cursor, X25519KeyLength));
                    lastRelayCtr.Dispose();
                    lastRelayCtr = null;
                }

                var relayLength = key.Kind == PublicKeyKind.X25519
                    ? X25519KeyLength
                    : MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;
                var currentRelay = relays.AsSpan(cursor, relayLength);

                if (profile.XorMode > 0)
                {
                    using var ctr = CtrTransform.Create(key.PublicBytes, iv);
                    ctr.Xor(currentRelay);
                }

                if (key.Kind == PublicKeyKind.X25519)
                {
                    if ((currentRelay[^1] & 0x80) != 0)
                    {
                        throw new InvalidDataException("The peer-sent VLESS X25519 public key has an invalid high bit.");
                    }

                    nfsKey = DeriveX25519SharedSecret(key.RawBytes, currentRelay);
                }
                else
                {
                    using var kem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, key.RawBytes);
                    nfsKey = kem.Decapsulate(currentRelay.ToArray());
                }

                cursor += relayLength;
                if (index + 1 >= profile.PrivateKeys.Count)
                {
                    continue;
                }

                lastRelayCtr = CtrTransform.Create(nfsKey, iv);
                var nextHash = relays.AsSpan(cursor, X25519KeyLength);
                lastRelayCtr.Xor(nextHash);
                if (!nextHash.SequenceEqual(profile.PrivateKeys[index + 1].Hash32))
                {
                    throw new InvalidDataException($"Unexpected VLESS relay hash: {Convert.ToHexString(nextHash)}.");
                }

                cursor += X25519KeyLength;
            }
        }
        finally
        {
            lastRelayCtr?.Dispose();
        }

        if (nfsKey is null)
        {
            throw new InvalidOperationException("VLESS transport decryption handshake did not derive a non-forward-secret key.");
        }

        var useAes = PreferAesGcm();
        var transportStream = new TransportStream(stream, profile.XorMode == 2);
        RecordCipher? nfsCipher = null;
        try
        {
            nfsCipher = RecordCipher.Create(iv, nfsKey, useAes);
            var encryptedLength = await ReadExactAsync(transportStream, 2 + TagLength, cancellationToken).ConfigureAwait(false);
            var decryptedLength = new byte[2];
            try
            {
                nfsCipher.Decrypt(encryptedLength, ReadOnlySpan<byte>.Empty, decryptedLength);
            }
            catch (CryptographicException)
            {
                nfsCipher.Dispose();
                useAes = !useAes;
                nfsCipher = RecordCipher.Create(iv, nfsKey, useAes);
                nfsCipher.Decrypt(encryptedLength, ReadOnlySpan<byte>.Empty, decryptedLength);
            }

            var length = DecodeLength(decryptedLength);
            if (length == 32)
            {
                if (!profile.AllowsResume)
                {
                    throw new InvalidDataException("VLESS transport decryption 0-RTT is not allowed.");
                }

                var encryptedTicket = await ReadExactAsync(
                    transportStream,
                    TicketLength + TagLength,
                    cancellationToken).ConfigureAwait(false);
                var ticket = new byte[TicketLength];
                nfsCipher.Decrypt(encryptedTicket, ReadOnlySpan<byte>.Empty, ticket);

                var resumeLookup = resumeState.TryAcquire(ticket, nfsKey, out var pfsKey);
                if (resumeLookup == ServerResumeLookupResult.Missing)
                {
                    await WriteInvalidResumeNoiseAsync(transportStream, cancellationToken).ConfigureAwait(false);
                    throw new InvalidDataException("VLESS transport decryption ticket expired.");
                }

                if (resumeLookup == ServerResumeLookupResult.Replay)
                {
                    throw new InvalidDataException("VLESS transport decryption replay detected.");
                }

                var unitedKey = Combine(pfsKey, nfsKey);
                var serverRandom = RandomNumberGenerator.GetBytes(TicketLength);
                var writeCipher = RecordCipher.Create(serverRandom, unitedKey, useAes);
                var readCipher = RecordCipher.Create(encryptedTicket, unitedKey, useAes);

                if (profile.XorMode == 2)
                {
                    transportStream.ConfigureXor(
                        unitedKey,
                        serverRandom,
                        TicketLength,
                        iv,
                        inboundSkip: 0);
                }

                nfsCipher.Dispose();
                nfsCipher = null;
                return new EncryptedStream(
                    transportStream,
                    unitedKey,
                    writeCipher,
                    readCipher,
                    serverRandom,
                    peerPaddingLength: 0,
                    new ResumeState(),
                    canRetryResume: false);
            }

            var clientMlkemPublicLength = MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes;
            if (length < clientMlkemPublicLength + X25519KeyLength + TagLength)
            {
                throw new InvalidDataException("VLESS transport decryption handshake is too short.");
            }

            var encryptedClientPfs = await ReadExactAsync(transportStream, length, cancellationToken).ConfigureAwait(false);
            var clientPfsPublic = new byte[length - TagLength];
            nfsCipher.Decrypt(encryptedClientPfs, ReadOnlySpan<byte>.Empty, clientPfsPublic);

            using var clientMlkemKey = MLKem.ImportEncapsulationKey(
                MLKemAlgorithm.MLKem768,
                clientPfsPublic.AsSpan(0, clientMlkemPublicLength));
            clientMlkemKey.Encapsulate(out var serverMlkemCiphertext, out var serverMlkemSharedSecret);

            using var serverX25519 = CreateX25519KeyPair();
            var serverX25519SharedSecret = DeriveX25519SharedSecret(
                serverX25519.PrivateKey,
                clientPfsPublic.AsSpan(clientMlkemPublicLength, X25519KeyLength));
            var pfsKeyBytes = Combine(serverMlkemSharedSecret, serverX25519SharedSecret);
            var unitedKeyBytes = Combine(pfsKeyBytes, nfsKey);
            var serverPfsPublic = Combine(serverMlkemCiphertext, serverX25519.PublicKey);
            var writeCipherFull = RecordCipher.Create(serverPfsPublic, unitedKeyBytes, useAes);
            var readCipherFull = RecordCipher.Create(
                clientPfsPublic.AsSpan(0, clientMlkemPublicLength + X25519KeyLength),
                unitedKeyBytes,
                useAes);

            var ticketBytes = CreateServerTicket(profile, resumeState, pfsKeyBytes);
            var createdPadding = profile.Padding.Create();
            var serverHello = new byte[
                PfsCiphertextLength + X25519KeyLength + TagLength +
                TicketLength + TagLength +
                createdPadding.TotalLength];
            nfsCipher.Encrypt(
                serverPfsPublic,
                ReadOnlySpan<byte>.Empty,
                serverHello.AsSpan(0, PfsCiphertextLength + X25519KeyLength + TagLength),
                MaxNonce);
            writeCipherFull.Encrypt(
                ticketBytes,
                ReadOnlySpan<byte>.Empty,
                serverHello.AsSpan(PfsCiphertextLength + X25519KeyLength + TagLength, TicketLength + TagLength));

            if (createdPadding.TotalLength > 0)
            {
                var paddingOffset = PfsCiphertextLength + X25519KeyLength + TagLength + TicketLength + TagLength;
                writeCipherFull.Encrypt(
                    EncodeLength(Math.Max(0, createdPadding.TotalLength - 18)),
                    ReadOnlySpan<byte>.Empty,
                    serverHello.AsSpan(paddingOffset, 18));

                var payloadLength = Math.Max(0, createdPadding.TotalLength - 18 - TagLength);
                writeCipherFull.Encrypt(
                    new byte[payloadLength],
                    ReadOnlySpan<byte>.Empty,
                    serverHello.AsSpan(paddingOffset + 18));
            }

            if (createdPadding.FragmentLengths.Length > 0)
            {
                createdPadding.FragmentLengths[0] += PfsCiphertextLength + X25519KeyLength + TagLength + TicketLength + TagLength;
            }

            await WriteFragmentedAsync(
                transportStream,
                serverHello,
                createdPadding.FragmentLengths,
                createdPadding.FragmentGaps,
                cancellationToken).ConfigureAwait(false);

            var encryptedPaddingLength = await ReadExactAsync(transportStream, 2 + TagLength, cancellationToken).ConfigureAwait(false);
            nfsCipher.Decrypt(encryptedPaddingLength, ReadOnlySpan<byte>.Empty, decryptedLength);
            var clientPaddingLength = DecodeLength(decryptedLength);
            if (clientPaddingLength > 0)
            {
                var encryptedPadding = await ReadExactAsync(transportStream, clientPaddingLength, cancellationToken).ConfigureAwait(false);
                var paddingBytes = new byte[Math.Max(0, encryptedPadding.Length - TagLength)];
                nfsCipher.Decrypt(encryptedPadding, ReadOnlySpan<byte>.Empty, paddingBytes);
            }

            if (profile.XorMode == 2)
            {
                transportStream.ConfigureXor(
                    unitedKeyBytes,
                    ticketBytes,
                    outboundSkip: 0,
                    iv,
                    inboundSkip: 0);
            }

            nfsCipher.Dispose();
            nfsCipher = null;
            return new EncryptedStream(
                transportStream,
                unitedKeyBytes,
                writeCipherFull,
                readCipherFull,
                preWrite: null,
                peerPaddingLength: 0,
                new ResumeState(),
                canRetryResume: false);
        }
        catch
        {
            nfsCipher?.Dispose();
            transportStream.Dispose();
            throw;
        }
    }

    private ResumeState GetOrCreateResumeState(string key)
    {
        lock (_sync)
        {
            if (_resumeStates.TryGetValue(key, out var state))
            {
                return state;
            }

            state = new ResumeState();
            _resumeStates[key] = state;
            return state;
        }
    }

    private ServerState GetOrCreateServerState(
        string key,
        Func<VlessInboundSessionOptions, ServerProfile> factory,
        VlessInboundSessionOptions options)
    {
        lock (_sync)
        {
            if (_serverStates.TryGetValue(key, out var state))
            {
                return state;
            }

            state = new ServerState(factory(options), new ServerResumeState());
            _serverStates[key] = state;
            return state;
        }
    }

    private static string NormalizePadding(string? value)
        => NormalizePaddingValue(value);

    private static bool PreferAesGcm()
        => AesGcm.IsSupported &&
           ((System.Runtime.Intrinsics.X86.Aes.IsSupported &&
             System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
             System.Runtime.Intrinsics.X86.Sse41.IsSupported &&
             System.Runtime.Intrinsics.X86.Ssse3.IsSupported) ||
            System.Runtime.Intrinsics.Arm.Aes.IsSupported);

    private static IReadOnlyList<PublicKeyEntry> ParsePublicKeys(string encryption)
    {
        var normalized = NormalizeEncryption(encryption);
        if (normalized.Length == 0)
        {
            return Array.Empty<PublicKeyEntry>();
        }

        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException("The current platform does not support VLESS ML-KEM encryption.");
        }

        var algorithm = MLKemAlgorithm.MLKem768;
        var keys = new List<PublicKeyEntry>();
        foreach (var segment in normalized.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var raw = DecodeBase64Url(segment);
            if (raw.Length == X25519KeyLength)
            {
                keys.Add(new PublicKeyEntry(PublicKeyKind.X25519, raw, ComputeHash(raw)));
                continue;
            }

            if (raw.Length != algorithm.EncapsulationKeySizeInBytes)
            {
                throw new FormatException($"Unsupported VLESS encryption public key length: {raw.Length}.");
            }

            keys.Add(new PublicKeyEntry(PublicKeyKind.MLKem768, raw, ComputeHash(raw)));
        }

        if (keys.Count == 0)
        {
            throw new FormatException("VLESS encryption requires at least one public key.");
        }

        return keys;
    }

    private static IReadOnlyList<PrivateKeyEntry> ParsePrivateKeys(string decryption)
    {
        var normalized = NormalizeDecryption(decryption);
        if (normalized.Length == 0)
        {
            return Array.Empty<PrivateKeyEntry>();
        }

        var algorithm = MLKemAlgorithm.MLKem768;
        var keys = new List<PrivateKeyEntry>();
        foreach (var segment in normalized.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var raw = DecodeBase64Url(segment);
            if (raw.Length == X25519KeyLength)
            {
                var publicKey = RuntimeX25519.DerivePublicKey(raw);
                keys.Add(new PrivateKeyEntry(PublicKeyKind.X25519, raw, publicKey, ComputeHash(publicKey)));
                continue;
            }

            if (raw.Length != algorithm.DecapsulationKeySizeInBytes)
            {
                throw new FormatException($"Unsupported VLESS decryption private key length: {raw.Length}.");
            }

            if (!MLKem.IsSupported)
            {
                throw new PlatformNotSupportedException("The current platform does not support VLESS ML-KEM decryption.");
            }

            using var kem = MLKem.ImportDecapsulationKey(algorithm, raw);
            var publicKeyBytes = kem.ExportEncapsulationKey();
            keys.Add(new PrivateKeyEntry(PublicKeyKind.MLKem768, raw, publicKeyBytes, ComputeHash(publicKeyBytes)));
        }

        if (keys.Count == 0)
        {
            throw new FormatException("VLESS decryption requires at least one private key.");
        }

        return keys;
    }

    private static PaddingProfile ParsePadding(string padding)
    {
        if (padding.Length == 0)
        {
            return new PaddingProfile(Array.Empty<int[]>(), Array.Empty<int[]>());
        }

        var lengths = new List<int[]>();
        var gaps = new List<int[]>();
        var maxLength = 0;
        var segments = padding.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var index = 0; index < segments.Length; index++)
        {
            var parts = segments[index].Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 3)
            {
                throw new InvalidOperationException($"Invalid VLESS padding segment: {segments[index]}.");
            }

            var entry = new[]
            {
                int.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture),
                int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture),
                int.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture)
            };

            if (index == 0 && (entry[0] < 100 || entry[1] < 35 || entry[2] < 35))
            {
                throw new InvalidOperationException("The first VLESS padding length must not be smaller than 35.");
            }

            if (index % 2 == 0)
            {
                lengths.Add(entry);
                maxLength += Math.Max(entry[1], entry[2]);
            }
            else
            {
                gaps.Add(entry);
            }
        }

        if (maxLength > 65553)
        {
            throw new InvalidOperationException("The total VLESS padding length must not be larger than 65553.");
        }

        return new PaddingProfile(lengths, gaps);
    }

    private async ValueTask<PreparedHandshake> PrepareHandshakeAsync(
        Profile profile,
        ResumeState resumeState,
        CancellationToken cancellationToken)
    {
        var iv = RandomNumberGenerator.GetBytes(TicketLength);
        var relays = new byte[profile.RelaysLength];
        var cursor = 0;
        byte[]? lastSharedSecret = null;
        CtrTransform? lastRelayCtr = null;

        for (var index = 0; index < profile.PublicKeys.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var key = profile.PublicKeys[index];
            var relayLength = key.Kind == PublicKeyKind.X25519
                ? X25519KeyLength
                : MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;
            byte[] sharedSecret;
            byte[] relay;

            if (key.Kind == PublicKeyKind.X25519)
            {
                using var ephemeral = CreateX25519KeyPair();
                relay = ephemeral.PublicKey;
                sharedSecret = DeriveX25519SharedSecret(ephemeral.PrivateKey, key.RawBytes);
            }
            else
            {
                using var kem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, key.RawBytes);
                kem.Encapsulate(out relay, out sharedSecret);
            }

            relay.CopyTo(relays, cursor);

            if (profile.XorMode > 0)
            {
                using var ctr = CtrTransform.Create(key.RawBytes, iv);
                ctr.Xor(relays.AsSpan(cursor, relayLength));
            }

            if (lastRelayCtr is not null)
            {
                lastRelayCtr.Xor(relays.AsSpan(cursor, X25519KeyLength));
                lastRelayCtr.Dispose();
                lastRelayCtr = null;
            }

            cursor += relayLength;

            if (index + 1 < profile.PublicKeys.Count)
            {
                lastRelayCtr = CtrTransform.Create(sharedSecret, iv);
                profile.PublicKeys[index + 1].Hash32.CopyTo(relays, cursor);
                lastRelayCtr.Xor(relays.AsSpan(cursor, X25519KeyLength));
                cursor += X25519KeyLength;
            }

            lastSharedSecret = sharedSecret;
        }

        lastRelayCtr?.Dispose();

        if (lastSharedSecret is null)
        {
            throw new InvalidOperationException("VLESS encryption handshake did not derive a non-forward-secret key.");
        }

        var useAes = PreferAesGcm();
        var nfsCipher = RecordCipher.Create(iv, lastSharedSecret, useAes);

        if (profile.Seconds > 0 &&
            resumeState.TryAcquireTicket(out var cachedPfsKey, out var cachedTicket))
        {
            var unitedKey = Combine(cachedPfsKey, lastSharedSecret);
            var preWrite = new byte[iv.Length + relays.Length + 18 + 32];
            iv.CopyTo(preWrite, 0);
            relays.CopyTo(preWrite, iv.Length);

            nfsCipher.Encrypt(
                EncodeLength(32),
                ReadOnlySpan<byte>.Empty,
                preWrite.AsSpan(iv.Length + relays.Length, 18));
            nfsCipher.Encrypt(
                cachedTicket,
                ReadOnlySpan<byte>.Empty,
                preWrite.AsSpan(iv.Length + relays.Length + 18, 32));

            return new PreparedHandshake(
                profile,
                HandshakeMode.ZeroRttResume,
                useAes,
                lastSharedSecret,
                nfsCipher)
            {
                PreWrite = preWrite,
                UnitedKey = unitedKey,
                WriteCipher = RecordCipher.Create(
                    preWrite.AsSpan(iv.Length + relays.Length + 18, 32),
                    unitedKey,
                    useAes)
            };
        }

        var pfsMlkemKey = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var pfsX25519Key = CreateX25519KeyPair();

        var pfsMlkemPublic = pfsMlkemKey.ExportEncapsulationKey();
        var pfsX25519Public = pfsX25519Key.PublicKey;
        var pfsPublicKey = Combine(pfsMlkemPublic, pfsX25519Public);

        var pfsExchange = new byte[18 + pfsPublicKey.Length + TagLength];
        nfsCipher.Encrypt(
            EncodeLength(pfsExchange.Length - 18),
            ReadOnlySpan<byte>.Empty,
            pfsExchange.AsSpan(0, 18));
        nfsCipher.Encrypt(
            pfsPublicKey,
            ReadOnlySpan<byte>.Empty,
            pfsExchange.AsSpan(18));

        var createdPadding = profile.Padding.Create();
        var paddingBuffer = new byte[createdPadding.TotalLength];
        if (paddingBuffer.Length > 0)
        {
            nfsCipher.Encrypt(
                EncodeLength(Math.Max(0, paddingBuffer.Length - 18)),
                ReadOnlySpan<byte>.Empty,
                paddingBuffer.AsSpan(0, 18));

            var payloadLength = Math.Max(0, paddingBuffer.Length - 18 - TagLength);
            nfsCipher.Encrypt(
                new byte[payloadLength],
                ReadOnlySpan<byte>.Empty,
                paddingBuffer.AsSpan(18));
        }

        var preWriteBuffer = new byte[iv.Length + relays.Length + pfsExchange.Length + paddingBuffer.Length];
        iv.CopyTo(preWriteBuffer, 0);
        relays.CopyTo(preWriteBuffer, iv.Length);
        pfsExchange.CopyTo(preWriteBuffer, iv.Length + relays.Length);
        paddingBuffer.CopyTo(preWriteBuffer, iv.Length + relays.Length + pfsExchange.Length);

        if (createdPadding.FragmentLengths.Length > 0)
        {
            createdPadding.FragmentLengths[0] += iv.Length + relays.Length + pfsExchange.Length;
        }

        return new PreparedHandshake(
            profile,
            HandshakeMode.FullHandshake,
            useAes,
            lastSharedSecret,
            nfsCipher)
        {
            PreWrite = preWriteBuffer,
            PaddingLengths = createdPadding.FragmentLengths,
            PaddingGaps = createdPadding.FragmentGaps,
            PfsMlkemKey = pfsMlkemKey,
            PfsX25519Key = pfsX25519Key.PrivateKey,
            PfsPublicKey = pfsPublicKey
        };
    }

    private static async ValueTask WriteFragmentedAsync(
        TransportStream transportStream,
        byte[] buffer,
        int[] fragmentLengths,
        TimeSpan[] fragmentGaps,
        CancellationToken cancellationToken)
    {
        if (fragmentLengths.Length == 0)
        {
            await transportStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        var offset = 0;
        for (var index = 0; index < fragmentLengths.Length; index++)
        {
            var length = fragmentLengths[index];
            if (length > 0)
            {
                await transportStream.WriteAsync(buffer.AsMemory(offset, length), cancellationToken).ConfigureAwait(false);
                await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                offset += length;
            }

            if (index < fragmentGaps.Length &&
                fragmentGaps[index] > TimeSpan.Zero)
            {
                await Task.Delay(fragmentGaps[index], cancellationToken).ConfigureAwait(false);
            }
        }

        if (offset < buffer.Length)
        {
            await transportStream.WriteAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static async ValueTask<byte[]> ReadExactAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        return buffer;
    }

    private static byte[] EncodeLength(int value)
        => [(byte)(value >> 8), (byte)value];

    private static int DecodeLength(ReadOnlySpan<byte> value)
    {
        if (value.Length < 2)
        {
            throw new InvalidDataException("VLESS encrypted length is incomplete.");
        }

        return (value[0] << 8) | value[1];
    }

    private static void EncodeHeader(Span<byte> destination, int length)
    {
        destination[0] = 23;
        destination[1] = 3;
        destination[2] = 3;
        destination[3] = (byte)(length >> 8);
        destination[4] = (byte)length;
    }

    private static int DecodeHeader(ReadOnlySpan<byte> source)
    {
        if (source.Length < HeaderLength)
        {
            throw new InvalidDataException("VLESS encrypted header is incomplete.");
        }

        var length = (source[3] << 8) | source[4];
        if (source[0] != 23 || source[1] != 3 || source[2] != 3)
        {
            length = 0;
        }

        if (length < MinCipherRecordLength || length > MaxCipherRecordLength)
        {
            throw new InvalidDataException($"Invalid VLESS encrypted header: {Convert.ToHexString(source[..HeaderLength])}.");
        }

        return length;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + 4 - padding, '=');
        }

        return Convert.FromBase64String(normalized);
    }

    private static byte[] ComputeHash(ReadOnlySpan<byte> value)
    {
        var hash = new byte[32];
        Hasher.Hash(value, hash);
        return hash;
    }

    private static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var buffer = new byte[first.Length + second.Length];
        first.CopyTo(buffer);
        second.CopyTo(buffer.AsSpan(first.Length));
        return buffer;
    }

    private static RuntimeX25519KeyPair CreateX25519KeyPair()
        => RuntimeX25519.CreateKeyPair();

    private static byte[] DeriveX25519SharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
        => RuntimeX25519.DeriveSharedSecret(privateKey, peerPublicKey);

    private static byte[] CreateServerTicket(
        ServerProfile profile,
        ServerResumeState resumeState,
        byte[] pfsKey)
    {
        var ticket = RandomNumberGenerator.GetBytes(TicketLength);
        var seconds = profile.SelectResumeSeconds();
        EncodeLength(seconds).CopyTo(ticket.AsSpan(0, 2));
        if (seconds > 0)
        {
            resumeState.Store(ticket, pfsKey, TimeSpan.FromSeconds(seconds));
        }

        return ticket;
    }

    private static async ValueTask WriteInvalidResumeNoiseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var length = RandomNumberGenerator.GetInt32(1279, 2279);
        var noise = new byte[length];
        do
        {
            RandomNumberGenerator.Fill(noise);
        }
        while (length >= TicketLength + HeaderLength &&
               TryDecodeHeader(noise.AsSpan(TicketLength, HeaderLength), out _));

        await stream.WriteAsync(noise, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static bool TryDecodeHeader(ReadOnlySpan<byte> source, out int length)
    {
        try
        {
            length = DecodeHeader(source);
            return true;
        }
        catch (InvalidDataException)
        {
            length = 0;
            return false;
        }
    }

    private sealed record PublicKeyEntry(
        PublicKeyKind Kind,
        byte[] RawBytes,
        byte[] Hash32);

    private sealed record PrivateKeyEntry(
        PublicKeyKind Kind,
        byte[] RawBytes,
        byte[] PublicBytes,
        byte[] Hash32);

    private enum PublicKeyKind
    {
        X25519 = 0,
        MLKem768 = 1
    }

    private enum HandshakeMode
    {
        FullHandshake = 0,
        ZeroRttResume = 1
    }

    private sealed class ResumeState
    {
        private readonly object _sync = new();
        private DateTimeOffset _expireAt = DateTimeOffset.MinValue;
        private byte[]? _pfsKey;
        private byte[]? _ticket;

        public bool TryAcquireTicket(out byte[] pfsKey, out byte[] ticket)
        {
            lock (_sync)
            {
                if (_pfsKey is not null &&
                    _ticket is not null &&
                    DateTimeOffset.UtcNow < _expireAt)
                {
                    pfsKey = _pfsKey.ToArray();
                    ticket = _ticket.ToArray();
                    return true;
                }

                pfsKey = default!;
                ticket = default!;
                return false;
            }
        }

        public void StoreTicket(int seconds, byte[] pfsKey, byte[] ticket)
        {
            if (seconds <= 0)
            {
                return;
            }

            lock (_sync)
            {
                _expireAt = DateTimeOffset.UtcNow.AddSeconds(seconds);
                _pfsKey = pfsKey.ToArray();
                _ticket = ticket.ToArray();
            }
        }

        public void Invalidate()
        {
            lock (_sync)
            {
                _expireAt = DateTimeOffset.MinValue;
                _pfsKey = null;
                _ticket = null;
            }
        }
    }

    private sealed record ServerState(
        ServerProfile Profile,
        ServerResumeState ResumeState);

    private sealed class ServerProfile
    {
        private ServerProfile(
            IReadOnlyList<PrivateKeyEntry> privateKeys,
            uint xorMode,
            int secondsFrom,
            int secondsTo,
            PaddingProfile padding)
        {
            PrivateKeys = privateKeys;
            XorMode = xorMode;
            SecondsFrom = secondsFrom;
            SecondsTo = secondsTo;
            Padding = padding;
            RelaysLength = privateKeys.Sum(static key => key.Kind == PublicKeyKind.X25519 ? 64 : 1120) - X25519KeyLength;
        }

        public IReadOnlyList<PrivateKeyEntry> PrivateKeys { get; }

        public uint XorMode { get; }

        public int SecondsFrom { get; }

        public int SecondsTo { get; }

        public bool AllowsResume => SecondsFrom > 0 || SecondsTo > 0;

        public PaddingProfile Padding { get; }

        public int RelaysLength { get; }

        public static string CreateCacheKey(VlessInboundSessionOptions options)
        {
            var decryption = NormalizeDecryption(options.Decryption);
            if (decryption.Length == 0)
            {
                return string.Empty;
            }

            var secondsFrom = NormalizeResumeSeconds(options.SecondsFrom);
            var secondsTo = secondsFrom == 0
                ? 0
                : NormalizeResumeSeconds(options.SecondsTo);

            return string.Join(
                "|",
                decryption,
                options.XorMode.ToString(System.Globalization.CultureInfo.InvariantCulture),
                secondsFrom.ToString(System.Globalization.CultureInfo.InvariantCulture),
                secondsTo.ToString(System.Globalization.CultureInfo.InvariantCulture),
                NormalizePaddingValue(options.Padding));
        }

        public static ServerProfile Parse(VlessInboundSessionOptions options)
        {
            var secondsFrom = NormalizeResumeSeconds(options.SecondsFrom);
            var secondsTo = secondsFrom == 0
                ? 0
                : NormalizeResumeSeconds(options.SecondsTo);
            return new ServerProfile(
                ParsePrivateKeys(options.Decryption),
                options.XorMode,
                secondsFrom,
                secondsTo,
                ParsePadding(NormalizePaddingValue(options.Padding)));
        }

        public int SelectResumeSeconds()
        {
            if (!AllowsResume)
            {
                return 0;
            }

            if (SecondsTo <= 0)
            {
                return SecondsFrom * RandomNumberGenerator.GetInt32(50, 100) / 100;
            }

            if (SecondsFrom == SecondsTo)
            {
                return SecondsFrom;
            }

            return RandomNumberGenerator.GetInt32(
                Math.Min(SecondsFrom, SecondsTo),
                Math.Max(SecondsFrom, SecondsTo));
        }

        private static int NormalizeResumeSeconds(int value)
            => Math.Clamp(value, 0, ushort.MaxValue);
    }

    private enum ServerResumeLookupResult
    {
        Missing = 0,
        Acquired = 1,
        Replay = 2
    }

    private sealed class ServerResumeState
    {
        private readonly object _sync = new();
        private readonly Dictionary<string, ServerSession> _sessions = new(StringComparer.Ordinal);

        public ServerResumeLookupResult TryAcquire(
            ReadOnlySpan<byte> ticket,
            ReadOnlySpan<byte> nfsKey,
            out byte[] pfsKey)
        {
            var now = DateTimeOffset.UtcNow;
            lock (_sync)
            {
                RemoveExpiredLocked(now);
                if (!_sessions.TryGetValue(Convert.ToHexString(ticket), out var session))
                {
                    pfsKey = Array.Empty<byte>();
                    return ServerResumeLookupResult.Missing;
                }

                if (!session.SeenNfsKeys.Add(Convert.ToHexString(nfsKey)))
                {
                    pfsKey = Array.Empty<byte>();
                    return ServerResumeLookupResult.Replay;
                }

                pfsKey = session.PfsKey.ToArray();
                return ServerResumeLookupResult.Acquired;
            }
        }

        public void Store(
            ReadOnlySpan<byte> ticket,
            byte[] pfsKey,
            TimeSpan lifetime)
        {
            if (lifetime <= TimeSpan.Zero)
            {
                return;
            }

            var expiresAt = DateTimeOffset.UtcNow.Add(lifetime);
            lock (_sync)
            {
                RemoveExpiredLocked(DateTimeOffset.UtcNow);
                _sessions[Convert.ToHexString(ticket)] = new ServerSession(
                    pfsKey.ToArray(),
                    expiresAt,
                    new HashSet<string>(StringComparer.Ordinal));
            }
        }

        private void RemoveExpiredLocked(DateTimeOffset now)
        {
            if (_sessions.Count == 0)
            {
                return;
            }

            var expiredKeys = _sessions
                .Where(entry => entry.Value.ExpiresAt <= now)
                .Select(static entry => entry.Key)
                .ToArray();
            foreach (var key in expiredKeys)
            {
                _sessions.Remove(key);
            }
        }
    }

    private sealed record ServerSession(
        byte[] PfsKey,
        DateTimeOffset ExpiresAt,
        HashSet<string> SeenNfsKeys);

    private sealed class Profile
    {
        private Profile(
            IReadOnlyList<PublicKeyEntry> publicKeys,
            uint xorMode,
            int seconds,
            PaddingProfile padding)
        {
            PublicKeys = publicKeys;
            XorMode = xorMode;
            Seconds = seconds;
            Padding = padding;
            RelaysLength = publicKeys.Sum(static key => key.Kind == PublicKeyKind.X25519 ? 64 : 1120) - X25519KeyLength;
        }

        public IReadOnlyList<PublicKeyEntry> PublicKeys { get; }

        public uint XorMode { get; }

        public int Seconds { get; }

        public PaddingProfile Padding { get; }

        public int RelaysLength { get; }

        public static Profile Parse(VlessClientOptions options)
            => new(
                ParsePublicKeys(options.Encryption),
                options.XorMode,
                Math.Max(0, options.Seconds),
                ParsePadding(NormalizePadding(options.Padding)));

        public string CreateResumeKey(VlessClientOptions options)
            => string.Join(
                "|",
                options.ServerHost.Trim(),
                options.ServerPort.ToString(System.Globalization.CultureInfo.InvariantCulture),
                NormalizeEncryption(options.Encryption),
                options.XorMode.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Math.Max(0, options.Seconds).ToString(System.Globalization.CultureInfo.InvariantCulture),
                NormalizePadding(options.Padding));
    }

    private sealed record PaddingProfile(
        IReadOnlyList<int[]> Lengths,
        IReadOnlyList<int[]> Gaps)
    {
        private static readonly int[][] DefaultLengths = [[100, 111, 1111], [50, 0, 3333]];
        private static readonly int[][] DefaultGaps = [[75, 0, 111]];

        public CreatedPadding Create()
        {
            var lengths = Lengths.Count > 0 ? Lengths : DefaultLengths;
            var gaps = Gaps.Count > 0 ? Gaps : DefaultGaps;

            var totalLength = 0;
            var fragmentLengths = new int[lengths.Count];
            for (var index = 0; index < lengths.Count; index++)
            {
                var entry = lengths[index];
                var length = entry[0] >= NextInt(0, 100)
                    ? NextInt(entry[1], entry[2])
                    : 0;
                fragmentLengths[index] = length;
                totalLength += length;
            }

            var fragmentGaps = new TimeSpan[gaps.Count];
            for (var index = 0; index < gaps.Count; index++)
            {
                var entry = gaps[index];
                var milliseconds = entry[0] >= NextInt(0, 100)
                    ? NextInt(entry[1], entry[2])
                    : 0;
                fragmentGaps[index] = TimeSpan.FromMilliseconds(milliseconds);
            }

            return new CreatedPadding(totalLength, fragmentLengths, fragmentGaps);
        }

        private static int NextInt(int fromInclusive, int toExclusive)
        {
            if (fromInclusive == toExclusive)
            {
                return fromInclusive;
            }

            if (fromInclusive > toExclusive)
            {
                (fromInclusive, toExclusive) = (toExclusive, fromInclusive);
            }

            return RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);
        }
    }

    private sealed record CreatedPadding(
        int TotalLength,
        int[] FragmentLengths,
        TimeSpan[] FragmentGaps);

    private sealed class PreparedHandshake : IDisposable
    {
        public PreparedHandshake(
            Profile profile,
            HandshakeMode mode,
            bool useAes,
            byte[] nfsKey,
            RecordCipher nfsCipher)
        {
            Profile = profile;
            Mode = mode;
            UseAes = useAes;
            NfsKey = nfsKey;
            NfsCipher = nfsCipher;
        }

        public Profile Profile { get; }

        public HandshakeMode Mode { get; }

        public bool UseAes { get; }

        public byte[] NfsKey { get; }

        public RecordCipher NfsCipher { get; }

        public byte[] PreWrite { get; init; } = Array.Empty<byte>();

        public byte[] UnitedKey { get; init; } = Array.Empty<byte>();

        public RecordCipher? WriteCipher { get; set; }

        public int[] PaddingLengths { get; init; } = Array.Empty<int>();

        public TimeSpan[] PaddingGaps { get; init; } = Array.Empty<TimeSpan>();

        public MLKem? PfsMlkemKey { get; init; }

        public byte[]? PfsX25519Key { get; init; }

        public byte[] PfsPublicKey { get; init; } = Array.Empty<byte>();

        public TransportStream CreateTransportStream(Stream stream)
            => new(stream, Profile.XorMode == 2);

        public void Dispose()
        {
            NfsCipher.Dispose();
            WriteCipher?.Dispose();
            PfsMlkemKey?.Dispose();
        }
    }

    private sealed class RecordCipher : IDisposable
    {
        private readonly AesGcm? _aesGcm;
        private readonly ChaCha20Poly1305? _chacha20Poly1305;
        private readonly byte[] _nonce = new byte[12];

        private RecordCipher(byte[] key, bool useAes)
        {
            UseAes = useAes;
            if (useAes)
            {
                _aesGcm = new AesGcm(key, TagLength);
            }
            else
            {
                _chacha20Poly1305 = new ChaCha20Poly1305(key);
            }
        }

        public bool UseAes { get; }

        public bool IsAtMaxNonce
            => _nonce.AsSpan().SequenceEqual(MaxNonce);

        public static RecordCipher Create(
            ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> key,
            bool useAes)
        {
            var derivedKey = new byte[32];
            using var hasher = Hasher.NewDeriveKey(context);
            hasher.Update(key);
            hasher.Finalize(derivedKey);
            return new RecordCipher(derivedKey, useAes);
        }

        public void Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> additionalData,
            Span<byte> destination,
            byte[]? nonce = null)
        {
            if (destination.Length != plaintext.Length + TagLength)
            {
                throw new ArgumentException("The VLESS encrypted record buffer size is invalid.", nameof(destination));
            }

            var ciphertext = destination[..plaintext.Length];
            var tag = destination[plaintext.Length..];
            var resolvedNonce = nonce ?? AdvanceNonce();
            if (UseAes)
            {
                _aesGcm!.Encrypt(resolvedNonce, plaintext, ciphertext, tag, additionalData);
            }
            else
            {
                _chacha20Poly1305!.Encrypt(resolvedNonce, plaintext, ciphertext, tag, additionalData);
            }
        }

        public void Decrypt(
            ReadOnlySpan<byte> ciphertextAndTag,
            ReadOnlySpan<byte> additionalData,
            Span<byte> destination,
            byte[]? nonce = null)
        {
            if (ciphertextAndTag.Length < TagLength)
            {
                throw new InvalidDataException("The VLESS encrypted record is too short.");
            }

            if (destination.Length != ciphertextAndTag.Length - TagLength)
            {
                throw new ArgumentException("The VLESS decrypted record buffer size is invalid.", nameof(destination));
            }

            var ciphertext = ciphertextAndTag[..^TagLength];
            var tag = ciphertextAndTag[^TagLength..];
            var resolvedNonce = nonce ?? AdvanceNonce();
            if (UseAes)
            {
                _aesGcm!.Decrypt(resolvedNonce, ciphertext, tag, destination, additionalData);
            }
            else
            {
                _chacha20Poly1305!.Decrypt(resolvedNonce, ciphertext, tag, destination, additionalData);
            }
        }

        private byte[] AdvanceNonce()
        {
            for (var index = _nonce.Length - 1; index >= 0; index--)
            {
                unchecked
                {
                    _nonce[index]++;
                }

                if (_nonce[index] != 0)
                {
                    break;
                }
            }

            return _nonce;
        }

        public void Dispose()
        {
            _aesGcm?.Dispose();
            _chacha20Poly1305?.Dispose();
        }
    }

    private sealed class CtrTransform : IDisposable
    {
        private readonly Aes _aes;
        private readonly byte[] _counter;
        private readonly ICryptoTransform _encryptor;
        private readonly byte[] _keystream = new byte[16];
        private int _keystreamOffset = 16;

        private CtrTransform(byte[] key, byte[] iv)
        {
            _aes = Aes.Create();
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;
            _aes.Key = key;
            _encryptor = _aes.CreateEncryptor();
            _counter = iv;
        }

        public static CtrTransform Create(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            if (iv.Length != 16)
            {
                throw new ArgumentOutOfRangeException(nameof(iv), "The VLESS CTR IV must be 16 bytes.");
            }

            var derivedKey = new byte[32];
            using var hasher = Hasher.NewDeriveKey(CtrDeriveKeyContext);
            hasher.Update(key);
            hasher.Finalize(derivedKey);
            return new CtrTransform(derivedKey, iv.ToArray());
        }

        public void Xor(Span<byte> buffer)
        {
            for (var index = 0; index < buffer.Length; index++)
            {
                if (_keystreamOffset >= _keystream.Length)
                {
                    FillKeystream();
                }

                buffer[index] ^= _keystream[_keystreamOffset++];
            }
        }

        private void FillKeystream()
        {
            _encryptor.TransformBlock(_counter, 0, _counter.Length, _keystream, 0);
            IncrementCounter(_counter);
            _keystreamOffset = 0;
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (var index = counter.Length - 1; index >= 0; index--)
            {
                unchecked
                {
                    counter[index]++;
                }

                if (counter[index] != 0)
                {
                    break;
                }
            }
        }

        public void Dispose()
        {
            _encryptor.Dispose();
            _aes.Dispose();
        }
    }

    private sealed class TransportStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly byte[] _inHeader = new byte[HeaderLength];
        private readonly byte[] _outHeader = new byte[HeaderLength];
        private readonly bool _xorEnabled;
        private CtrTransform? _inboundCtr;
        private CtrTransform? _outboundCtr;
        private byte[] _unitedKey = Array.Empty<byte>();
        private int _inHeaderCount;
        private int _inSkip;
        private int _outHeaderCount;
        private int _outSkip;

        public TransportStream(Stream innerStream, bool xorEnabled)
        {
            _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
            _xorEnabled = xorEnabled;
        }

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

        public void ConfigureXor(
            byte[] unitedKey,
            byte[]? outboundSeed,
            int outboundSkip,
            byte[]? inboundSeed,
            int inboundSkip)
        {
            if (!_xorEnabled)
            {
                return;
            }

            _unitedKey = unitedKey.ToArray();
            UpdateCtr(ref _outboundCtr, outboundSeed);
            UpdateCtr(ref _inboundCtr, inboundSeed);
            _outSkip = Math.Max(0, outboundSkip);
            _inSkip = Math.Max(0, inboundSkip);
            _outHeaderCount = 0;
            _inHeaderCount = 0;
        }

        public void UpdateInboundCtrSeed(byte[] inboundSeed, int inboundSkip = 0)
        {
            if (!_xorEnabled)
            {
                return;
            }

            if (_unitedKey.Length == 0)
            {
                throw new InvalidOperationException("VLESS transport XOR has not been initialized.");
            }

            UpdateCtr(ref _inboundCtr, inboundSeed);
            _inSkip = Math.Max(0, inboundSkip);
            _inHeaderCount = 0;
        }

        public override void Flush()
            => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsMemory(offset, count).Span);

        public override int Read(Span<byte> buffer)
        {
            var count = _innerStream.Read(buffer);
            ProcessInbound(buffer[..count]);
            return count;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var count = await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            ProcessInbound(buffer.Span[..count]);
            return count;
        }

        public override void Write(byte[] buffer, int offset, int count)
            => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!_xorEnabled || buffer.Length == 0)
            {
                _innerStream.Write(buffer);
                return;
            }

            var copy = buffer.ToArray();
            ProcessOutbound(copy);
            _innerStream.Write(copy);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_xorEnabled || buffer.Length == 0)
            {
                await _innerStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                return;
            }

            var copy = buffer.ToArray();
            ProcessOutbound(copy);
            await _innerStream.WriteAsync(copy, cancellationToken).ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _outboundCtr?.Dispose();
                _inboundCtr?.Dispose();
                _outboundCtr = null;
                _inboundCtr = null;
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            Dispose(disposing: true);
            return ValueTask.CompletedTask;
        }

        private void UpdateCtr(ref CtrTransform? target, byte[]? seed)
        {
            target?.Dispose();
            target = seed is null ? null : CtrTransform.Create(_unitedKey, seed);
        }

        private void ProcessOutbound(Span<byte> buffer)
        {
            if (_outboundCtr is null)
            {
                return;
            }

            var offset = 0;
            while (offset < buffer.Length)
            {
                if (_outSkip > 0)
                {
                    var skip = Math.Min(_outSkip, buffer.Length - offset);
                    _outSkip -= skip;
                    offset += skip;
                    if (offset >= buffer.Length)
                    {
                        return;
                    }
                }

                var need = HeaderLength - _outHeaderCount;
                if (buffer.Length - offset < need)
                {
                    buffer[offset..].CopyTo(_outHeader.AsSpan(_outHeaderCount));
                    _outHeaderCount += buffer.Length - offset;
                    _outboundCtr.Xor(buffer[offset..]);
                    return;
                }

                buffer.Slice(offset, need).CopyTo(_outHeader.AsSpan(_outHeaderCount));
                _outboundCtr.Xor(buffer.Slice(offset, need));
                _outHeaderCount += need;
                _outSkip = DecodeHeader(_outHeader);
                _outHeaderCount = 0;
                offset += need;
            }
        }

        private void ProcessInbound(Span<byte> buffer)
        {
            if (!_xorEnabled || buffer.Length == 0)
            {
                return;
            }

            var offset = 0;
            while (offset < buffer.Length)
            {
                if (_inSkip > 0)
                {
                    var skip = Math.Min(_inSkip, buffer.Length - offset);
                    _inSkip -= skip;
                    offset += skip;
                    if (offset >= buffer.Length)
                    {
                        return;
                    }
                }

                if (_inboundCtr is null)
                {
                    return;
                }

                var need = HeaderLength - _inHeaderCount;
                if (buffer.Length - offset < need)
                {
                    var segment = buffer[offset..];
                    _inboundCtr.Xor(segment);
                    segment.CopyTo(_inHeader.AsSpan(_inHeaderCount));
                    _inHeaderCount += segment.Length;
                    return;
                }

                var headerSegment = buffer.Slice(offset, need);
                _inboundCtr.Xor(headerSegment);
                headerSegment.CopyTo(_inHeader.AsSpan(_inHeaderCount));
                _inHeaderCount += need;
                _inSkip = DecodeHeader(_inHeader);
                _inHeaderCount = 0;
                offset += need;
            }
        }
    }

    private sealed class EncryptedStream : Stream
    {
        private readonly ResumeState _resumeState;
        private readonly TransportStream _transportStream;
        private readonly byte[] _unitedKey;
        private RecordCipher? _readCipher;
        private RecordCipher _writeCipher;
        private bool _canRetryResume;
        private byte[] _pendingRead = Array.Empty<byte>();
        private int _pendingReadOffset;
        private int _peerPaddingLength;
        private byte[]? _preWrite;

        public EncryptedStream(
            TransportStream transportStream,
            byte[] unitedKey,
            RecordCipher writeCipher,
            RecordCipher? readCipher,
            byte[]? preWrite,
            int peerPaddingLength,
            ResumeState resumeState,
            bool canRetryResume)
        {
            _transportStream = transportStream ?? throw new ArgumentNullException(nameof(transportStream));
            _unitedKey = unitedKey ?? throw new ArgumentNullException(nameof(unitedKey));
            _writeCipher = writeCipher ?? throw new ArgumentNullException(nameof(writeCipher));
            _readCipher = readCipher;
            _preWrite = preWrite;
            _peerPaddingLength = Math.Max(0, peerPaddingLength);
            _resumeState = resumeState ?? throw new ArgumentNullException(nameof(resumeState));
            _canRetryResume = canRetryResume;
        }

        public override bool CanRead => _transportStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _transportStream.CanWrite;

        public override bool CanTimeout => _transportStream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int ReadTimeout
        {
            get => _transportStream.ReadTimeout;
            set => _transportStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _transportStream.WriteTimeout;
            set => _transportStream.WriteTimeout = value;
        }

        public override void Flush()
            => _transportStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _transportStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => ReadCoreAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => WriteCoreAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _writeCipher.Dispose();
                _readCipher?.Dispose();
                _writeCipher = null!;
                _readCipher = null;
                _pendingRead = Array.Empty<byte>();
                _pendingReadOffset = 0;
                _preWrite = null;
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            Dispose(disposing: true);
            return ValueTask.CompletedTask;
        }

        private async ValueTask<int> ReadCoreAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken)
        {
            if (buffer.Length == 0)
            {
                return 0;
            }

            var copied = TryReadPending(buffer.Span);
            if (copied > 0)
            {
                return copied;
            }

            await EnsureReadCipherAsync(cancellationToken).ConfigureAwait(false);
            await ConsumePeerPaddingAsync(cancellationToken).ConfigureAwait(false);

            var header = await ReadExactAsync(_transportStream, HeaderLength, cancellationToken).ConfigureAwait(false);

            int cipherLength;
            try
            {
                cipherLength = DecodeHeader(header);
                _canRetryResume = false;
            }
            catch (InvalidDataException ex) when (_canRetryResume)
            {
                _resumeState.Invalidate();
                throw new IOException("new handshake needed", ex);
            }

            var encryptedPayload = await ReadExactAsync(_transportStream, cipherLength, cancellationToken).ConfigureAwait(false);
            var plaintextLength = cipherLength - TagLength;
            var rotateCipher = _readCipher!.IsAtMaxNonce;
            RecordCipher? nextCipher = null;
            if (rotateCipher)
            {
                nextCipher = RecordCipher.Create(
                    Combine(header, encryptedPayload),
                    _unitedKey,
                    _writeCipher.UseAes);
            }

            try
            {
                if (plaintextLength <= buffer.Length)
                {
                    _readCipher.Decrypt(
                        encryptedPayload,
                        header,
                        buffer.Span[..plaintextLength]);
                    PromoteReadCipher(nextCipher);
                    return plaintextLength;
                }

                var plaintext = new byte[plaintextLength];
                _readCipher.Decrypt(
                    encryptedPayload,
                    header,
                    plaintext);
                PromoteReadCipher(nextCipher);

                plaintext.AsSpan(0, buffer.Length).CopyTo(buffer.Span);
                _pendingRead = plaintext;
                _pendingReadOffset = buffer.Length;
                return buffer.Length;
            }
            catch
            {
                nextCipher?.Dispose();
                throw;
            }
        }

        private async ValueTask WriteCoreAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken)
        {
            if (buffer.Length == 0)
            {
                return;
            }

            var offset = 0;
            while (offset < buffer.Length)
            {
                var chunkLength = Math.Min(CipherChunkLength, buffer.Length - offset);
                var payload = CreateOutboundPayload(buffer.Slice(offset, chunkLength).Span);
                await _transportStream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
                offset += chunkLength;
            }
        }

        private byte[] CreateOutboundPayload(ReadOnlySpan<byte> plaintext)
        {
            var record = new byte[HeaderLength + plaintext.Length + TagLength];
            EncodeHeader(record.AsSpan(0, HeaderLength), plaintext.Length + TagLength);

            var rotateCipher = _writeCipher.IsAtMaxNonce;
            _writeCipher.Encrypt(
                plaintext,
                record.AsSpan(0, HeaderLength),
                record.AsSpan(HeaderLength));

            if (rotateCipher)
            {
                var nextCipher = RecordCipher.Create(record, _unitedKey, _writeCipher.UseAes);
                _writeCipher.Dispose();
                _writeCipher = nextCipher;
            }

            if (_preWrite is null || _preWrite.Length == 0)
            {
                return record;
            }

            var combined = new byte[_preWrite.Length + record.Length];
            _preWrite.CopyTo(combined, 0);
            record.CopyTo(combined, _preWrite.Length);
            _preWrite = null;
            return combined;
        }

        private int TryReadPending(Span<byte> destination)
        {
            if (_pendingReadOffset >= _pendingRead.Length)
            {
                _pendingRead = Array.Empty<byte>();
                _pendingReadOffset = 0;
                return 0;
            }

            var count = Math.Min(destination.Length, _pendingRead.Length - _pendingReadOffset);
            _pendingRead.AsSpan(_pendingReadOffset, count).CopyTo(destination);
            _pendingReadOffset += count;
            if (_pendingReadOffset >= _pendingRead.Length)
            {
                _pendingRead = Array.Empty<byte>();
                _pendingReadOffset = 0;
            }

            return count;
        }

        private async ValueTask EnsureReadCipherAsync(CancellationToken cancellationToken)
        {
            if (_readCipher is not null)
            {
                return;
            }

            var serverRandom = await ReadExactAsync(_transportStream, TicketLength, cancellationToken).ConfigureAwait(false);
            _readCipher = RecordCipher.Create(serverRandom, _unitedKey, _writeCipher.UseAes);
            _transportStream.UpdateInboundCtrSeed(serverRandom);
        }

        private async ValueTask ConsumePeerPaddingAsync(CancellationToken cancellationToken)
        {
            if (_peerPaddingLength <= 0)
            {
                return;
            }

            var encryptedPadding = await ReadExactAsync(_transportStream, _peerPaddingLength, cancellationToken).ConfigureAwait(false);
            var padding = new byte[Math.Max(0, encryptedPadding.Length - TagLength)];
            _readCipher!.Decrypt(encryptedPadding, ReadOnlySpan<byte>.Empty, padding);
            _peerPaddingLength = 0;
        }

        private void PromoteReadCipher(RecordCipher? nextCipher)
        {
            if (nextCipher is null)
            {
                return;
            }

            _readCipher!.Dispose();
            _readCipher = nextCipher;
        }
    }

}

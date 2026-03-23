using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

public sealed class VmessHandshakeReader
{
    private const int AeadTagLength = 16;
    private const int AuthIdToleranceSeconds = 120;
    private const string DrainErrorPrefix = "common/drain: ";
    private const string VmessEncodingErrorPrefix = "proxy/vmess/encoding: ";

    private static readonly byte[] SaltAuthIdEncryptionKey = Encoding.ASCII.GetBytes("AES Auth ID Encryption");
    private static readonly byte[] SaltAeadResponseHeaderLengthKey = Encoding.ASCII.GetBytes("AEAD Resp Header Len Key");
    private static readonly byte[] SaltAeadResponseHeaderLengthIv = Encoding.ASCII.GetBytes("AEAD Resp Header Len IV");
    private static readonly byte[] SaltAeadResponseHeaderPayloadKey = Encoding.ASCII.GetBytes("AEAD Resp Header Key");
    private static readonly byte[] SaltAeadResponseHeaderPayloadIv = Encoding.ASCII.GetBytes("AEAD Resp Header IV");
    private static readonly byte[] SaltVmessHeaderPayloadAeadKey = Encoding.ASCII.GetBytes("VMess Header AEAD Key");
    private static readonly byte[] SaltVmessHeaderPayloadAeadIv = Encoding.ASCII.GetBytes("VMess Header AEAD Nonce");
    private static readonly byte[] SaltVmessHeaderPayloadLengthAeadKey = Encoding.ASCII.GetBytes("VMess Header AEAD Key_Length");
    private static readonly byte[] SaltVmessHeaderPayloadLengthAeadIv = Encoding.ASCII.GetBytes("VMess Header AEAD Nonce_Length");

    private readonly VmessAuthIdHistory _authIdHistory;
    private readonly VmessBehaviorSeedRegistry _behaviorSeedRegistry;
    private readonly VmessSessionHistory _sessionHistory;

    public VmessHandshakeReader()
        : this(new VmessSessionHistory(), new VmessAuthIdHistory(), new VmessBehaviorSeedRegistry())
    {
    }

    internal VmessHandshakeReader(VmessSessionHistory sessionHistory)
        : this(sessionHistory, new VmessAuthIdHistory(), new VmessBehaviorSeedRegistry())
    {
    }

    internal VmessHandshakeReader(VmessSessionHistory sessionHistory, VmessAuthIdHistory authIdHistory)
        : this(sessionHistory, authIdHistory, new VmessBehaviorSeedRegistry())
    {
    }

    internal VmessHandshakeReader(
        VmessSessionHistory sessionHistory,
        VmessAuthIdHistory authIdHistory,
        VmessBehaviorSeedRegistry behaviorSeedRegistry)
    {
        _authIdHistory = authIdHistory ?? throw new ArgumentNullException(nameof(authIdHistory));
        _behaviorSeedRegistry = behaviorSeedRegistry ?? throw new ArgumentNullException(nameof(behaviorSeedRegistry));
        _sessionHistory = sessionHistory ?? throw new ArgumentNullException(nameof(sessionHistory));
    }

    public async ValueTask<VmessRequest> ReadAsync(
        Stream stream,
        IReadOnlyList<VmessUser> users,
        CancellationToken cancellationToken)
        => await ReadAsync(stream, users, drainOnFailure: false, cancellationToken).ConfigureAwait(false);

    internal async ValueTask<VmessRequest> ReadAsync(
        Stream stream,
        IReadOnlyList<VmessUser> users,
        bool drainOnFailure,
        CancellationToken cancellationToken)
        => await ReadAsync(stream, users, drainOnFailure, runtimeState: null, cancellationToken).ConfigureAwait(false);

    internal async ValueTask<VmessRequest> ReadAsync(
        Stream stream,
        IReadOnlyList<VmessUser> users,
        bool drainOnFailure,
        VmessInboundRuntimeState? runtimeState,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(users);

        var authIdHistory = runtimeState?.AuthIdHistory ?? _authIdHistory;
        var sessionHistory = runtimeState?.SessionHistory ?? _sessionHistory;
        var behaviorSeed = runtimeState?.BehaviorSeed;
        var drainer = drainOnFailure
            ? VmessHandshakeDrainer.Create(behaviorSeed ?? _behaviorSeedRegistry.GetOrCreate(null, users))
            : null;

        var authId = new byte[16];
        await TrojanProtocolCodec.ReadExactAsync(stream, authId, cancellationToken).ConfigureAwait(false);
        drainer?.AcknowledgeReceive(authId.Length);

        var (user, authIdError) = ResolveUser(authId, users, authIdHistory);
        if (user is null)
        {
            throw await DrainAndThrowAsync(
                drainer,
                stream,
                CreateInvalidUserException(authIdError),
                cancellationToken).ConfigureAwait(false);
        }

        var encryptedHeaderLength = new byte[2 + AeadTagLength];
        var connectionNonce = new byte[8];
        try
        {
            await TrojanProtocolCodec.ReadExactAsync(stream, encryptedHeaderLength, cancellationToken).ConfigureAwait(false);
            drainer?.AcknowledgeReceive(encryptedHeaderLength.Length);
            await TrojanProtocolCodec.ReadExactAsync(stream, connectionNonce, cancellationToken).ConfigureAwait(false);
            drainer?.AcknowledgeReceive(connectionNonce.Length);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidDataException(VmessEncodingErrorPrefix + "AEAD read failed, drain skipped", ex);
        }

        var payloadLengthKey = VmessAeadKdf.Kdf16(
            user.CmdKey,
            SaltVmessHeaderPayloadLengthAeadKey,
            authId,
            connectionNonce);
        var payloadLengthNonce = VmessAeadKdf.Kdf(
            user.CmdKey,
            SaltVmessHeaderPayloadLengthAeadIv,
            authId,
            connectionNonce).AsSpan(0, 12).ToArray();
        byte[] decryptedLength;
        try
        {
            decryptedLength = DecryptAead(payloadLengthKey, payloadLengthNonce, encryptedHeaderLength, authId);
        }
        catch (CryptographicException ex)
        {
            throw await DrainAndThrowAsync(
                drainer,
                stream,
                new InvalidDataException(VmessEncodingErrorPrefix + "AEAD read failed", ex),
                cancellationToken).ConfigureAwait(false);
        }

        if (decryptedLength.Length != 2)
        {
            throw new InvalidDataException(VmessEncodingErrorPrefix + "AEAD read failed");
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(decryptedLength);
        var encryptedPayload = new byte[payloadLength + AeadTagLength];
        try
        {
            await TrojanProtocolCodec.ReadExactAsync(stream, encryptedPayload, cancellationToken).ConfigureAwait(false);
            drainer?.AcknowledgeReceive(encryptedPayload.Length);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidDataException(VmessEncodingErrorPrefix + "AEAD read failed, drain skipped", ex);
        }

        var payloadKey = VmessAeadKdf.Kdf16(
            user.CmdKey,
            SaltVmessHeaderPayloadAeadKey,
            authId,
            connectionNonce);
        var payloadNonce = VmessAeadKdf.Kdf(
            user.CmdKey,
            SaltVmessHeaderPayloadAeadIv,
            authId,
            connectionNonce).AsSpan(0, 12).ToArray();
        byte[] decryptedPayload;
        try
        {
            decryptedPayload = DecryptAead(payloadKey, payloadNonce, encryptedPayload, authId);
        }
        catch (CryptographicException ex)
        {
            throw await DrainAndThrowAsync(
                drainer,
                stream,
                new InvalidDataException(VmessEncodingErrorPrefix + "AEAD read failed", ex),
                cancellationToken).ConfigureAwait(false);
        }

        var request = ParseRequest(decryptedPayload, user);
        if (!sessionHistory.TryRegister(request))
        {
            throw new InvalidDataException(VmessEncodingErrorPrefix + "duplicated session id, possibly under replay attack, but this is a AEAD request");
        }

        if (request.Security is VmessSecurityType.Unknown or VmessSecurityType.Auto)
        {
            throw new NotSupportedException(VmessEncodingErrorPrefix + $"unknown security type: {request.Security}");
        }

        return request;
    }

    public static ValueTask WriteResponseAsync(
        Stream stream,
        VmessRequest request,
        CancellationToken cancellationToken)
    {
        var responseBodyKey = DeriveResponseBodyKey(request.RequestBodyKey);
        var responseBodyIv = DeriveResponseBodyIv(request.RequestBodyIv);

        Span<byte> responseHeaderLength = stackalloc byte[2];
        var responsePayload = new byte[] { request.ResponseHeader, 0x00, 0x00, 0x00 };
        BinaryPrimitives.WriteUInt16BigEndian(responseHeaderLength, (ushort)responsePayload.Length);

        var encryptedLength = EncryptAead(
            VmessAeadKdf.Kdf16(responseBodyKey, SaltAeadResponseHeaderLengthKey),
            VmessAeadKdf.Kdf(responseBodyIv, SaltAeadResponseHeaderLengthIv).AsSpan(0, 12).ToArray(),
            responseHeaderLength.ToArray(),
            ReadOnlySpan<byte>.Empty);
        var encryptedPayload = EncryptAead(
            VmessAeadKdf.Kdf16(responseBodyKey, SaltAeadResponseHeaderPayloadKey),
            VmessAeadKdf.Kdf(responseBodyIv, SaltAeadResponseHeaderPayloadIv).AsSpan(0, 12).ToArray(),
            responsePayload,
            ReadOnlySpan<byte>.Empty);

        return WriteResponseAsync(stream, encryptedLength, encryptedPayload, cancellationToken);
    }

    internal static VmessDataStream CreateDataStream(Stream stream, VmessRequest request)
        => new(stream, request);

    internal static byte[] DeriveResponseBodyKey(ReadOnlySpan<byte> requestBodyKey)
        => SHA256.HashData(requestBodyKey.ToArray()).AsSpan(0, 16).ToArray();

    internal static byte[] DeriveResponseBodyIv(ReadOnlySpan<byte> requestBodyIv)
        => SHA256.HashData(requestBodyIv.ToArray()).AsSpan(0, 16).ToArray();

    private static async ValueTask WriteResponseAsync(
        Stream stream,
        byte[] encryptedLength,
        byte[] encryptedPayload,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(encryptedLength, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(encryptedPayload, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<Exception> DrainAndThrowAsync(
        VmessHandshakeDrainer? drainer,
        Stream stream,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (drainer is not null)
        {
            try
            {
                var drained = await drainer.DrainAsync(stream, cancellationToken).ConfigureAwait(false);
                if (drained)
                {
                    return new IOException(DrainErrorPrefix + "drained connection", exception);
                }

                return new IOException(
                    DrainErrorPrefix + "unable to drain connection",
                    new EndOfStreamException("VMess handshake drain reached EOF before expected byte count.", exception));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                return new IOException(
                    DrainErrorPrefix + "unable to drain connection",
                    new IOException(ex.Message, exception));
            }
        }

        return exception;
    }

    private static VmessRequest ParseRequest(ReadOnlySpan<byte> payload, VmessUser user)
    {
        if (payload.Length < 42)
        {
            throw new InvalidDataException("VMess request header is too short.");
        }

        var checksumOffset = payload.Length - 4;
        var expectedChecksum = BinaryPrimitives.ReadUInt32BigEndian(payload[checksumOffset..]);
        var actualChecksum = ComputeFnv1a(payload[..checksumOffset]);
        if (expectedChecksum != actualChecksum)
        {
            throw new InvalidDataException(VmessEncodingErrorPrefix + "invalid auth, but this is a AEAD request");
        }

        var version = payload[0];
        if (version != 1)
        {
            throw new NotSupportedException($"Unsupported VMess version: {version}.");
        }

        var requestBodyIv = payload.Slice(1, 16).ToArray();
        var requestBodyKey = payload.Slice(17, 16).ToArray();
        var responseHeader = payload[33];
        var option = payload[34];
        var paddingLength = payload[35] >> 4;
        var security = ParseSecurityType((byte)(payload[35] & 0x0F));
        var command = (VmessCommand)payload[37];

        var offset = 38;
        string targetHost;
        int targetPort;

        if (command == VmessCommand.Mux)
        {
            targetHost = "v1.mux.cool";
            targetPort = 0;
        }
        else
        {
            if (payload.Length < offset + 3)
            {
                throw new InvalidDataException("VMess request destination is truncated.");
            }

            targetPort = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(offset, 2));
            offset += 2;
            targetHost = ReadAddress(payload, ref offset);
        }

        if (offset + paddingLength != checksumOffset)
        {
            if (offset + paddingLength > checksumOffset)
            {
                throw new InvalidDataException("VMess request padding is invalid.");
            }

            offset += paddingLength;
            if (offset != checksumOffset)
            {
                throw new InvalidDataException("VMess request header layout is invalid.");
            }
        }

        return new VmessRequest
        {
            Version = version,
            User = user,
            RequestBodyIv = requestBodyIv,
            RequestBodyKey = requestBodyKey,
            ResponseHeader = responseHeader,
            Option = option,
            Security = security,
            Command = command,
            TargetHost = targetHost,
            TargetPort = targetPort
        };
    }

    private static string ReadAddress(ReadOnlySpan<byte> payload, ref int offset)
    {
        var addressType = payload[offset++];
        return addressType switch
        {
            0x01 => ReadIpAddress(payload, ref offset, 4),
            0x03 => ReadDomain(payload, ref offset),
            0x04 => ReadIpAddress(payload, ref offset, 16),
            _ => throw new InvalidDataException($"Unsupported VMess address type: {addressType}.")
        };
    }

    private static string ReadIpAddress(ReadOnlySpan<byte> payload, ref int offset, int byteCount)
    {
        if (payload.Length < offset + byteCount)
        {
            throw new InvalidDataException("VMess IP address is truncated.");
        }

        var host = new System.Net.IPAddress(payload.Slice(offset, byteCount)).ToString();
        offset += byteCount;
        return host;
    }

    private static string ReadDomain(ReadOnlySpan<byte> payload, ref int offset)
    {
        if (payload.Length <= offset)
        {
            throw new InvalidDataException("VMess domain address is truncated.");
        }

        var length = payload[offset++];
        if (length == 0 || payload.Length < offset + length)
        {
            throw new InvalidDataException("VMess domain address is invalid.");
        }

        var domain = Encoding.ASCII.GetString(payload.Slice(offset, length));
        offset += length;
        return domain;
    }

    private static (VmessUser? User, Exception? Error) ResolveUser(
        ReadOnlySpan<byte> authId,
        IReadOnlyList<VmessUser> users,
        VmessAuthIdHistory authIdHistory)
    {
        for (var index = 0; index < users.Count; index++)
        {
            var user = users[index];
            if (user.CmdKey.Length != 16)
            {
                continue;
            }

            var decryptedAuthId = DecryptAuthId(authId, user.CmdKey);
            switch (ValidateAuthId(decryptedAuthId))
            {
                case AuthIdValidationResult.InvalidChecksum:
                    continue;

                case AuthIdValidationResult.NegativeTime:
                    return (null, new InvalidDataException("timestamp is negative"));

                case AuthIdValidationResult.InvalidTime:
                    return (null, new InvalidDataException("invalid timestamp, perhaps unsynchronized time"));

                case AuthIdValidationResult.Valid:
                    if (!authIdHistory.TryRegister(authId))
                    {
                        return (null, new InvalidDataException("replayed request"));
                    }

                    return (user, null);
            }
        }

        return (null, new InvalidDataException("user do not exist"));
    }

    private static byte[] DecryptAuthId(ReadOnlySpan<byte> authId, ReadOnlySpan<byte> cmdKey)
    {
        var authIdKey = VmessAeadKdf.Kdf16(cmdKey, SaltAuthIdEncryptionKey);
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = authIdKey;
        using var decryptor = aes.CreateDecryptor();

        var decrypted = new byte[16];
        var input = authId.ToArray();
        var written = decryptor.TransformBlock(input, 0, input.Length, decrypted, 0);
        if (written != decrypted.Length)
        {
            throw new InvalidDataException("VMess auth id decryption failed.");
        }

        return decrypted;
    }

    private static AuthIdValidationResult ValidateAuthId(ReadOnlySpan<byte> decryptedAuthId)
    {
        if (decryptedAuthId.Length != 16)
        {
            return AuthIdValidationResult.InvalidChecksum;
        }

        var timestamp = BinaryPrimitives.ReadInt64BigEndian(decryptedAuthId[..8]);
        if (timestamp < 0)
        {
            return AuthIdValidationResult.NegativeTime;
        }

        var checksum = BinaryPrimitives.ReadUInt32BigEndian(decryptedAuthId.Slice(12, 4));
        if (checksum != ComputeCrc32(decryptedAuthId[..12]))
        {
            return AuthIdValidationResult.InvalidChecksum;
        }

        var delta = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp);
        return delta <= AuthIdToleranceSeconds
            ? AuthIdValidationResult.Valid
            : AuthIdValidationResult.InvalidTime;
    }

    private static UnauthorizedAccessException CreateInvalidUserException(Exception? inner)
        => inner is null
            ? new UnauthorizedAccessException(VmessEncodingErrorPrefix + "invalid user")
            : new UnauthorizedAccessException(VmessEncodingErrorPrefix + "invalid user", inner);

    private static VmessSecurityType ParseSecurityType(byte value)
        => value switch
        {
            (byte)VmessSecurityType.Unknown => VmessSecurityType.Auto,
            (byte)VmessSecurityType.Auto => VmessSecurityType.Auto,
            (byte)VmessSecurityType.Aes128Gcm => VmessSecurityType.Aes128Gcm,
            (byte)VmessSecurityType.ChaCha20Poly1305 => VmessSecurityType.ChaCha20Poly1305,
            (byte)VmessSecurityType.None => VmessSecurityType.None,
            _ => VmessSecurityType.Unknown
        };

    private static byte[] DecryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> encrypted,
        ReadOnlySpan<byte> additionalData)
    {
        if (encrypted.Length < AeadTagLength)
        {
            throw new InvalidDataException("VMess AEAD payload is truncated.");
        }

        var ciphertextLength = encrypted.Length - AeadTagLength;
        var plaintext = new byte[ciphertextLength];
        using var aead = new AesGcm(key.ToArray(), AeadTagLength);
        aead.Decrypt(
            nonce,
            encrypted[..ciphertextLength],
            encrypted[ciphertextLength..],
            plaintext,
            additionalData);
        return plaintext;
    }

    private static byte[] EncryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> additionalData)
    {
        var output = new byte[plaintext.Length + AeadTagLength];
        using var aead = new AesGcm(key.ToArray(), AeadTagLength);
        aead.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, AeadTagLength),
            additionalData);
        return output;
    }

    private static uint ComputeFnv1a(ReadOnlySpan<byte> data)
    {
        const uint offsetBasis = 2166136261;
        const uint prime = 16777619;

        var hash = offsetBasis;
        foreach (var value in data)
        {
            hash ^= value;
            hash *= prime;
        }

        return hash;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0
                    ? (crc >> 1) ^ 0xEDB88320u
                    : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }

    private enum AuthIdValidationResult
    {
        InvalidChecksum = 0,
        NegativeTime = 1,
        InvalidTime = 2,
        Valid = 3
    }
}

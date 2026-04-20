using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Globalization;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class RealityInboundConnectionAcceptor
{
    private static readonly RuntimeFallbackRelayService FallbackRelayService = new(new RelayService());

    public static async Task<TlsAcceptedConnectionContext?> AcceptAsync(
        AcceptedConnection connection,
        RuntimeRealityServerOptions realityOptions,
        bool acceptProxyProtocol,
        bool receiveOriginalDestination,
        IReadOnlyList<string> applicationProtocols,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<EndPoint?>? onEffectiveRemoteEndPointChanged,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(realityOptions);
        ArgumentNullException.ThrowIfNull(applicationProtocols);

        var preparedConnection = await AcceptedInboundConnectionPreprocessor
            .PrepareAsync(
                connection,
                acceptProxyProtocol,
                receiveOriginalDestination,
                onEffectiveRemoteEndPointChanged,
                cancellationToken)
            .ConfigureAwait(false);

        var acceptor = new RuntimeRealityTls13ServerAcceptor(
            preparedConnection.Stream,
            RuntimeRealityInboundServerProfile.Create(realityOptions),
            applicationProtocols,
            FallbackRelayService);
        var accepted = await acceptor.AcceptAsync(
                connection,
                preparedConnection,
                onClientHelloRejected,
                onUnknownServerNameRejected,
                cancellationToken)
            .ConfigureAwait(false);
        if (accepted is null)
        {
            return null;
        }

        return new TlsAcceptedConnectionContext
        {
            Stream = accepted.Stream,
            RemoteEndPoint = preparedConnection.RemoteEndPoint,
            LocalEndPoint = preparedConnection.LocalEndPoint,
            OriginalDestinationEndPoint = preparedConnection.OriginalDestinationEndPoint,
            ServerName = accepted.ServerName,
            NegotiatedAlpn = accepted.NegotiatedAlpn,
            NegotiatedSslProtocol = SslProtocols.Tls13
        };
    }
}

internal sealed class RuntimeRealityTls13ServerAcceptor
{
    private readonly Stream _transportStream;
    private readonly RuntimeRealityInboundServerProfile _profile;
    private readonly IReadOnlyList<string> _applicationProtocols;
    private readonly RuntimeFallbackRelayService _fallbackRelayService;

    public RuntimeRealityTls13ServerAcceptor(
        Stream transportStream,
        RuntimeRealityInboundServerProfile profile,
        IReadOnlyList<string> applicationProtocols,
        RuntimeFallbackRelayService fallbackRelayService)
    {
        _transportStream = transportStream ?? throw new ArgumentNullException(nameof(transportStream));
        _profile = profile ?? throw new ArgumentNullException(nameof(profile));
        _applicationProtocols = applicationProtocols ?? throw new ArgumentNullException(nameof(applicationProtocols));
        _fallbackRelayService = fallbackRelayService ?? throw new ArgumentNullException(nameof(fallbackRelayService));
    }

    public Task<RuntimeRealityAcceptedConnection?> AcceptAsync(
        AcceptedConnection connection,
        PreparedAcceptedConnectionContext preparedConnection,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        CancellationToken cancellationToken)
        => AcceptCoreAsync(
            connection,
            preparedConnection,
            onClientHelloRejected,
            onUnknownServerNameRejected,
            cancellationToken);

    private async Task<RuntimeRealityAcceptedConnection?> AcceptCoreAsync(
        AcceptedConnection connection,
        PreparedAcceptedConnectionContext preparedConnection,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(preparedConnection);

        var clientHelloRecord = await RuntimeTlsClientHelloReader
            .ReadAsync(_transportStream, cancellationToken)
            .ConfigureAwait(false);
        if (clientHelloRecord.Length == 0)
        {
            return null;
        }

        RuntimeTlsClientHelloMetadata? clientHelloMetadata = null;
        if (RuntimeTlsClientHelloParser.TryParse(clientHelloRecord, out var parsedClientHelloMetadata))
        {
            clientHelloMetadata = parsedClientHelloMetadata;
        }

        if (RuntimeTlsClientHelloPolicyEvaluator.ShouldReject(
                _profile.ClientHelloPolicy,
                clientHelloMetadata,
                out var policyDecision))
        {
            InboundServerRuntimeSupport.InvokeSafely(
                onClientHelloRejected,
                new RuntimeTlsClientHelloRejectionContext
                {
                    RemoteEndPoint = connection.LogRemoteEndPoint ?? preparedConnection.RemoteEndPoint,
                    Metadata = clientHelloMetadata,
                    Reason = policyDecision.Reason
                });

            if (await TryHandleFallbackAsync(clientHelloRecord, preparedConnection, cancellationToken).ConfigureAwait(false))
            {
                return null;
            }

            return null;
        }

        var requestedServerName = ResolveRequestedServerName(clientHelloMetadata);
        if (!IsAllowedServerName(requestedServerName))
        {
            InboundServerRuntimeSupport.InvokeSafely(
                onUnknownServerNameRejected,
                new RuntimeTlsServerNameRejectionContext
                {
                    RemoteEndPoint = connection.LogRemoteEndPoint ?? preparedConnection.RemoteEndPoint,
                    RequestedServerName = requestedServerName
                });

            if (await TryHandleFallbackAsync(clientHelloRecord, preparedConnection, cancellationToken).ConfigureAwait(false))
            {
                return null;
            }

            return null;
        }

        RuntimeRealityClientHelloDocument hello;
        RuntimeRealityAuthenticatedClient authenticatedClient = null!;
        RuntimeTls13CipherSuite cipherSuite = null!;
        RuntimeRealityTls13ServerHandshakeState handshakeState = null!;
        string negotiatedAlpn = string.Empty;
        var fallbackAllowed = true;
        var initialClientHelloMessage = clientHelloRecord.AsSpan(5).ToArray();
        var currentClientHelloMessage = initialClientHelloMessage;
        byte[]? helloRetryRequestMessage = null;
        try
        {
            if (!RuntimeRealityClientHelloDocument.TryParse(clientHelloRecord, out var parsedHello, out var error) ||
                parsedHello is null)
            {
                throw new AuthenticationException(
                    string.IsNullOrWhiteSpace(error)
                        ? "REALITY inbound client hello is invalid."
                        : error);
            }

            hello = parsedHello;

            if (!hello.SupportsTls13)
            {
                throw new AuthenticationException("REALITY inbound requires a TLS 1.3 ClientHello.");
            }

            var remoteAddress = connection.LogRemoteEndPoint?.ToString() ??
                                preparedConnection.RemoteEndPoint?.ToString() ??
                                "unknown";
            authenticatedClient = AuthenticateClientHello(hello, remoteAddress);
            RuntimeRealityDebugLogger.TryWriteLine(
                _profile.Show,
                $"REALITY remoteAddr: {remoteAddress}\ths.c.AuthKey[:16]: {RuntimeRealityDebugLogger.FormatHexPrefix(authenticatedClient.AuthKey, 16)}\tAEAD: {nameof(AesGcm)}");
            RuntimeRealityDebugLogger.TryWriteLine(
                _profile.Show,
                $"REALITY remoteAddr: {remoteAddress}\ths.c.ClientVer: {FormatClientVersion(authenticatedClient.PlainSessionId)}");
            RuntimeRealityDebugLogger.TryWriteLine(
                _profile.Show,
                $"REALITY remoteAddr: {remoteAddress}\ths.c.ClientTime: {FormatClientTimestamp(authenticatedClient.PlainSessionId)}");
            RuntimeRealityDebugLogger.TryWriteLine(
                _profile.Show,
                $"REALITY remoteAddr: {remoteAddress}\ths.c.ClientShortId: {FormatClientShortId(authenticatedClient.PlainSessionId)}");
            cipherSuite = ResolveCipherSuite(hello.CipherSuites);
            negotiatedAlpn = ResolveNegotiatedApplicationProtocol(clientHelloMetadata?.ApplicationProtocols);

            var handshakeSelection = SelectServerHandshake(hello);
            if (handshakeSelection.HandshakeState is not null)
            {
                handshakeState = handshakeSelection.HandshakeState;
            }
            else
            {
                var helloRetryRequestCookiePayload =
                    BuildHelloRetryRequestCookieExtensionPayload(RandomNumberGenerator.GetBytes(32));
                var helloRetryRequestRecord = BuildHelloRetryRequest(
                    hello.SessionId,
                    handshakeSelection.SelectedGroup,
                    cipherSuite.Id,
                    helloRetryRequestCookiePayload);
                helloRetryRequestMessage = helloRetryRequestRecord.AsSpan(5).ToArray();

                fallbackAllowed = false;
                await _transportStream.WriteAsync(
                        helloRetryRequestRecord.AsMemory(0, helloRetryRequestRecord.Length),
                        cancellationToken)
                    .ConfigureAwait(false);
                await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

                var retryClientHelloRecord = await ReadHelloRetryRequestClientHelloAsync(
                        hello.RecordVersion,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (!RuntimeRealityClientHelloDocument.TryParse(
                        retryClientHelloRecord,
                        out var retryHello,
                        out var retryError) ||
                    retryHello is null)
                {
                    throw new AuthenticationException(
                        string.IsNullOrWhiteSpace(retryError)
                            ? "REALITY inbound retry client hello is invalid."
                            : retryError);
                }

                ValidateHelloRetryRequestClientHello(
                    hello,
                    retryHello,
                    handshakeSelection.SelectedGroup,
                    helloRetryRequestCookiePayload);
                if (!TryCreateServerHandshakeState(
                        handshakeSelection.SelectedGroup,
                        ParseKeyShares(retryHello),
                        out var retryHandshakeState) ||
                    retryHandshakeState is null)
                {
                    throw new AuthenticationException(
                        $"REALITY inbound retry client hello did not include the requested key share group 0x{handshakeSelection.SelectedGroup:X4}.");
                }

                handshakeState = retryHandshakeState;
                hello = retryHello;
                currentClientHelloMessage = retryClientHelloRecord.AsSpan(5).ToArray();
            }
        }
        catch (Exception ex) when (fallbackAllowed && IsFallbackEligibleException(ex))
        {
            if (await TryHandleFallbackAsync(clientHelloRecord, preparedConnection, cancellationToken).ConfigureAwait(false))
            {
                return null;
            }

            throw;
        }

        var serverHelloRecord = BuildServerHello(
            hello.SessionId,
            handshakeState.SelectedGroup,
            cipherSuite.Id,
            handshakeState.ServerKeyShare);
        var serverHelloMessage = serverHelloRecord.AsSpan(5).ToArray();

        var transcript = new RuntimeTls13HandshakeTranscript();
        transcript.Append(initialClientHelloMessage);
        if (helloRetryRequestMessage is not null)
        {
            transcript.ReplaceClientHelloWithMessageHashAndAppendHelloRetryRequest(
                cipherSuite.HashAlgorithm,
                helloRetryRequestMessage);
            transcript.Append(currentClientHelloMessage);
        }
        transcript.Append(serverHelloMessage);

        var keySchedule = RuntimeTls13KeySchedule.Create(
            cipherSuite,
            handshakeState.SharedSecret,
            transcript.GetHash(cipherSuite.HashAlgorithm));

        var certificateMaterial = CreateSyntheticCertificate(
            authenticatedClient.AuthKey,
            currentClientHelloMessage,
            serverHelloMessage);

        var encryptedExtensions = BuildEncryptedExtensions(negotiatedAlpn);
        transcript.Append(encryptedExtensions);

        var certificateMessage = BuildCertificate(certificateMaterial.RawCertificate);
        transcript.Append(certificateMessage);

        var certificateVerify = BuildCertificateVerify(
            0x0807,
            RuntimeEd25519.Sign(
                certificateMaterial.Ed25519PrivateKey,
                BuildCertificateVerifyData(
                    "TLS 1.3, server CertificateVerify",
                    transcript.GetHash(cipherSuite.HashAlgorithm))));
        transcript.Append(certificateVerify);

        var finished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ServerHandshakeTrafficSecret,
            transcript.GetHash(cipherSuite.HashAlgorithm),
            cipherSuite);
        transcript.Append(finished);

        using var serverHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            cipherSuite,
            keySchedule.ServerHandshakeTrafficSecret);
        using var clientHandshakeProtector = RuntimeTls13TrafficProtector.Create(
            cipherSuite,
            keySchedule.ClientHandshakeTrafficSecret);

        await _transportStream.WriteAsync(serverHelloRecord.AsMemory(0, serverHelloRecord.Length), cancellationToken).ConfigureAwait(false);
        await WriteCompatibilityChangeCipherSpecAsync(cancellationToken).ConfigureAwait(false);
        await WriteEncryptedHandshakeAsync(serverHandshakeProtector, encryptedExtensions, cancellationToken).ConfigureAwait(false);
        await WriteEncryptedHandshakeAsync(serverHandshakeProtector, certificateMessage, cancellationToken).ConfigureAwait(false);
        await WriteEncryptedHandshakeAsync(serverHandshakeProtector, certificateVerify, cancellationToken).ConfigureAwait(false);
        await WriteEncryptedHandshakeAsync(serverHandshakeProtector, finished, cancellationToken).ConfigureAwait(false);

        var expectedClientFinished = RuntimeTls13KeySchedule.CreateFinishedMessage(
            keySchedule.ClientHandshakeTrafficSecret,
            transcript.GetHash(cipherSuite.HashAlgorithm),
            cipherSuite);
        var applicationSecrets = keySchedule.CreateApplicationSecrets(
            transcript.GetHash(cipherSuite.HashAlgorithm));
        var clientFinished = await ReadEncryptedHandshakeMessageAsync(
                clientHandshakeProtector,
                cancellationToken)
            .ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(expectedClientFinished, clientFinished))
        {
            throw new AuthenticationException("REALITY inbound TLS 1.3 client Finished verification failed.");
        }

        transcript.Append(clientFinished);
        var applicationReadProtector = RuntimeTls13TrafficProtector.Create(
            cipherSuite,
            applicationSecrets.ClientApplicationTrafficSecret);
        var applicationWriteProtector = RuntimeTls13TrafficProtector.Create(
            cipherSuite,
            applicationSecrets.ServerApplicationTrafficSecret);
        RuntimeTlsKeyLogWriter.TryAppendTls13Secrets(
            _profile.MasterKeyLog,
            hello.Random,
            keySchedule.ClientHandshakeTrafficSecret,
            keySchedule.ServerHandshakeTrafficSecret,
            applicationSecrets.ClientApplicationTrafficSecret,
            applicationSecrets.ServerApplicationTrafficSecret,
            _profile.Show);
        var securedStream = new RuntimeTls13DuplexStream(
            _transportStream,
            applicationReadProtector,
            applicationWriteProtector);

        return new RuntimeRealityAcceptedConnection(
            securedStream,
            requestedServerName,
            negotiatedAlpn);
    }

    private static bool IsFallbackEligibleException(Exception exception)
        => exception is AuthenticationException or CryptographicException;

    private async Task<bool> TryHandleFallbackAsync(
        byte[] initialPayload,
        PreparedAcceptedConnectionContext preparedConnection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(initialPayload);
        ArgumentNullException.ThrowIfNull(preparedConnection);

        if (_profile.Fallback is null)
        {
            return false;
        }

        var options = new RuntimeRealityFallbackConnectionOptions(
            preparedConnection.RemoteEndPoint,
            preparedConnection.LocalEndPoint,
            preparedConnection.OriginalDestinationEndPoint,
            _profile.Fallback);
        return await _fallbackRelayService
            .TryHandleAsync(
                _transportStream,
                initialPayload,
                options,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private sealed record RuntimeRealityFallbackConnectionOptions(
        EndPoint? RemoteEndPoint,
        EndPoint? LocalEndPoint,
        EndPoint? OriginalDestinationEndPoint,
        RuntimeRealityInboundFallbackProfile FallbackProfile) : IRuntimeFallbackConnectionOptions
    {
        public string InboundTag => string.Empty;

        public int HandshakeTimeoutSeconds => 60;

        public int ConnectTimeoutSeconds => 10;

        public int ConnectionIdleSeconds => 300;

        public int UplinkOnlySeconds => 1;

        public int DownlinkOnlySeconds => 1;

        public bool UseCone => true;

        public bool ReceiveOriginalDestination => false;

        public string ServerName => string.Empty;

        public string Alpn => string.Empty;

        public IRuntimeSniffingDefinition Sniffing => RuntimeSniffingOptions.Disabled;

        public IReadOnlyList<IRuntimeFallbackDefinition> Fallbacks => new IRuntimeFallbackDefinition[]
        {
            new RuntimeRealityFallbackDefinition(FallbackProfile)
        };
    }

    private sealed record RuntimeRealityFallbackDefinition(RuntimeRealityInboundFallbackProfile Profile) : IRuntimeFallbackDefinition
    {
        public string Name => string.Empty;

        public string Alpn => string.Empty;

        public string Path => string.Empty;

        public string Type => Profile.Type;

        public string Dest => Profile.Destination;

        public int ProxyProtocolVersion => Profile.ProxyProtocolVersion;
    }

    private sealed record RuntimeRealityAuthenticatedClient(
        byte[] AuthKey,
        byte[] PlainSessionId);

    private sealed record RuntimeRealityTls13ServerHandshakeSelection(
        ushort SelectedGroup,
        RuntimeRealityTls13ServerHandshakeState? HandshakeState);

    private sealed record RuntimeRealitySyntheticCertificateMaterial(
        byte[] Ed25519PrivateKey,
        byte[] RawCertificate);

    private string ResolveRequestedServerName(RuntimeTlsClientHelloMetadata? metadata)
        => metadata?.ServerName ?? string.Empty;

    private bool IsAllowedServerName(string requestedServerName)
    {
        if (requestedServerName.Length == 0)
        {
            return false;
        }

        foreach (var allowedServerName in _profile.ServerNames)
        {
            if (string.Equals(requestedServerName, allowedServerName, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private string ResolveNegotiatedApplicationProtocol(IReadOnlyList<string>? clientApplicationProtocols)
    {
        if (_applicationProtocols.Count == 0)
        {
            return string.Empty;
        }

        if (clientApplicationProtocols is null || clientApplicationProtocols.Count == 0)
        {
            throw new AuthenticationException("REALITY inbound client hello did not advertise ALPN.");
        }

        foreach (var serverProtocol in _applicationProtocols)
        {
            if (string.IsNullOrWhiteSpace(serverProtocol))
            {
                continue;
            }

            foreach (var clientProtocol in clientApplicationProtocols)
            {
                if (string.Equals(
                        serverProtocol.Trim(),
                        clientProtocol?.Trim(),
                        StringComparison.OrdinalIgnoreCase))
                {
                    return serverProtocol.Trim().ToLowerInvariant();
                }
            }
        }

        throw new AuthenticationException("REALITY inbound client hello did not advertise a compatible ALPN.");
    }

    private RuntimeRealityAuthenticatedClient AuthenticateClientHello(
        RuntimeRealityClientHelloDocument hello,
        string remoteAddress)
    {
        if (hello.X25519PublicKey is null)
        {
            throw new AuthenticationException("REALITY inbound client hello is missing an X25519 key share.");
        }

        if (hello.SessionId.Length != RuntimeRealityClientHelloProtector.EncryptedSessionIdLength)
        {
            throw new AuthenticationException("REALITY inbound client hello session ID length is invalid.");
        }

        var zeroSessionIdClientHello = hello.Write(
            new byte[RuntimeRealityClientHelloProtector.EncryptedSessionIdLength]);
        var sharedSecret = RuntimeX25519.DeriveSharedSecret(_profile.PrivateKey, hello.X25519PublicKey);
        var authKey = RuntimeHkdf.ExtractAndExpandSha256(
            sharedSecret,
            hello.Random.AsSpan(0, 20),
            "REALITY"u8,
            RuntimeX25519.KeyLength);
        RuntimeRealityDebugLogger.TryWriteLine(
            _profile.Show,
            $"REALITY remoteAddr: {remoteAddress}\ths.c.AuthKey[:16]: {RuntimeRealityDebugLogger.FormatHexPrefix(authKey, 16)}\tAEAD: {nameof(AesGcm)}");
        var plainSessionId = DecryptSessionId(
            authKey,
            hello.Random.AsSpan(20, 12),
            hello.SessionId,
            zeroSessionIdClientHello.AsSpan(5));

        ValidateClientVersion(plainSessionId.AsSpan(0, 3));
        ValidateClientTimestamp(plainSessionId.AsSpan(4, 4));
        ValidateShortId(plainSessionId.AsSpan(8, 8));

        return new RuntimeRealityAuthenticatedClient(authKey, plainSessionId);
    }

    private static byte[] DecryptSessionId(
        ReadOnlySpan<byte> authKey,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> encryptedSessionId,
        ReadOnlySpan<byte> associatedData)
    {
        var plaintext = new byte[RuntimeRealityClientHelloProtector.PlainSessionIdLength];
        using var aead = new AesGcm(
            authKey.ToArray(),
            RuntimeRealityClientHelloProtector.EncryptedSessionIdLength - RuntimeRealityClientHelloProtector.PlainSessionIdLength);
        aead.Decrypt(
            nonce,
            encryptedSessionId[..RuntimeRealityClientHelloProtector.PlainSessionIdLength],
            encryptedSessionId[RuntimeRealityClientHelloProtector.PlainSessionIdLength..],
            plaintext,
            associatedData);
        return plaintext;
    }

    private void ValidateClientVersion(ReadOnlySpan<byte> clientVersion)
    {
        if (_profile.MinClientVersion.Length > 0 &&
            CompareClientVersions(clientVersion, _profile.MinClientVersion) < 0)
        {
            throw new AuthenticationException("REALITY inbound client version is below the configured minimum.");
        }

        if (_profile.MaxClientVersion.Length > 0 &&
            CompareClientVersions(clientVersion, _profile.MaxClientVersion) > 0)
        {
            throw new AuthenticationException("REALITY inbound client version is above the configured maximum.");
        }
    }

    private void ValidateClientTimestamp(ReadOnlySpan<byte> unixSeconds)
    {
        if (_profile.MaxTimeDiffMilliseconds <= 0)
        {
            return;
        }

        var clientUnixSeconds = BinaryPrimitives.ReadUInt32BigEndian(unixSeconds);
        var clientUnixMilliseconds = checked((long)clientUnixSeconds * 1000L);
        var diff = Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - clientUnixMilliseconds);
        if (diff > _profile.MaxTimeDiffMilliseconds)
        {
            throw new AuthenticationException("REALITY inbound client timestamp exceeded the configured maxTimeDiff.");
        }
    }

    private static string FormatClientVersion(ReadOnlySpan<byte> plainSessionId)
    {
        if (plainSessionId.Length < 3)
        {
            return "invalid";
        }

        return $"[{plainSessionId[0]} {plainSessionId[1]} {plainSessionId[2]}]";
    }

    private static string FormatClientTimestamp(ReadOnlySpan<byte> plainSessionId)
    {
        if (plainSessionId.Length < 8)
        {
            return "invalid";
        }

        var seconds = BinaryPrimitives.ReadUInt32BigEndian(plainSessionId.Slice(4, 4));
        return DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ");
    }

    private static string FormatClientShortId(ReadOnlySpan<byte> plainSessionId)
    {
        if (plainSessionId.Length < 16)
        {
            return "invalid";
        }

        return Convert.ToHexString(plainSessionId.Slice(8, 8));
    }

    private void ValidateShortId(ReadOnlySpan<byte> shortId)
    {
        foreach (var allowedShortId in _profile.ShortIds)
        {
            if (CryptographicOperations.FixedTimeEquals(shortId, allowedShortId))
            {
                return;
            }
        }

        throw new AuthenticationException("REALITY inbound short ID is not allowed.");
    }

    private static int CompareClientVersions(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        for (var index = 0; index < 3; index++)
        {
            var leftPart = index < left.Length ? left[index] : (byte)0;
            var rightPart = index < right.Length ? right[index] : (byte)0;
            if (leftPart == rightPart)
            {
                continue;
            }

            return leftPart < rightPart ? -1 : 1;
        }

        return 0;
    }

    private static RuntimeTls13CipherSuite ResolveCipherSuite(byte[] cipherSuites)
    {
        for (var index = 0; index + 1 < cipherSuites.Length; index += 2)
        {
            var cipherSuiteId = BinaryPrimitives.ReadUInt16BigEndian(cipherSuites.AsSpan(index, 2));
            try
            {
                return RuntimeTls13CipherSuite.Resolve(cipherSuiteId);
            }
            catch (NotSupportedException)
            {
            }
        }

        throw new AuthenticationException("REALITY inbound client hello did not advertise a supported TLS 1.3 cipher suite.");
    }

    private static RuntimeRealityTls13ServerHandshakeSelection SelectServerHandshake(
        RuntimeRealityClientHelloDocument hello)
    {
        ArgumentNullException.ThrowIfNull(hello);

        var keyShares = ParseKeyShares(hello);
        foreach (var preferredGroup in RuntimeTls13KeyShareNegotiation.PreferredServerGroups)
        {
            if (!RuntimeTls13KeyShareNegotiation.IsRuntimeSupported(preferredGroup))
            {
                continue;
            }

            if (TryCreateServerHandshakeState(preferredGroup, keyShares, out var handshakeState) &&
                handshakeState is not null)
            {
                return new RuntimeRealityTls13ServerHandshakeSelection(preferredGroup, handshakeState);
            }

            if (ContainsNamedGroup(hello.SupportedGroups, preferredGroup))
            {
                return new RuntimeRealityTls13ServerHandshakeSelection(preferredGroup, null);
            }
        }

        throw new AuthenticationException("REALITY inbound client hello did not advertise a supported key share.");
    }

    private static IReadOnlyList<RuntimeTls13KeyShareEntry> ParseKeyShares(RuntimeRealityClientHelloDocument hello)
    {
        var keyShareExtension = hello.Extensions
            .FirstOrDefault(static extension => extension.Type == 0x0033);
        if (keyShareExtension is null)
        {
            return Array.Empty<RuntimeTls13KeyShareEntry>();
        }

        var payload = keyShareExtension.Payload;
        if (payload.Length < 2)
        {
            return Array.Empty<RuntimeTls13KeyShareEntry>();
        }

        var length = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(0, 2));
        var cursor = 2;
        var end = Math.Min(payload.Length, cursor + length);
        var entries = new List<RuntimeTls13KeyShareEntry>();
        while (cursor + 4 <= end)
        {
            var group = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(cursor, 2));
            var keyExchangeLength = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(cursor + 2, 2));
            cursor += 4;
            if (cursor + keyExchangeLength > end)
            {
                break;
            }

            entries.Add(new RuntimeTls13KeyShareEntry(
                group,
                payload.AsSpan(cursor, keyExchangeLength).ToArray()));
            cursor += keyExchangeLength;
        }

        return entries;
    }

    private static bool TryCreateServerHandshakeState(
        ushort selectedGroup,
        IReadOnlyList<RuntimeTls13KeyShareEntry> keyShares,
        out RuntimeRealityTls13ServerHandshakeState? handshakeState)
    {
        foreach (var keyShare in keyShares)
        {
            if (keyShare.Group != selectedGroup)
            {
                continue;
            }

            handshakeState = CreateServerHandshakeState(selectedGroup, keyShare.KeyExchange);
            return true;
        }

        handshakeState = null;
        return false;
    }

    private static RuntimeRealityTls13ServerHandshakeState CreateServerHandshakeState(
        ushort selectedGroup,
        ReadOnlySpan<byte> keyExchange)
    {
        switch (selectedGroup)
        {
            case RuntimeTlsNamedGroups.X25519:
                using (var keyPair = RuntimeX25519.CreateKeyPair())
                {
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        keyPair.PublicKey.ToArray(),
                        RuntimeX25519.DeriveSharedSecret(keyPair.PrivateKey, keyExchange));
                }
            case RuntimeTlsNamedGroups.X25519Kyber768Draft00 when RuntimeX25519Kyber768Draft00.IsSupported:
                {
                    var exchange = RuntimeX25519Kyber768Draft00.Encapsulate(keyExchange);
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case RuntimeTlsNamedGroups.X25519MLKem768 when RuntimeX25519MlKem768.IsSupported:
                {
                    var exchange = RuntimeX25519MlKem768.Encapsulate(keyExchange);
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case RuntimeTlsNamedGroups.Secp256r1MLKem768 when RuntimeSecp256r1MlKem768.IsSupported:
                {
                    var exchange = RuntimeSecp256r1MlKem768.Encapsulate(keyExchange);
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case RuntimeTlsNamedGroups.Secp256r1:
                using (var keyPair = RuntimeSecp256r1.CreateKeyPair())
                {
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        keyPair.PublicKey.ToArray(),
                        RuntimeSecp256r1.DeriveSharedSecret(keyPair.PrivateKey, keyExchange));
                }
            case RuntimeTlsNamedGroups.Secp384r1MLKem1024 when RuntimeSecp384r1MlKem1024.IsSupported:
                {
                    var exchange = RuntimeSecp384r1MlKem1024.Encapsulate(keyExchange);
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        exchange.ServerKeyShare,
                        exchange.SharedSecret);
                }
            case RuntimeTlsNamedGroups.Secp384r1:
                using (var keyPair = RuntimeSecp384r1.CreateKeyPair())
                {
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        keyPair.PublicKey.ToArray(),
                        RuntimeSecp384r1.DeriveSharedSecret(keyPair.PrivateKey, keyExchange));
                }
            case RuntimeTlsNamedGroups.Secp521r1:
                using (var keyPair = RuntimeSecp521r1.CreateKeyPair())
                {
                    return new RuntimeRealityTls13ServerHandshakeState(
                        selectedGroup,
                        keyPair.PublicKey.ToArray(),
                        RuntimeSecp521r1.DeriveSharedSecret(keyPair.PrivateKey, keyExchange));
                }
            default:
                throw new AuthenticationException(
                    $"REALITY inbound client hello selected unsupported key share group 0x{selectedGroup:X4}.");
        }
    }

    private static bool ContainsNamedGroup(IReadOnlyList<ushort> groups, ushort group)
    {
        foreach (var candidate in groups)
        {
            if (candidate == group)
            {
                return true;
            }
        }

        return false;
    }

    private RuntimeRealitySyntheticCertificateMaterial CreateSyntheticCertificate(
        byte[] authKey,
        byte[] clientHelloMessage,
        byte[] serverHelloMessage)
    {
        var ed25519PrivateKey = RandomNumberGenerator.GetBytes(RuntimeEd25519.PrivateKeyLength);
        var ed25519PublicKey = RuntimeEd25519.DerivePublicKey(ed25519PrivateKey);
        var certificateSignature = HMACSHA512.HashData(authKey, ed25519PublicKey);
        var extensions = CreateSyntheticCertificateExtensions(
            authKey,
            ed25519PublicKey,
            clientHelloMessage,
            serverHelloMessage);
        return new RuntimeRealitySyntheticCertificateMaterial(
            ed25519PrivateKey,
            RuntimeRealitySyntheticCertificateFactory.CreateEd25519Certificate(
                ed25519PublicKey,
                certificateSignature,
                extensions));
    }

    private IReadOnlyList<X509Extension> CreateSyntheticCertificateExtensions(
        byte[] authKey,
        byte[] ed25519PublicKey,
        byte[] clientHelloMessage,
        byte[] serverHelloMessage)
    {
        if (_profile.Mldsa65Seed is null)
        {
            return Array.Empty<X509Extension>();
        }

        if (!MLDsa.IsSupported)
        {
            throw new NotSupportedException("REALITY inbound ML-DSA-65 is not supported on the current .NET runtime.");
        }

        using var mldsa = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, _profile.Mldsa65Seed);
        var signature = mldsa.SignData(
            BuildMldsa65Payload(
                authKey,
                ed25519PublicKey,
                clientHelloMessage,
                serverHelloMessage),
            Array.Empty<byte>());
        return
        [
            new X509Extension(new Oid("1.3.6.1.4.1.55555.1"), signature, critical: false)
        ];
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

    private static byte[] BuildServerHello(
        ReadOnlySpan<byte> sessionId,
        ushort selectedGroup,
        ushort cipherSuite,
        ReadOnlySpan<byte> serverKeyShare)
    {
        using var extensions = new MemoryStream();
        WriteUInt16(extensions, 0x002B);
        WriteUInt16(extensions, 0x0002);
        WriteUInt16(extensions, 0x0304);

        using var keySharePayload = new MemoryStream();
        WriteUInt16(keySharePayload, selectedGroup);
        WriteUInt16(keySharePayload, checked((ushort)serverKeyShare.Length));
        keySharePayload.Write(serverKeyShare);
        var keyShareBytes = keySharePayload.ToArray();
        WriteUInt16(extensions, 0x0033);
        WriteUInt16(extensions, checked((ushort)keyShareBytes.Length));
        extensions.Write(keyShareBytes);

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, 0x0303);
        body.Write(Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray());
        body.WriteByte(checked((byte)sessionId.Length));
        if (sessionId.Length > 0)
        {
            body.Write(sessionId);
        }

        WriteUInt16(body, cipherSuite);
        body.WriteByte(0x00);
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        body.Write(extensionBytes);

        return BuildHandshakeRecord(RuntimeTls13HandshakeType.ServerHello, body.ToArray());
    }

    private static byte[] BuildHelloRetryRequest(
        ReadOnlySpan<byte> sessionId,
        ushort selectedGroup,
        ushort cipherSuite,
        ReadOnlySpan<byte> cookieExtensionPayload)
    {
        using var extensions = new MemoryStream();
        WriteUInt16(extensions, 0x002B);
        WriteUInt16(extensions, 0x0002);
        WriteUInt16(extensions, 0x0304);

        if (cookieExtensionPayload.Length > 0)
        {
            WriteUInt16(extensions, 0x002C);
            WriteUInt16(extensions, checked((ushort)cookieExtensionPayload.Length));
            extensions.Write(cookieExtensionPayload);
        }

        if (selectedGroup != 0)
        {
            WriteUInt16(extensions, 0x0033);
            WriteUInt16(extensions, 0x0002);
            WriteUInt16(extensions, selectedGroup);
        }

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, 0x0303);
        body.Write(RuntimeTls13ServerHello.HelloRetryRequestRandomBytes);
        body.WriteByte(checked((byte)sessionId.Length));
        if (sessionId.Length > 0)
        {
            body.Write(sessionId);
        }

        WriteUInt16(body, cipherSuite);
        body.WriteByte(0x00);
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        body.Write(extensionBytes);
        return BuildHandshakeRecord(RuntimeTls13HandshakeType.ServerHello, body.ToArray());
    }

    private static byte[] BuildHelloRetryRequestCookieExtensionPayload(ReadOnlySpan<byte> cookie)
    {
        if (cookie.Length == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(cookie), "TLS 1.3 HelloRetryRequest cookie cannot be empty.");
        }

        var payload = new byte[2 + cookie.Length];
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(0, 2), checked((ushort)cookie.Length));
        cookie.CopyTo(payload.AsSpan(2));
        return payload;
    }

    private static byte[] BuildEncryptedExtensions(string negotiatedApplicationProtocol)
    {
        using var extensions = new MemoryStream();
        if (!string.IsNullOrWhiteSpace(negotiatedApplicationProtocol))
        {
            var protocolBytes = Encoding.ASCII.GetBytes(negotiatedApplicationProtocol.Trim());
            using var alpnPayload = new MemoryStream();
            WriteUInt16(alpnPayload, checked((ushort)(protocolBytes.Length + 1)));
            alpnPayload.WriteByte(checked((byte)protocolBytes.Length));
            alpnPayload.Write(protocolBytes);
            var alpnBytes = alpnPayload.ToArray();

            WriteUInt16(extensions, 0x0010);
            WriteUInt16(extensions, checked((ushort)alpnBytes.Length));
            extensions.Write(alpnBytes);
        }

        var extensionBytes = extensions.ToArray();
        using var body = new MemoryStream();
        WriteUInt16(body, checked((ushort)extensionBytes.Length));
        body.Write(extensionBytes);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.EncryptedExtensions, body.ToArray());
    }

    private static byte[] BuildCertificate(ReadOnlySpan<byte> rawCertificate)
    {
        using var certificateEntry = new MemoryStream();
        WriteUInt24(certificateEntry, rawCertificate.Length);
        certificateEntry.Write(rawCertificate);
        WriteUInt16(certificateEntry, 0);
        var certificateEntryBytes = certificateEntry.ToArray();

        using var body = new MemoryStream();
        body.WriteByte(0x00);
        WriteUInt24(body, certificateEntryBytes.Length);
        body.Write(certificateEntryBytes);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.Certificate, body.ToArray());
    }

    private static byte[] BuildCertificateVerify(ushort algorithm, ReadOnlySpan<byte> signature)
    {
        using var body = new MemoryStream();
        WriteUInt16(body, algorithm);
        WriteUInt16(body, checked((ushort)signature.Length));
        body.Write(signature);
        return BuildHandshakeMessage(RuntimeTls13HandshakeType.CertificateVerify, body.ToArray());
    }

    private static byte[] BuildCertificateVerifyData(string context, byte[] transcriptHash)
    {
        var contextBytes = Encoding.ASCII.GetBytes(context);
        var message = new byte[64 + contextBytes.Length + 1 + transcriptHash.Length];
        message.AsSpan(0, 64).Fill(0x20);
        contextBytes.CopyTo(message.AsSpan(64));
        transcriptHash.CopyTo(message.AsSpan(64 + contextBytes.Length + 1));
        return message;
    }

    private async ValueTask WriteCompatibilityChangeCipherSpecAsync(CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> record = new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        await _transportStream.WriteAsync(record, cancellationToken).ConfigureAwait(false);
        await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
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

    private async Task<byte[]> ReadEncryptedHandshakeMessageAsync(
        RuntimeTls13TrafficProtector protector,
        CancellationToken cancellationToken)
    {
        var handshakeBuffer = new ResizableByteQueue();
        while (true)
        {
            var plaintext = await ReadEncryptedTls13PlaintextAsync(
                    protector,
                    cancellationToken)
                .ConfigureAwait(false);
            if (plaintext.ContentType != RuntimeTls13RecordType.Handshake)
            {
                throw new AuthenticationException(
                    $"Unexpected TLS 1.3 content type '{plaintext.ContentType}' before handshake completion.");
            }

            handshakeBuffer.Append(plaintext.Content);
            if (TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
            {
                return handshakeMessage;
            }
        }
    }

    private async Task<byte[]> ReadHelloRetryRequestClientHelloAsync(
        ushort recordVersion,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(_transportStream, allowEof: false, cancellationToken).ConfigureAwait(false)
                ?? throw new EndOfStreamException("Unexpected EOF while waiting for the retry ClientHello.");

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls13AlertExceptionFactory.Create(record.Payload, encrypted: false);
                case RuntimeTls13RecordType.Handshake:
                    if (record.Payload.Length < 4 ||
                        record.Payload[0] != (byte)RuntimeTls13HandshakeType.ClientHello)
                    {
                        throw new AuthenticationException(
                            "TLS 1.3 retry flight did not contain a ClientHello.");
                    }

                    return BuildTlsRecord(recordVersion, record.Type, record.Payload);
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' while waiting for the retry ClientHello.");
            }
        }
    }

    private async Task<RuntimeTls13Plaintext> ReadEncryptedTls13PlaintextAsync(
        RuntimeTls13TrafficProtector protector,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(_transportStream, allowEof: false, cancellationToken).ConfigureAwait(false)
                ?? throw new EndOfStreamException("Unexpected EOF while reading an encrypted TLS 1.3 record.");

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls13AlertExceptionFactory.Create(record.Payload, encrypted: false);
                case RuntimeTls13RecordType.ApplicationData:
                    return protector.Decrypt(record.Payload);
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' before handshake completion.");
            }
        }
    }

    private static bool TryReadHandshakeMessage(ResizableByteQueue buffer, out byte[] handshakeMessage)
    {
        handshakeMessage = Array.Empty<byte>();
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

        handshakeMessage = buffer.Slice(0, totalLength).ToArray();
        buffer.Consume(totalLength);
        return true;
    }

    private static void ValidateHelloRetryRequestClientHello(
        RuntimeRealityClientHelloDocument initialHello,
        RuntimeRealityClientHelloDocument retryHello,
        ushort selectedGroup,
        ReadOnlySpan<byte> expectedCookieExtensionPayload)
    {
        ArgumentNullException.ThrowIfNull(initialHello);
        ArgumentNullException.ThrowIfNull(retryHello);

        if (!retryHello.SupportsTls13)
        {
            throw new AuthenticationException("REALITY inbound retry client hello must advertise TLS 1.3 support.");
        }

        if (retryHello.LegacyVersion != initialHello.LegacyVersion ||
            !retryHello.Random.AsSpan().SequenceEqual(initialHello.Random) ||
            !retryHello.SessionId.AsSpan().SequenceEqual(initialHello.SessionId) ||
            !retryHello.CipherSuites.AsSpan().SequenceEqual(initialHello.CipherSuites) ||
            !retryHello.CompressionMethods.AsSpan().SequenceEqual(initialHello.CompressionMethods))
        {
            throw new AuthenticationException(
                "REALITY inbound retry client hello changed immutable parameters.");
        }

        if (!TryGetExtensionPayload(retryHello, 0x002C, out var cookieExtensionPayload) ||
            !cookieExtensionPayload.AsSpan().SequenceEqual(expectedCookieExtensionPayload))
        {
            throw new AuthenticationException("REALITY inbound retry client hello cookie validation failed.");
        }

        if (!ContainsNamedGroup(retryHello.SupportedGroups, selectedGroup))
        {
            throw new AuthenticationException(
                $"REALITY inbound retry client hello did not advertise the requested named group 0x{selectedGroup:X4}.");
        }
    }

    private static bool TryGetExtensionPayload(
        RuntimeRealityClientHelloDocument hello,
        ushort extensionType,
        out byte[] payload)
    {
        foreach (var extension in hello.Extensions)
        {
            if (extension.Type != extensionType)
            {
                continue;
            }

            payload = extension.Payload;
            return true;
        }

        payload = Array.Empty<byte>();
        return false;
    }

    private static byte[] BuildTlsRecord(
        ushort recordVersion,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> payload)
    {
        var record = new byte[5 + payload.Length];
        record[0] = (byte)recordType;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(1, 2), recordVersion);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), checked((ushort)payload.Length));
        payload.CopyTo(record.AsSpan(5));
        return record;
    }

    private static byte[] BuildHandshakeRecord(RuntimeTls13HandshakeType handshakeType, ReadOnlySpan<byte> body)
    {
        var handshakeMessage = BuildHandshakeMessage(handshakeType, body);
        using var record = new MemoryStream();
        record.WriteByte((byte)RuntimeTls13RecordType.Handshake);
        WriteUInt16(record, 0x0303);
        WriteUInt16(record, checked((ushort)handshakeMessage.Length));
        record.Write(handshakeMessage);
        return record.ToArray();
    }

    private static byte[] BuildHandshakeMessage(RuntimeTls13HandshakeType handshakeType, ReadOnlySpan<byte> body)
    {
        var message = new byte[4 + body.Length];
        message[0] = (byte)handshakeType;
        WriteUInt24(message.AsSpan(1, 3), body.Length);
        body.CopyTo(message.AsSpan(4));
        return message;
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

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }
}

internal sealed record RuntimeRealityAcceptedConnection(
    Stream Stream,
    string ServerName,
    string NegotiatedAlpn);

internal sealed record RuntimeRealityInboundServerProfile(
    bool Show,
    string MasterKeyLog,
    RuntimeRealityInboundFallbackProfile? Fallback,
    IReadOnlyList<string> ServerNames,
    byte[] PrivateKey,
    byte[] MinClientVersion,
    byte[] MaxClientVersion,
    long MaxTimeDiffMilliseconds,
    IReadOnlyList<byte[]> ShortIds,
    byte[]? Mldsa65Seed,
    RuntimeTlsClientHelloPolicyOptions ClientHelloPolicy)
{
    public static RuntimeRealityInboundServerProfile Create(RuntimeRealityServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var serverNames = options.ServerNames
            .Select(NormalizeServerName)
            .Where(static value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (serverNames.Length == 0)
        {
            throw new InvalidOperationException("REALITY inbound requires at least one server name.");
        }

        if (!RuntimeRealityOptions.TryDecodeBase64Url(options.PrivateKey.Trim(), out var privateKey) ||
            privateKey.Length != RuntimeX25519.KeyLength)
        {
            throw new InvalidOperationException("REALITY inbound private key is invalid.");
        }

        var shortIds = ParseShortIds(options.ShortIds);
        if (shortIds.Count == 0)
        {
            throw new InvalidOperationException("REALITY inbound requires at least one short ID.");
        }

        var normalizedPrivateKeyText = options.PrivateKey.Trim();
        byte[]? mldsa65Seed = null;
        if (!string.IsNullOrWhiteSpace(options.Mldsa65Seed))
        {
            if (string.Equals(
                    normalizedPrivateKeyText,
                    options.Mldsa65Seed.Trim(),
                    StringComparison.Ordinal))
            {
                throw new InvalidOperationException("REALITY inbound ML-DSA-65 seed cannot match the private key.");
            }

            if (!RuntimeRealityOptions.TryDecodeBase64Url(options.Mldsa65Seed.Trim(), out var decodedMldsa65Seed) ||
                decodedMldsa65Seed.Length != 32)
            {
                throw new InvalidOperationException("REALITY inbound ML-DSA-65 seed is invalid.");
            }

            mldsa65Seed = decodedMldsa65Seed;
        }

        return new RuntimeRealityInboundServerProfile(
            options.Show,
            NormalizeMasterKeyLog(options.MasterKeyLog),
            CreateFallbackProfile(options),
            serverNames,
            privateKey,
            ParseClientVersion(options.MinClientVersion, nameof(options.MinClientVersion)),
            ParseClientVersion(options.MaxClientVersion, nameof(options.MaxClientVersion)),
            Math.Max(0, options.MaxTimeDiffMilliseconds),
            shortIds,
            mldsa65Seed,
            options.ClientHelloPolicy);
    }

    private static RuntimeRealityInboundFallbackProfile? CreateFallbackProfile(RuntimeRealityServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var destination = options.Dest?.Trim() ?? string.Empty;
        if (destination.Length == 0)
        {
            return null;
        }

        var type = TrojanFallbackCompatibility.NormalizeType(options.Type, destination);
        if (type.Length == 0)
        {
            throw new InvalidOperationException("REALITY inbound fallback type is invalid.");
        }

        if (options.Xver is < 0 or > 2)
        {
            throw new InvalidOperationException("REALITY inbound fallback xver only accepts 0, 1 or 2.");
        }

        if (!TrojanFallbackCompatibility.IsSupportedTransportType(type))
        {
            throw new InvalidOperationException($"REALITY inbound fallback type '{type}' is not supported.");
        }

        if (!TrojanFallbackCompatibility.IsValidDestination(type, destination))
        {
            throw new InvalidOperationException("REALITY inbound fallback destination is invalid.");
        }

        return new RuntimeRealityInboundFallbackProfile(
            type,
            TrojanFallbackCompatibility.NormalizeDestination(type, destination),
            TrojanFallbackCompatibility.NormalizeProxyProtocolVersion(options.Xver),
            NormalizeFallbackLimit(options.LimitFallbackUpload),
            NormalizeFallbackLimit(options.LimitFallbackDownload));
    }

    private static IReadOnlyList<byte[]> ParseShortIds(IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var shortIds = new List<byte[]>(values.Count);
        for (var index = 0; index < values.Count; index++)
        {
            var current = values[index]?.Trim().ToLowerInvariant() ?? string.Empty;
            if (current.Length > 16)
            {
                throw new InvalidOperationException($"REALITY inbound shortIds[{index}] is too long.");
            }

            var shortId = new byte[8];
            if (current.Length > 0)
            {
                if (!RuntimeRealityOptions.TryDecodeHex(current, out var decoded))
                {
                    throw new InvalidOperationException($"REALITY inbound shortIds[{index}] is invalid.");
                }

                decoded.CopyTo(shortId.AsSpan());
            }

            shortIds.Add(shortId);
        }

        return shortIds;
    }

    private static byte[] ParseClientVersion(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<byte>();
        }

        var version = new byte[3];
        var parts = value.Trim().Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length > 3)
        {
            throw new InvalidOperationException($"REALITY inbound {parameterName} is invalid.");
        }

        for (var index = 0; index < parts.Length; index++)
        {
            if (!byte.TryParse(parts[index], NumberStyles.None, CultureInfo.InvariantCulture, out version[index]))
            {
                throw new InvalidOperationException($"REALITY inbound {parameterName} is invalid.");
            }
        }

        return version;
    }

    private static RuntimeFallbackLimitOptions NormalizeFallbackLimit(RuntimeFallbackLimitOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return new RuntimeFallbackLimitOptions
        {
            AfterBytes = Math.Max(0, options.AfterBytes),
            BytesPerSecond = Math.Max(0, options.BytesPerSecond),
            BurstBytesPerSecond = Math.Max(0, options.BurstBytesPerSecond)
        };
    }

    private static string NormalizeMasterKeyLog(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        return string.Equals(normalized, "none", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : normalized;
    }

    private static string NormalizeServerName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        if (IPAddress.TryParse(trimmed, out var address))
        {
            return address.ToString().ToLowerInvariant();
        }

        try
        {
            trimmed = new IdnMapping().GetAscii(trimmed);
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }

        return trimmed.ToLowerInvariant();
    }
}

internal sealed record RuntimeRealityInboundFallbackProfile(
    string Type,
    string Destination,
    int ProxyProtocolVersion,
    RuntimeFallbackLimitOptions LimitUpload,
    RuntimeFallbackLimitOptions LimitDownload);

internal sealed record RuntimeRealityTls13ServerHandshakeState(
    ushort SelectedGroup,
    byte[] ServerKeyShare,
    byte[] SharedSecret);

internal sealed record RuntimeTls13KeyShareEntry(
    ushort Group,
    byte[] KeyExchange);

internal static class RuntimeRealitySyntheticCertificateFactory
{
    public static byte[] CreateEd25519Certificate(
        byte[] publicKey,
        byte[] signature,
        IReadOnlyList<X509Extension>? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(signature);

        var subjectName = CreateCommonName("synthetic.example");

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
}

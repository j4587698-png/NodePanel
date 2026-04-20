#pragma warning disable SYSLIB0039
using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NodePanel.Core.Runtime;

internal sealed record RuntimeTlsServerHelloFlight(
    byte[] ServerHelloMessage,
    ResizableByteQueue PendingHandshakeMessages);

internal sealed record RuntimeTlsServerHelloInfo(
    byte[] Message,
    SslProtocols NegotiatedSslProtocol,
    ushort CipherSuite,
    byte[] Random,
    byte[] SessionId,
    string NegotiatedApplicationProtocol,
    bool UsesExtendedMasterSecret)
{
    public static RuntimeTlsServerHelloInfo Parse(ReadOnlySpan<byte> handshakeMessage)
    {
        if (handshakeMessage.Length < 4 ||
            handshakeMessage[0] != (byte)RuntimeTls13HandshakeType.ServerHello)
        {
            throw new AuthenticationException("The TLS peer did not return a ServerHello.");
        }

        var messageLength = ReadUInt24(handshakeMessage.Slice(1, 3));
        var totalLength = 4 + messageLength;
        if (totalLength > handshakeMessage.Length)
        {
            throw new AuthenticationException("The TLS ServerHello is truncated.");
        }

        var body = handshakeMessage.Slice(4, messageLength);
        if (body.Length < 38)
        {
            throw new AuthenticationException("The TLS ServerHello payload is truncated.");
        }

        var position = 0;
        var legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
        position += 2;
        var random = body.Slice(position, 32).ToArray();
        position += 32;

        var sessionIdLength = body[position];
        position++;
        if (position + sessionIdLength + 3 > body.Length)
        {
            throw new AuthenticationException("The TLS ServerHello session identifier is truncated.");
        }

        var sessionId = body.Slice(position, sessionIdLength).ToArray();
        position += sessionIdLength;
        var cipherSuite = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
        position += 3;

        ushort selectedVersion = (ushort)legacyVersion;
        var negotiatedApplicationProtocol = string.Empty;
        var usesExtendedMasterSecret = false;
        if (position < body.Length)
        {
            if (position + 2 > body.Length)
            {
                throw new AuthenticationException("The TLS ServerHello extensions are truncated.");
            }

            var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            position += 2;
            var extensionsEnd = position + extensionsLength;
            if (extensionsEnd > body.Length)
            {
                throw new AuthenticationException("The TLS ServerHello extensions are truncated.");
            }

            while (position + 4 <= extensionsEnd)
            {
                var extensionType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
                var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position + 2, 2));
                position += 4;
                if (position + extensionLength > extensionsEnd)
                {
                    throw new AuthenticationException("The TLS ServerHello extension payload is truncated.");
                }

                var extensionPayload = body.Slice(position, extensionLength);
                switch (extensionType)
                {
                    case 0x0010:
                        negotiatedApplicationProtocol = ParseSelectedApplicationProtocol(extensionPayload);
                        break;
                    case 0x0017:
                        usesExtendedMasterSecret = true;
                        break;
                    case 0x002B when extensionPayload.Length >= 2:
                        selectedVersion = BinaryPrimitives.ReadUInt16BigEndian(extensionPayload[..2]);
                        break;
                }

                position += extensionLength;
            }
        }

        return new RuntimeTlsServerHelloInfo(
            handshakeMessage.Slice(0, totalLength).ToArray(),
            selectedVersion switch
            {
                0x0304 => SslProtocols.Tls13,
                0x0303 => SslProtocols.Tls12,
                0x0302 => SslProtocols.Tls11,
                0x0301 => SslProtocols.Tls,
                _ => SslProtocols.None
            },
            cipherSuite,
            random,
            sessionId,
            negotiatedApplicationProtocol,
            usesExtendedMasterSecret);
    }

    private static string ParseSelectedApplicationProtocol(ReadOnlySpan<byte> payload)
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

    private static int ReadUInt24(ReadOnlySpan<byte> payload)
        => (payload[0] << 16) | (payload[1] << 8) | payload[2];
}

internal static class RuntimeTls12FingerprintHandshake
{
    public static async Task<RuntimeTlsFingerprintHandshakeResult> CompleteAsync(
        RuntimeTlsFingerprintHandshakeRequest request,
        Stream transportStream,
        byte[] clientHelloMessage,
        RuntimeTlsServerHelloInfo serverHello,
        ResizableByteQueue pendingHandshakeMessages,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentNullException.ThrowIfNull(clientHelloMessage);
        ArgumentNullException.ThrowIfNull(serverHello);
        ArgumentNullException.ThrowIfNull(pendingHandshakeMessages);

        var negotiatedProtocol = NormalizeNegotiatedProtocol(serverHello.NegotiatedSslProtocol);
        var cipherSuite = RuntimeTls12CipherSuite.Resolve(serverHello.CipherSuite);
        EnsureCipherSuiteSupportsProtocol(cipherSuite, negotiatedProtocol);
        var recordVersion = GetRecordVersion(negotiatedProtocol);
        var useExplicitCbcIv = UsesExplicitCbcIv(negotiatedProtocol);
        using var transcript = new RuntimeTls12HandshakeTranscript();
        transcript.Append(clientHelloMessage);
        transcript.Append(serverHello.Message);
        var clientRandom = ExtractClientRandom(clientHelloMessage);

        using var serverHandshake = await ReceiveServerHandshakeAsync(
                request,
                transportStream,
                clientRandom,
                serverHello,
                negotiatedProtocol,
                cipherSuite,
                pendingHandshakeMessages,
                transcript,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            if (serverHandshake.ServerRequestedClientCertificate)
            {
                var emptyCertificateMessage = CreateEmptyCertificateMessage();
                transcript.Append(emptyCertificateMessage);
                await WritePlaintextRecordAsync(
                        transportStream,
                        RuntimeTls13RecordType.Handshake,
                        emptyCertificateMessage,
                        recordVersion,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var clientKeyExchange = CreateClientKeyExchange(
                cipherSuite,
                serverHandshake.ServerKeyExchange,
                serverHandshake.Peer.LeafCertificate!,
                clientHelloMessage);
            transcript.Append(clientKeyExchange.Message);

            var transcriptHash = transcript.GetHashForPseudoRandomFunction(
                negotiatedProtocol,
                cipherSuite.HashAlgorithm);
            var masterSecret = serverHello.UsesExtendedMasterSecret
                ? RuntimeTls12PseudoRandomFunction.CreateExtendedMasterSecret(
                    negotiatedProtocol,
                    cipherSuite,
                    clientKeyExchange.PreMasterSecret,
                    transcriptHash)
                : RuntimeTls12PseudoRandomFunction.CreateMasterSecret(
                    negotiatedProtocol,
                    cipherSuite,
                    clientKeyExchange.PreMasterSecret,
                    clientRandom,
                    serverHello.Random);
            var keyBlock = RuntimeTls12PseudoRandomFunction.CreateKeyBlock(
                negotiatedProtocol,
                cipherSuite,
                masterSecret,
                clientRandom,
                serverHello.Random);

            using var serverReadProtector = RuntimeTls12TrafficProtector.Create(
                cipherSuite,
                keyBlock.ServerWriteKey,
                keyBlock.ServerWriteIv,
                keyBlock.ServerMacKey,
                recordVersion,
                useExplicitCbcIv);
            using var clientWriteProtector = RuntimeTls12TrafficProtector.Create(
                cipherSuite,
                keyBlock.ClientWriteKey,
                keyBlock.ClientWriteIv,
                keyBlock.ClientMacKey,
                recordVersion,
                useExplicitCbcIv);

            await WritePlaintextRecordAsync(
                    transportStream,
                    RuntimeTls13RecordType.Handshake,
                    clientKeyExchange.Message,
                    recordVersion,
                    cancellationToken)
                .ConfigureAwait(false);
            await WritePlaintextRecordAsync(
                    transportStream,
                    RuntimeTls13RecordType.ChangeCipherSpec,
                    new byte[] { 0x01 },
                    recordVersion,
                    cancellationToken)
                .ConfigureAwait(false);

            var clientFinishedMessage = RuntimeTls12PseudoRandomFunction.CreateFinishedMessage(
                negotiatedProtocol,
                cipherSuite,
                masterSecret,
                transcriptHash,
                isClient: true);
            var clientFinishedRecord = clientWriteProtector.Encrypt(
                RuntimeTls13RecordType.Handshake,
                clientFinishedMessage);
            await transportStream
                .WriteAsync(clientFinishedRecord.AsMemory(0, clientFinishedRecord.Length), cancellationToken)
                .ConfigureAwait(false);
            await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            transcript.Append(clientFinishedMessage);

            await ReceiveServerFinishedAsync(
                    transportStream,
                    serverReadProtector,
                    transcript,
                    negotiatedProtocol,
                    cipherSuite,
                    masterSecret,
                    cancellationToken)
                .ConfigureAwait(false);

            var transport = new RuntimeTls12DuplexStream(
                transportStream,
                serverReadProtector.Detach(),
                clientWriteProtector.Detach());
            var remoteCertificate = X509CertificateLoader.LoadCertificate(serverHandshake.Peer.LeafCertificate!.RawData);
            return new RuntimeTlsFingerprintHandshakeResult
            {
                TransportStream = transport,
                SecurityState = RuntimeInternetSecurityState.Create(
                    RuntimeInternetSecurityTypes.Tls,
                    negotiatedProtocol,
                    serverHandshake.Peer.NegotiatedApplicationProtocol,
                    remoteCertificate)
            };
        }
        finally
        {
            serverHandshake.Peer.Dispose();
        }
    }

    private static async Task<RuntimeTls12ServerHandshakeState> ReceiveServerHandshakeAsync(
        RuntimeTlsFingerprintHandshakeRequest request,
        Stream transportStream,
        byte[] clientRandom,
        RuntimeTlsServerHelloInfo serverHello,
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        ResizableByteQueue handshakeBuffer,
        RuntimeTls12HandshakeTranscript transcript,
        CancellationToken cancellationToken)
    {
        var peer = new RuntimeTls13ServerPeer
        {
            NegotiatedApplicationProtocol = serverHello.NegotiatedApplicationProtocol
        };
        RuntimeTls12ServerKeyExchange? serverKeyExchange = null;
        var serverRequestedClientCertificate = false;
        var seenCertificate = false;
        var seenServerHelloDone = false;

        while (!seenServerHelloDone)
        {
            if (!TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
            {
                var record = await RuntimeTls13Record.ReadAsync(
                        transportStream,
                        allowEof: false,
                        cancellationToken)
                    .ConfigureAwait(false)
                    ?? throw new EndOfStreamException("Unexpected EOF while reading TLS 1.2 handshake records.");
                switch (record.Type)
                {
                    case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                        continue;
                    case RuntimeTls13RecordType.Alert:
                        throw RuntimeTls12AlertExceptionFactory.Create(record.Payload, encrypted: false);
                    case RuntimeTls13RecordType.Handshake:
                        handshakeBuffer.Append(record.Payload);
                        continue;
                    default:
                        throw new AuthenticationException(
                            $"Unexpected TLS record '{record.Type}' before TLS 1.2 handshake completion.");
                }
            }

            switch (handshakeMessage[0])
            {
                case (byte)RuntimeTls13HandshakeType.Certificate:
                    if (seenCertificate)
                    {
                        throw new AuthenticationException("TLS 1.2 Certificate was received multiple times.");
                    }

                    seenCertificate = true;
                    ParseCertificateMessage(handshakeMessage, peer);
                    ValidateServerCertificate(request, peer);
                    transcript.Append(handshakeMessage);
                    break;
                case 12:
                    if (!seenCertificate)
                    {
                        throw new AuthenticationException("TLS 1.2 ServerKeyExchange arrived before Certificate.");
                    }

                    if (cipherSuite.KeyExchangeKind != RuntimeTls12KeyExchangeKind.Ecdhe)
                    {
                        throw new AuthenticationException(
                            "TLS 1.2 ServerKeyExchange was received for a cipher suite that does not use ECDHE.");
                    }

                    serverKeyExchange = ParseServerKeyExchange(
                        handshakeMessage,
                        clientRandom,
                        serverHello.Random,
                        negotiatedProtocol,
                        peer.LeafCertificate!);
                    transcript.Append(handshakeMessage);
                    break;
                case 14:
                    transcript.Append(handshakeMessage);
                    seenServerHelloDone = true;
                    break;
                case 13:
                    if (serverRequestedClientCertificate)
                    {
                        throw new AuthenticationException("TLS 1.2 CertificateRequest was received multiple times.");
                    }

                    serverRequestedClientCertificate = true;
                    transcript.Append(handshakeMessage);
                    break;
                case 22:
                case (byte)RuntimeTls13HandshakeType.NewSessionTicket:
                    transcript.Append(handshakeMessage);
                    break;
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS 1.2 handshake message 0x{handshakeMessage[0]:X2} before handshake completion.");
            }
        }

        if (peer.LeafCertificate is null)
        {
            throw new AuthenticationException("TLS 1.2 Certificate message did not include a leaf certificate.");
        }

        if (cipherSuite.KeyExchangeKind == RuntimeTls12KeyExchangeKind.Ecdhe &&
            serverKeyExchange is null)
        {
            throw new AuthenticationException("TLS 1.2 ServerKeyExchange was not received.");
        }

        return new RuntimeTls12ServerHandshakeState(peer, serverKeyExchange, serverRequestedClientCertificate);
    }

    private static void ParseCertificateMessage(
        ReadOnlySpan<byte> handshakeMessage,
        RuntimeTls13ServerPeer peer)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.Certificate);
        if (body.Length < 3)
        {
            throw new AuthenticationException("TLS 1.2 Certificate payload is truncated.");
        }

        var certificateListLength = ReadUInt24(body[..3]);
        var position = 3;
        var end = position + certificateListLength;
        if (end > body.Length)
        {
            throw new AuthenticationException("TLS 1.2 Certificate list is truncated.");
        }

        while (position + 3 <= end)
        {
            var certificateLength = ReadUInt24(body.Slice(position, 3));
            position += 3;
            if (position + certificateLength > end)
            {
                throw new AuthenticationException("TLS 1.2 certificate entry is truncated.");
            }

            peer.CertificateChain.Add(
                X509CertificateLoader.LoadCertificate(body.Slice(position, certificateLength).ToArray()));
            position += certificateLength;
        }

        if (peer.CertificateChain.Count == 0)
        {
            throw new AuthenticationException("TLS 1.2 Certificate message did not include any certificates.");
        }

        peer.LeafCertificate = peer.CertificateChain[0];
    }

    private static void ValidateServerCertificate(
        RuntimeTlsFingerprintHandshakeRequest request,
        RuntimeTls13ServerPeer peer)
    {
        X509Chain? chain = null;
        try
        {
            if (!RuntimeServerCertificateValidation.Validate(
                    request.ServerName,
                    request.SkipCertificateValidation,
                    request.CertificateValidationCallback,
                    request,
                    peer.LeafCertificate,
                    peer.CertificateChain,
                    out chain!,
                    out var errors))
            {
                throw new AuthenticationException(
                    $"TLS 1.2 server certificate validation failed: {errors}.");
            }
        }
        finally
        {
            chain?.Dispose();
        }
    }

    private static RuntimeTls12ServerKeyExchange ParseServerKeyExchange(
        ReadOnlySpan<byte> handshakeMessage,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        SslProtocols negotiatedProtocol,
        X509Certificate2 leafCertificate)
    {
        var body = GetHandshakeBody(handshakeMessage, expectedType: 12);
        if (body.Length < 6)
        {
            throw new AuthenticationException("TLS 1.2 ServerKeyExchange payload is truncated.");
        }

        if (body[0] != 3)
        {
            throw new AuthenticationException("TLS 1.2 server selected an unsupported elliptic-curve encoding.");
        }

        var namedGroup = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(1, 2));
        var publicKeyLength = body[3];
        if (4 + publicKeyLength + 4 > body.Length)
        {
            throw new AuthenticationException("TLS 1.2 ServerKeyExchange public key is truncated.");
        }

        var signedParameters = body.Slice(0, 4 + publicKeyLength);
        var publicKey = signedParameters[4..].ToArray();
        var position = 4 + publicKeyLength;
        if (UsesTls12SignatureAlgorithms(negotiatedProtocol))
        {
            if (position + 4 > body.Length)
            {
                throw new AuthenticationException("TLS 1.2 ServerKeyExchange signature is truncated.");
            }

            var signatureAlgorithm = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            position += 2;
            var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            position += 2;
            if (position + signatureLength > body.Length)
            {
                throw new AuthenticationException("TLS 1.2 ServerKeyExchange signature is truncated.");
            }

            var signature = body.Slice(position, signatureLength);
            var signedData = BuildServerKeyExchangeHash(
                signatureAlgorithm,
                clientRandom,
                serverRandom,
                signedParameters);
            if (!VerifyHandshakeSignature(leafCertificate, signatureAlgorithm, signedData, signature))
            {
                throw new AuthenticationException(
                    $"TLS 1.2 ServerKeyExchange verification failed for signature algorithm 0x{signatureAlgorithm:X4}.");
            }
        }
        else
        {
            if (position + 2 > body.Length)
            {
                throw new AuthenticationException("TLS 1.0/1.1 ServerKeyExchange signature is truncated.");
            }

            var signatureLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(position, 2));
            position += 2;
            if (position + signatureLength > body.Length)
            {
                throw new AuthenticationException("TLS 1.0/1.1 ServerKeyExchange signature is truncated.");
            }

            var signature = body.Slice(position, signatureLength);
            if (!VerifyLegacyServerKeyExchangeSignature(
                    leafCertificate,
                    clientRandom,
                    serverRandom,
                    signedParameters,
                    signature))
            {
                throw new AuthenticationException("TLS 1.0/1.1 ServerKeyExchange verification failed.");
            }
        }

        return new RuntimeTls12ServerKeyExchange(namedGroup, publicKey);
    }

    private static RuntimeTls12ClientKeyExchangeState CreateClientKeyExchange(
        RuntimeTls12CipherSuite cipherSuite,
        RuntimeTls12ServerKeyExchange? serverKeyExchange,
        X509Certificate2 leafCertificate,
        ReadOnlySpan<byte> clientHelloMessage)
    {
        if (cipherSuite.KeyExchangeKind == RuntimeTls12KeyExchangeKind.Rsa)
        {
            var preMasterSecret = new byte[48];
            BinaryPrimitives.WriteUInt16BigEndian(
                preMasterSecret.AsSpan(0, 2),
                ExtractClientLegacyProtocolVersion(clientHelloMessage));
            RandomNumberGenerator.Fill(preMasterSecret.AsSpan(2));

            using var rsa = leafCertificate.GetRSAPublicKey();
            if (rsa is null)
            {
                throw new AuthenticationException("TLS 1.2 RSA key exchange requires an RSA server certificate.");
            }

            var encryptedPreMasterSecret = rsa.Encrypt(preMasterSecret, RSAEncryptionPadding.Pkcs1);
            var rsaBody = new byte[2 + encryptedPreMasterSecret.Length];
            BinaryPrimitives.WriteUInt16BigEndian(rsaBody.AsSpan(0, 2), checked((ushort)encryptedPreMasterSecret.Length));
            encryptedPreMasterSecret.CopyTo(rsaBody, 2);
            return new RuntimeTls12ClientKeyExchangeState(
                CreateHandshakeMessage(16, rsaBody),
                preMasterSecret);
        }

        if (serverKeyExchange is null)
        {
            throw new AuthenticationException("TLS 1.2 ECDHE key exchange is missing ServerKeyExchange.");
        }

        byte[] clientPublicKey;
        byte[] preMasterSecretForEcdhe;
        switch (serverKeyExchange.NamedGroup)
        {
            case RuntimeTlsNamedGroups.X25519:
                using (var keyPair = RuntimeX25519.CreateKeyPair())
                {
                    clientPublicKey = keyPair.PublicKey;
                    preMasterSecretForEcdhe = RuntimeX25519.DeriveSharedSecret(keyPair.PrivateKey, serverKeyExchange.PublicKey);
                }

                break;
            case RuntimeTlsNamedGroups.Secp256r1:
                using (var keyPair = RuntimeSecp256r1.CreateKeyPair())
                {
                    clientPublicKey = keyPair.PublicKey;
                    preMasterSecretForEcdhe = RuntimeSecp256r1.DeriveSharedSecret(keyPair.PrivateKey, serverKeyExchange.PublicKey);
                }

                break;
            case RuntimeTlsNamedGroups.Secp384r1:
                using (var keyPair = RuntimeSecp384r1.CreateKeyPair())
                {
                    clientPublicKey = keyPair.PublicKey;
                    preMasterSecretForEcdhe = RuntimeSecp384r1.DeriveSharedSecret(keyPair.PrivateKey, serverKeyExchange.PublicKey);
                }

                break;
            case RuntimeTlsNamedGroups.Secp521r1:
                using (var keyPair = RuntimeSecp521r1.CreateKeyPair())
                {
                    clientPublicKey = keyPair.PublicKey;
                    preMasterSecretForEcdhe = RuntimeSecp521r1.DeriveSharedSecret(keyPair.PrivateKey, serverKeyExchange.PublicKey);
                }

                break;
            default:
                throw new NotSupportedException(
                    $"TLS 1.2 named group 0x{serverKeyExchange.NamedGroup:X4} is not supported by the built-in fingerprint client.");
        }

        var body = new byte[1 + clientPublicKey.Length];
        body[0] = checked((byte)clientPublicKey.Length);
        clientPublicKey.CopyTo(body, 1);

        var message = new byte[4 + body.Length];
        message[0] = 16;
        WriteUInt24(message.AsSpan(1, 3), body.Length);
        body.CopyTo(message, 4);
        return new RuntimeTls12ClientKeyExchangeState(message, preMasterSecretForEcdhe);
    }

    private static byte[] CreateEmptyCertificateMessage()
        => CreateHandshakeMessage((byte)RuntimeTls13HandshakeType.Certificate, [0x00, 0x00, 0x00]);

    private static async Task ReceiveServerFinishedAsync(
        Stream transportStream,
        RuntimeTls12TrafficProtector serverReadProtector,
        RuntimeTls12HandshakeTranscript transcript,
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        byte[] masterSecret,
        CancellationToken cancellationToken)
    {
        var seenChangeCipherSpec = false;
        var handshakeBuffer = new ResizableByteQueue();
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(
                    transportStream,
                    allowEof: false,
                    cancellationToken)
                .ConfigureAwait(false)
                ?? throw new EndOfStreamException("Unexpected EOF while waiting for the TLS 1.2 Finished record.");
            if (!seenChangeCipherSpec)
            {
                switch (record.Type)
                {
                    case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                        seenChangeCipherSpec = true;
                        continue;
                    case RuntimeTls13RecordType.Alert:
                        throw RuntimeTls12AlertExceptionFactory.Create(record.Payload, encrypted: false);
                    default:
                        throw new AuthenticationException(
                            $"Unexpected TLS record '{record.Type}' while waiting for the server ChangeCipherSpec.");
                }
            }

            switch (record.Type)
            {
                case RuntimeTls13RecordType.Alert:
                    throw RuntimeTls12AlertExceptionFactory.Create(
                        serverReadProtector.Decrypt(RuntimeTls13RecordType.Alert, record.Payload),
                        encrypted: true);
                case RuntimeTls13RecordType.Handshake:
                    handshakeBuffer.Append(serverReadProtector.Decrypt(RuntimeTls13RecordType.Handshake, record.Payload));
                    while (TryReadHandshakeMessage(handshakeBuffer, out var handshakeMessage))
                    {
                        switch (handshakeMessage[0])
                        {
                            case (byte)RuntimeTls13HandshakeType.NewSessionTicket:
                                transcript.Append(handshakeMessage);
                                break;
                            case (byte)RuntimeTls13HandshakeType.Finished:
                                VerifyServerFinished(
                                    handshakeMessage,
                                    negotiatedProtocol,
                                    cipherSuite,
                                    masterSecret,
                                    transcript.GetHashForPseudoRandomFunction(
                                        negotiatedProtocol,
                                        cipherSuite.HashAlgorithm));
                                transcript.Append(handshakeMessage);
                                return;
                            default:
                                throw new AuthenticationException(
                                    $"Unexpected TLS 1.2 handshake message 0x{handshakeMessage[0]:X2} after ChangeCipherSpec.");
                        }
                    }

                    break;
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' after the server ChangeCipherSpec.");
            }
        }
    }

    private static void VerifyServerFinished(
        ReadOnlySpan<byte> handshakeMessage,
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        byte[] masterSecret,
        byte[] transcriptHash)
    {
        var body = GetHandshakeBody(handshakeMessage, RuntimeTls13HandshakeType.Finished);
        if (body.Length != 12)
        {
            throw new AuthenticationException("TLS 1.2 Finished verify_data has an unexpected length.");
        }

        var expected = RuntimeTls12PseudoRandomFunction.CreateFinishedVerifyData(
            negotiatedProtocol,
            cipherSuite,
            masterSecret,
            transcriptHash,
            isClient: false);
        if (!CryptographicOperations.FixedTimeEquals(expected, body))
        {
            throw new AuthenticationException("TLS 1.2 Finished verification failed.");
        }
    }

    private static byte[] ExtractClientRandom(ReadOnlySpan<byte> clientHelloMessage)
    {
        if (clientHelloMessage.Length < 38 ||
            clientHelloMessage[0] != (byte)RuntimeTls13HandshakeType.ClientHello)
        {
            throw new AuthenticationException("The TLS ClientHello is truncated.");
        }

        return clientHelloMessage.Slice(6, 32).ToArray();
    }

    private static ushort ExtractClientLegacyProtocolVersion(ReadOnlySpan<byte> clientHelloMessage)
    {
        if (clientHelloMessage.Length < 6 ||
            clientHelloMessage[0] != (byte)RuntimeTls13HandshakeType.ClientHello)
        {
            throw new AuthenticationException("The TLS ClientHello is truncated.");
        }

        return BinaryPrimitives.ReadUInt16BigEndian(clientHelloMessage.Slice(4, 2));
    }

    private static async ValueTask WritePlaintextRecordAsync(
        Stream stream,
        RuntimeTls13RecordType type,
        ReadOnlyMemory<byte> payload,
        ushort recordVersion,
        CancellationToken cancellationToken)
    {
        var record = new byte[5 + payload.Length];
        record[0] = (byte)type;
        record[1] = (byte)(recordVersion >> 8);
        record[2] = (byte)recordVersion;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), checked((ushort)payload.Length));
        payload.CopyTo(record.AsMemory(5));
        await stream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static SslProtocols NormalizeNegotiatedProtocol(SslProtocols negotiatedProtocol)
        => negotiatedProtocol switch
        {
            SslProtocols.Tls12 or SslProtocols.Tls11 or SslProtocols.Tls => negotiatedProtocol,
            _ => throw new AuthenticationException(
                $"The TLS peer selected unsupported legacy protocol '{negotiatedProtocol}'.")
        };

    private static void EnsureCipherSuiteSupportsProtocol(
        RuntimeTls12CipherSuite cipherSuite,
        SslProtocols negotiatedProtocol)
    {
        if (negotiatedProtocol == SslProtocols.Tls12)
        {
            return;
        }

        if (cipherSuite.CipherKind is RuntimeTls12CipherKind.AesGcm or RuntimeTls12CipherKind.ChaCha20Poly1305)
        {
            throw new NotSupportedException(
                $"Negotiated {FormatProtocol(negotiatedProtocol)} cannot use TLS 1.2-only cipher suite '{cipherSuite.Name}'.");
        }
    }

    private static ushort GetRecordVersion(SslProtocols negotiatedProtocol)
        => negotiatedProtocol switch
        {
            SslProtocols.Tls12 => 0x0303,
            SslProtocols.Tls11 => 0x0302,
            SslProtocols.Tls => 0x0301,
            _ => throw new AuthenticationException(
                $"The TLS peer selected unsupported legacy protocol '{negotiatedProtocol}'.")
        };

    private static bool UsesExplicitCbcIv(SslProtocols negotiatedProtocol)
        => negotiatedProtocol != SslProtocols.Tls;

    private static bool UsesTls12SignatureAlgorithms(SslProtocols negotiatedProtocol)
        => negotiatedProtocol == SslProtocols.Tls12;

    private static bool VerifyLegacyServerKeyExchangeSignature(
        X509Certificate2 leafCertificate,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> signedParameters,
        ReadOnlySpan<byte> signature)
    {
        var signedData = new byte[clientRandom.Length + serverRandom.Length + signedParameters.Length];
        clientRandom.CopyTo(signedData.AsSpan(0, clientRandom.Length));
        serverRandom.CopyTo(signedData.AsSpan(clientRandom.Length));
        signedParameters.CopyTo(signedData.AsSpan(clientRandom.Length + serverRandom.Length));

        using var rsa = leafCertificate.GetRSAPublicKey();
        if (rsa is not null)
        {
            return RuntimeRsaPkcs1SignaturePrimitives.VerifyLegacyMd5Sha1(rsa, signedData, signature);
        }

        using var ecdsa = leafCertificate.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            return ecdsa.VerifyHash(
                RuntimeCryptographicHashes.Hash(HashAlgorithmName.SHA1, signedData),
                signature);
        }

        return false;
    }

    private static string FormatProtocol(SslProtocols negotiatedProtocol)
        => negotiatedProtocol switch
        {
            SslProtocols.Tls12 => "TLS 1.2",
            SslProtocols.Tls11 => "TLS 1.1",
            SslProtocols.Tls => "TLS 1.0",
            _ => negotiatedProtocol.ToString()
        };

    private static byte[] BuildServerKeyExchangeHash(
        ushort signatureAlgorithm,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> signedParameters)
    {
        var signedData = new byte[clientRandom.Length + serverRandom.Length + signedParameters.Length];
        clientRandom.CopyTo(signedData.AsSpan(0, clientRandom.Length));
        serverRandom.CopyTo(signedData.AsSpan(clientRandom.Length));
        signedParameters.CopyTo(signedData.AsSpan(clientRandom.Length + serverRandom.Length));
        if (signatureAlgorithm == 0x0807)
        {
            return signedData;
        }

        var hashAlgorithm = signatureAlgorithm switch
        {
            0x0201 or 0x0203 => HashAlgorithmName.SHA1,
            0x0401 or 0x0403 or 0x0804 => HashAlgorithmName.SHA256,
            0x0501 or 0x0503 or 0x0805 => HashAlgorithmName.SHA384,
            0x0601 or 0x0603 or 0x0806 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException(
                $"TLS 1.2 signature algorithm 0x{signatureAlgorithm:X4} is not supported by the built-in fingerprint client.")
        };
        return RuntimeCryptographicHashes.Hash(hashAlgorithm, signedData);
    }

    private static bool VerifyHandshakeSignature(
        X509Certificate2 certificate,
        ushort signatureAlgorithm,
        byte[] data,
        ReadOnlySpan<byte> signature)
        => signatureAlgorithm switch
        {
            0x0201 => VerifyRsaPkcs1(certificate, data, signature, HashAlgorithmName.SHA1),
            0x0401 => VerifyRsaPkcs1(certificate, data, signature, HashAlgorithmName.SHA256),
            0x0501 => VerifyRsaPkcs1(certificate, data, signature, HashAlgorithmName.SHA384),
            0x0601 => VerifyRsaPkcs1(certificate, data, signature, HashAlgorithmName.SHA512),
            0x0804 => VerifyRsaPss(certificate, data, signature, HashAlgorithmName.SHA256),
            0x0805 => VerifyRsaPss(certificate, data, signature, HashAlgorithmName.SHA384),
            0x0806 => VerifyRsaPss(certificate, data, signature, HashAlgorithmName.SHA512),
            0x0203 => VerifyEcdsa(certificate, data, signature),
            0x0403 => VerifyEcdsa(certificate, data, signature),
            0x0503 => VerifyEcdsa(certificate, data, signature),
            0x0603 => VerifyEcdsa(certificate, data, signature),
            0x0807 => VerifyEd25519(certificate, data, signature),
            _ => false
        };

    private static bool VerifyRsaPkcs1(
        X509Certificate2 certificate,
        byte[] data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        using var rsa = certificate.GetRSAPublicKey();
        return rsa is not null &&
               rsa.VerifyHash(data, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
    }

    private static bool VerifyRsaPss(
        X509Certificate2 certificate,
        byte[] data,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        using var rsa = certificate.GetRSAPublicKey();
        return rsa is not null &&
               rsa.VerifyHash(data, signature, hashAlgorithm, RSASignaturePadding.Pss);
    }

    private static bool VerifyEcdsa(
        X509Certificate2 certificate,
        byte[] data,
        ReadOnlySpan<byte> signature)
    {
        using var ecdsa = certificate.GetECDsaPublicKey();
        return ecdsa is not null && ecdsa.VerifyHash(data, signature);
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

    private static ReadOnlySpan<byte> GetHandshakeBody(
        ReadOnlySpan<byte> handshakeMessage,
        RuntimeTls13HandshakeType expectedType)
        => GetHandshakeBody(handshakeMessage, (byte)expectedType);

    private static ReadOnlySpan<byte> GetHandshakeBody(
        ReadOnlySpan<byte> handshakeMessage,
        byte expectedType)
    {
        if (handshakeMessage.Length < 4)
        {
            throw new AuthenticationException("TLS handshake message is truncated.");
        }
        if (handshakeMessage[0] != expectedType)
        {
            throw new AuthenticationException(
                $"Expected TLS handshake message 0x{expectedType:X2}, but received 0x{handshakeMessage[0]:X2}.");
        }

        var bodyLength = ReadUInt24(handshakeMessage.Slice(1, 3));
        if (bodyLength != handshakeMessage.Length - 4)
        {
            throw new AuthenticationException("TLS handshake message length is invalid.");
        }

        return handshakeMessage[4..];
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

    private static int ReadUInt24(ReadOnlySpan<byte> payload)
        => (payload[0] << 16) | (payload[1] << 8) | payload[2];

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }

    private static byte[] CreateHandshakeMessage(byte handshakeType, ReadOnlySpan<byte> body)
    {
        var message = new byte[4 + body.Length];
        message[0] = handshakeType;
        WriteUInt24(message.AsSpan(1, 3), body.Length);
        body.CopyTo(message.AsSpan(4));
        return message;
    }
}

internal sealed record RuntimeTls12ServerHandshakeState(
    RuntimeTls13ServerPeer Peer,
    RuntimeTls12ServerKeyExchange? ServerKeyExchange,
    bool ServerRequestedClientCertificate) : IDisposable
{
    public void Dispose()
    {
    }
}

internal sealed record RuntimeTls12ServerKeyExchange(
    ushort NamedGroup,
    byte[] PublicKey);

internal sealed record RuntimeTls12ClientKeyExchangeState(
    byte[] Message,
    byte[] PreMasterSecret);

internal sealed record RuntimeTls12CipherSuite(
    ushort Id,
    string Name,
    RuntimeTls12KeyExchangeKind KeyExchangeKind,
    RuntimeTls12CipherKind CipherKind,
    int KeyLength,
    int MacKeyLength,
    int IvLength,
    HashAlgorithmName HashAlgorithm,
    HashAlgorithmName? RecordMacHashAlgorithm = null)
{
    public static RuntimeTls12CipherSuite Resolve(ushort id)
        => id switch
        {
            0xC02B => new(id, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesGcm, 16, 0, 4, HashAlgorithmName.SHA256),
            0xC02F => new(id, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesGcm, 16, 0, 4, HashAlgorithmName.SHA256),
            0xC02C => new(id, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesGcm, 32, 0, 4, HashAlgorithmName.SHA384),
            0xC030 => new(id, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesGcm, 32, 0, 4, HashAlgorithmName.SHA384),
            0xCCA9 => new(id, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.ChaCha20Poly1305, 32, 0, 12, HashAlgorithmName.SHA256),
            0xCCA8 => new(id, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.ChaCha20Poly1305, 32, 0, 12, HashAlgorithmName.SHA256),
            0xC009 => new(id, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesCbc, 16, 20, 16, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0xC013 => new(id, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesCbc, 16, 20, 16, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0xC00A => new(id, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesCbc, 32, 20, 16, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0xC014 => new(id, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.AesCbc, 32, 20, 16, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0x009C => new(id, "TLS_RSA_WITH_AES_128_GCM_SHA256", RuntimeTls12KeyExchangeKind.Rsa, RuntimeTls12CipherKind.AesGcm, 16, 0, 4, HashAlgorithmName.SHA256),
            0x009D => new(id, "TLS_RSA_WITH_AES_256_GCM_SHA384", RuntimeTls12KeyExchangeKind.Rsa, RuntimeTls12CipherKind.AesGcm, 32, 0, 4, HashAlgorithmName.SHA384),
            0x002F => new(id, "TLS_RSA_WITH_AES_128_CBC_SHA", RuntimeTls12KeyExchangeKind.Rsa, RuntimeTls12CipherKind.AesCbc, 16, 20, 16, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0x0035 => new(id, "TLS_RSA_WITH_AES_256_CBC_SHA", RuntimeTls12KeyExchangeKind.Rsa, RuntimeTls12CipherKind.AesCbc, 32, 20, 16, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0xC008 => new(id, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.TripleDesCbc, 24, 20, 8, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0xC012 => new(id, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", RuntimeTls12KeyExchangeKind.Ecdhe, RuntimeTls12CipherKind.TripleDesCbc, 24, 20, 8, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            0x000A => new(id, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", RuntimeTls12KeyExchangeKind.Rsa, RuntimeTls12CipherKind.TripleDesCbc, 24, 20, 8, HashAlgorithmName.SHA256, HashAlgorithmName.SHA1),
            _ => throw new NotSupportedException(
                $"TLS 1.2 cipher suite 0x{id:X4} is not supported by the built-in fingerprint client.")
        };
}

internal enum RuntimeTls12KeyExchangeKind
{
    Ecdhe,
    Rsa
}

internal enum RuntimeTls12CipherKind
{
    AesGcm,
    ChaCha20Poly1305,
    AesCbc,
    TripleDesCbc
}

internal sealed class RuntimeTls12HandshakeTranscript : IDisposable
{
    private readonly MemoryStream _buffer = new();

    public void Append(ReadOnlySpan<byte> message)
    {
        _buffer.Write(message);
    }

    public byte[] GetHash(HashAlgorithmName hashAlgorithm)
        => RuntimeCryptographicHashes.Hash(hashAlgorithm, _buffer.ToArray());

    public byte[] GetHashForPseudoRandomFunction(
        SslProtocols negotiatedProtocol,
        HashAlgorithmName tls12HashAlgorithm)
        => negotiatedProtocol == SslProtocols.Tls12
            ? GetHash(tls12HashAlgorithm)
            : RuntimeCryptographicHashes.HashLegacyMd5Sha1(_buffer.ToArray());

    public void Dispose()
    {
        _buffer.Dispose();
    }
}

internal static class RuntimeTls12PseudoRandomFunction
{
    private static readonly byte[] MasterSecretLabel = Encoding.ASCII.GetBytes("master secret");
    private static readonly byte[] ExtendedMasterSecretLabel = Encoding.ASCII.GetBytes("extended master secret");
    private static readonly byte[] KeyExpansionLabel = Encoding.ASCII.GetBytes("key expansion");
    private static readonly byte[] ClientFinishedLabel = Encoding.ASCII.GetBytes("client finished");
    private static readonly byte[] ServerFinishedLabel = Encoding.ASCII.GetBytes("server finished");

    public static byte[] CreateMasterSecret(
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        var seed = new byte[clientRandom.Length + serverRandom.Length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed.AsSpan(clientRandom.Length));
        return Expand(negotiatedProtocol, cipherSuite.HashAlgorithm, preMasterSecret, MasterSecretLabel, seed, 48);
    }

    public static byte[] CreateExtendedMasterSecret(
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        ReadOnlySpan<byte> preMasterSecret,
        ReadOnlySpan<byte> transcriptHash)
        => Expand(
            negotiatedProtocol,
            cipherSuite.HashAlgorithm,
            preMasterSecret,
            ExtendedMasterSecretLabel,
            transcriptHash,
            48);

    public static RuntimeTls12KeyBlock CreateKeyBlock(
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom)
    {
        var seed = new byte[serverRandom.Length + clientRandom.Length];
        serverRandom.CopyTo(seed);
        clientRandom.CopyTo(seed.AsSpan(serverRandom.Length));
        var keyMaterial = Expand(
            negotiatedProtocol,
            cipherSuite.HashAlgorithm,
            masterSecret,
            KeyExpansionLabel,
            seed,
            (cipherSuite.MacKeyLength * 2) + (cipherSuite.KeyLength * 2) + (cipherSuite.IvLength * 2));
        var offset = 0;
        var clientMacKey = keyMaterial.AsSpan(offset, cipherSuite.MacKeyLength).ToArray();
        offset += cipherSuite.MacKeyLength;
        var serverMacKey = keyMaterial.AsSpan(offset, cipherSuite.MacKeyLength).ToArray();
        offset += cipherSuite.MacKeyLength;
        var clientWriteKey = keyMaterial.AsSpan(offset, cipherSuite.KeyLength).ToArray();
        offset += cipherSuite.KeyLength;
        var serverWriteKey = keyMaterial.AsSpan(offset, cipherSuite.KeyLength).ToArray();
        offset += cipherSuite.KeyLength;
        var clientWriteIv = keyMaterial.AsSpan(offset, cipherSuite.IvLength).ToArray();
        offset += cipherSuite.IvLength;
        var serverWriteIv = keyMaterial.AsSpan(offset, cipherSuite.IvLength).ToArray();
        return new RuntimeTls12KeyBlock(
            clientMacKey,
            serverMacKey,
            clientWriteKey,
            serverWriteKey,
            clientWriteIv,
            serverWriteIv);
    }

    public static byte[] CreateFinishedMessage(
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> transcriptHash,
        bool isClient)
    {
        var verifyData = CreateFinishedVerifyData(
            negotiatedProtocol,
            cipherSuite,
            masterSecret,
            transcriptHash,
            isClient);
        var message = new byte[4 + verifyData.Length];
        message[0] = (byte)RuntimeTls13HandshakeType.Finished;
        WriteUInt24(message.AsSpan(1, 3), verifyData.Length);
        verifyData.CopyTo(message, 4);
        return message;
    }

    public static byte[] CreateFinishedVerifyData(
        SslProtocols negotiatedProtocol,
        RuntimeTls12CipherSuite cipherSuite,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> transcriptHash,
        bool isClient)
        => Expand(
            negotiatedProtocol,
            cipherSuite.HashAlgorithm,
            masterSecret,
            isClient ? ClientFinishedLabel : ServerFinishedLabel,
            transcriptHash,
            12);

    private static byte[] Expand(
        SslProtocols negotiatedProtocol,
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> seed,
        int length)
    {
        var labelAndSeed = new byte[label.Length + seed.Length];
        label.CopyTo(labelAndSeed);
        seed.CopyTo(labelAndSeed.AsSpan(label.Length));
        return negotiatedProtocol == SslProtocols.Tls12
            ? PHash(hashAlgorithm, secret, labelAndSeed, length)
            : LegacyPHash(secret, labelAndSeed, length);
    }

    private static byte[] PHash(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> seed,
        int length)
    {
        var result = new byte[length];
        var previous = RuntimeCryptographicHashes.Hmac(hashAlgorithm, secret, seed);
        var written = 0;
        while (written < length)
        {
            var input = new byte[previous.Length + seed.Length];
            previous.CopyTo(input, 0);
            seed.CopyTo(input.AsSpan(previous.Length));
            var block = RuntimeCryptographicHashes.Hmac(hashAlgorithm, secret, input);
            var copyLength = Math.Min(block.Length, length - written);
            block.AsSpan(0, copyLength).CopyTo(result.AsSpan(written, copyLength));
            written += copyLength;
            previous = RuntimeCryptographicHashes.Hmac(hashAlgorithm, secret, previous);
        }

        return result;
    }

    private static byte[] LegacyPHash(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> seed,
        int length)
    {
        var halfLength = (secret.Length + 1) / 2;
        var md5 = PHash(HashAlgorithmName.MD5, secret[..halfLength], seed, length);
        var sha1 = PHash(HashAlgorithmName.SHA1, secret[^halfLength..], seed, length);
        for (var index = 0; index < md5.Length; index++)
        {
            md5[index] ^= sha1[index];
        }

        return md5;
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)((value >> 16) & 0xFF);
        destination[1] = (byte)((value >> 8) & 0xFF);
        destination[2] = (byte)(value & 0xFF);
    }
}

internal sealed record RuntimeTls12KeyBlock(
    byte[] ClientMacKey,
    byte[] ServerMacKey,
    byte[] ClientWriteKey,
    byte[] ServerWriteKey,
    byte[] ClientWriteIv,
    byte[] ServerWriteIv);

#pragma warning restore SYSLIB0039

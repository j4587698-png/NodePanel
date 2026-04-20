using System.Buffers.Binary;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeTls12TrafficProtector : IDisposable
{
    private readonly RuntimeTls12CipherSuite _cipherSuite;
    private readonly byte[] _iv;
    private readonly byte[] _macKey;
    private readonly ushort _recordVersion;
    private readonly bool _useExplicitCbcIv;
    private readonly AesGcm? _aesGcm;
    private readonly ChaCha20Poly1305? _chaCha20Poly1305;
    private readonly SymmetricAlgorithm? _cbcCipher;

    private ulong _sequenceNumber;
    private int _disposed;
    private int _suppressDisposeOnce;

    private RuntimeTls12TrafficProtector(
        RuntimeTls12CipherSuite cipherSuite,
        byte[] key,
        byte[] iv,
        byte[] macKey,
        ushort recordVersion,
        bool useExplicitCbcIv)
    {
        _cipherSuite = cipherSuite;
        _iv = iv.ToArray();
        _macKey = macKey.ToArray();
        _recordVersion = recordVersion;
        _useExplicitCbcIv = useExplicitCbcIv;
        switch (cipherSuite.CipherKind)
        {
            case RuntimeTls12CipherKind.AesGcm:
                _aesGcm = new AesGcm(key, tagSizeInBytes: 16);
                break;
            case RuntimeTls12CipherKind.ChaCha20Poly1305:
                _chaCha20Poly1305 = new ChaCha20Poly1305(key);
                break;
            case RuntimeTls12CipherKind.AesCbc:
                _cbcCipher = Aes.Create();
                _cbcCipher.Mode = CipherMode.CBC;
                _cbcCipher.Padding = PaddingMode.None;
                _cbcCipher.Key = key.ToArray();
                break;
            case RuntimeTls12CipherKind.TripleDesCbc:
                _cbcCipher = TripleDES.Create();
                _cbcCipher.Mode = CipherMode.CBC;
                _cbcCipher.Padding = PaddingMode.None;
                _cbcCipher.Key = key.ToArray();
                break;
        }
    }

    public static RuntimeTls12TrafficProtector Create(
        RuntimeTls12CipherSuite cipherSuite,
        byte[] key,
        byte[] iv,
        byte[]? macKey = null,
        ushort recordVersion = 0x0303,
        bool useExplicitCbcIv = true)
        => new(cipherSuite, key, iv, macKey ?? [], recordVersion, useExplicitCbcIv);

    public byte[] Encrypt(RuntimeTls13RecordType recordType, ReadOnlySpan<byte> plaintext)
    {
        ThrowIfDisposed();

        Span<byte> sequenceNumber = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceNumber, _sequenceNumber);
        byte[] recordPayload = _cipherSuite.CipherKind switch
        {
            RuntimeTls12CipherKind.AesGcm => EncryptAesGcm(sequenceNumber, recordType, plaintext),
            RuntimeTls12CipherKind.ChaCha20Poly1305 => EncryptChaCha20Poly1305(sequenceNumber, recordType, plaintext),
            RuntimeTls12CipherKind.AesCbc or RuntimeTls12CipherKind.TripleDesCbc => EncryptCbc(sequenceNumber, recordType, plaintext),
            _ => throw new NotSupportedException($"Unsupported TLS 1.2 cipher kind '{_cipherSuite.CipherKind}'.")
        };

        AdvanceSequenceNumber();
        return BuildRecord(recordType, recordPayload);
    }

    public byte[] Decrypt(RuntimeTls13RecordType recordType, ReadOnlySpan<byte> payload)
    {
        ThrowIfDisposed();

        Span<byte> sequenceNumber = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(sequenceNumber, _sequenceNumber);
        byte[] plaintext = _cipherSuite.CipherKind switch
        {
            RuntimeTls12CipherKind.AesGcm => DecryptAesGcm(sequenceNumber, recordType, payload),
            RuntimeTls12CipherKind.ChaCha20Poly1305 => DecryptChaCha20Poly1305(sequenceNumber, recordType, payload),
            RuntimeTls12CipherKind.AesCbc or RuntimeTls12CipherKind.TripleDesCbc => DecryptCbc(sequenceNumber, recordType, payload),
            _ => throw new NotSupportedException($"Unsupported TLS 1.2 cipher kind '{_cipherSuite.CipherKind}'.")
        };

        AdvanceSequenceNumber();
        return plaintext;
    }

    public RuntimeTls12TrafficProtector Detach()
    {
        ThrowIfDisposed();
        Interlocked.Exchange(ref _suppressDisposeOnce, 1);
        return this;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _suppressDisposeOnce, 0) != 0)
        {
            return;
        }

        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _aesGcm?.Dispose();
        _chaCha20Poly1305?.Dispose();
        _cbcCipher?.Dispose();
    }

    private byte[] EncryptAesGcm(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> plaintext)
    {
        const int explicitNonceLength = 8;
        var recordPayload = new byte[explicitNonceLength + plaintext.Length + 16];
        var ciphertext = recordPayload.AsSpan(explicitNonceLength, plaintext.Length);
        var tag = recordPayload.AsSpan(explicitNonceLength + plaintext.Length, 16);
        var additionalData = BuildAdditionalData(sequenceNumber, recordType, plaintext.Length);
        sequenceNumber.CopyTo(recordPayload);

        Span<byte> nonce = stackalloc byte[12];
        _iv.CopyTo(nonce);
        sequenceNumber.CopyTo(nonce[4..]);
        _aesGcm!.Encrypt(nonce, plaintext, ciphertext, tag, additionalData);
        return recordPayload;
    }

    private byte[] DecryptAesGcm(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> payload)
    {
        const int explicitNonceLength = 8;
        if (payload.Length < explicitNonceLength + 16)
        {
            throw new AuthenticationException("The TLS 1.2 encrypted record is truncated.");
        }

        var ciphertext = payload.Slice(explicitNonceLength, payload.Length - explicitNonceLength - 16);
        var tag = payload[^16..];
        var plaintext = new byte[ciphertext.Length];
        var additionalData = BuildAdditionalData(sequenceNumber, recordType, plaintext.Length);

        Span<byte> nonce = stackalloc byte[12];
        _iv.CopyTo(nonce);
        payload[..explicitNonceLength].CopyTo(nonce[4..]);
        _aesGcm!.Decrypt(nonce, ciphertext, tag, plaintext, additionalData);
        return plaintext;
    }

    private byte[] EncryptChaCha20Poly1305(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> plaintext)
    {
        var recordPayload = new byte[plaintext.Length + 16];
        var ciphertext = recordPayload.AsSpan(0, plaintext.Length);
        var tag = recordPayload.AsSpan(plaintext.Length, 16);
        var additionalData = BuildAdditionalData(sequenceNumber, recordType, plaintext.Length);

        Span<byte> nonce = stackalloc byte[12];
        _iv.CopyTo(nonce);
        for (var index = 0; index < sequenceNumber.Length; index++)
        {
            nonce[4 + index] ^= sequenceNumber[index];
        }

        _chaCha20Poly1305!.Encrypt(nonce, plaintext, ciphertext, tag, additionalData);
        return recordPayload;
    }

    private byte[] DecryptChaCha20Poly1305(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 16)
        {
            throw new AuthenticationException("The TLS 1.2 encrypted record is truncated.");
        }

        var ciphertext = payload[..^16];
        var tag = payload[^16..];
        var plaintext = new byte[ciphertext.Length];
        var additionalData = BuildAdditionalData(sequenceNumber, recordType, plaintext.Length);

        Span<byte> nonce = stackalloc byte[12];
        _iv.CopyTo(nonce);
        for (var index = 0; index < sequenceNumber.Length; index++)
        {
            nonce[4 + index] ^= sequenceNumber[index];
        }

        _chaCha20Poly1305!.Decrypt(nonce, ciphertext, tag, plaintext, additionalData);
        return plaintext;
    }

    private byte[] EncryptCbc(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> plaintext)
    {
        if (_cipherSuite.RecordMacHashAlgorithm is null)
        {
            throw new AuthenticationException($"TLS 1.2 CBC suite '{_cipherSuite.Name}' is missing a record MAC algorithm.");
        }

        var mac = ComputeTls10Mac(sequenceNumber, recordType, plaintext);
        var blockSize = _cipherSuite.IvLength;
        var plaintextLength = plaintext.Length + mac.Length;
        var paddingLength = blockSize - (plaintextLength % blockSize);
        var encryptedPayload = new byte[plaintextLength + paddingLength];
        plaintext.CopyTo(encryptedPayload);
        mac.CopyTo(encryptedPayload.AsSpan(plaintext.Length));
        encryptedPayload.AsSpan(plaintextLength, paddingLength).Fill(checked((byte)(paddingLength - 1)));

        if (_useExplicitCbcIv)
        {
            var explicitIv = new byte[blockSize];
            RandomNumberGenerator.Fill(explicitIv);
            var ciphertext = TransformCbc(encrypt: true, encryptedPayload, explicitIv);
            var recordPayload = new byte[explicitIv.Length + ciphertext.Length];
            explicitIv.CopyTo(recordPayload, 0);
            ciphertext.CopyTo(recordPayload, explicitIv.Length);
            return recordPayload;
        }

        var ciphertextWithoutExplicitIv = TransformCbc(encrypt: true, encryptedPayload, _iv);
        ciphertextWithoutExplicitIv.AsSpan(ciphertextWithoutExplicitIv.Length - blockSize, blockSize).CopyTo(_iv);
        return ciphertextWithoutExplicitIv;
    }

    private byte[] DecryptCbc(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> payload)
    {
        if (_cipherSuite.RecordMacHashAlgorithm is null)
        {
            throw new AuthenticationException($"TLS 1.2 CBC suite '{_cipherSuite.Name}' is missing a record MAC algorithm.");
        }

        var blockSize = _cipherSuite.IvLength;
        var macSize = _cipherSuite.MacKeyLength;
        var minimumPayloadLength = (_useExplicitCbcIv ? blockSize : 0) + RoundUp(macSize + 1, blockSize);
        if (payload.Length < minimumPayloadLength)
        {
            throw new AuthenticationException("The TLS 1.2 encrypted record is truncated.");
        }

        byte[] iv;
        ReadOnlySpan<byte> ciphertext;
        if (_useExplicitCbcIv)
        {
            iv = payload[..blockSize].ToArray();
            ciphertext = payload[blockSize..];
        }
        else
        {
            iv = _iv.ToArray();
            ciphertext = payload;
        }

        if (ciphertext.Length == 0 || ciphertext.Length % blockSize != 0)
        {
            throw new AuthenticationException("The TLS 1.2 encrypted record has an invalid CBC payload length.");
        }

        if (!_useExplicitCbcIv)
        {
            ciphertext[^blockSize..].CopyTo(_iv);
        }

        var decryptedPayload = TransformCbc(encrypt: false, ciphertext, iv);
        var (paddingLength, paddingGood) = ExtractPadding(decryptedPayload);
        var contentLength = decryptedPayload.Length - macSize - paddingLength;
        if (contentLength < 0)
        {
            contentLength = 0;
        }

        var remoteMac = decryptedPayload.AsSpan(contentLength, macSize);
        var plaintext = decryptedPayload.AsSpan(0, contentLength);
        var trailingBytes = decryptedPayload.AsSpan(contentLength + macSize);
        var localMac = ComputeTls10Mac(sequenceNumber, recordType, plaintext, trailingBytes);
        var macGood = CryptographicOperations.FixedTimeEquals(localMac, remoteMac) ? 1 : 0;
        var macAndPaddingGood = macGood & paddingGood;
        if (macAndPaddingGood != 1)
        {
            throw new AuthenticationException("The TLS 1.2 CBC record MAC or padding is invalid.");
        }

        return plaintext.ToArray();
    }

    private byte[] ComputeTls10Mac(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> extra = default)
    {
        if (_cipherSuite.RecordMacHashAlgorithm is null)
        {
            return [];
        }

        var header = BuildRecordHeader(recordType, data.Length);
        var buffer = new byte[sequenceNumber.Length + header.Length + data.Length];
        sequenceNumber.CopyTo(buffer);
        header.CopyTo(buffer.AsSpan(sequenceNumber.Length));
        data.CopyTo(buffer.AsSpan(sequenceNumber.Length + header.Length));

        var mac = RuntimeCryptographicHashes.Hmac(
            _cipherSuite.RecordMacHashAlgorithm.Value,
            _macKey,
            buffer);

        if (!extra.IsEmpty)
        {
            // Go's tls10MAC feeds the trailing bytes into the live HMAC state
            // after materializing the digest. .NET doesn't expose a cloneable
            // HMAC state here, so we replay the same continuation work and
            // discard the result to keep the extra-data path observable.
            var extendedBuffer = new byte[buffer.Length + extra.Length];
            buffer.CopyTo(extendedBuffer, 0);
            extra.CopyTo(extendedBuffer.AsSpan(buffer.Length));
            _ = RuntimeCryptographicHashes.Hmac(
                _cipherSuite.RecordMacHashAlgorithm.Value,
                _macKey,
                extendedBuffer);
        }

        return mac;
    }

    private byte[] TransformCbc(bool encrypt, ReadOnlySpan<byte> payload, byte[] iv)
    {
        using var transform = encrypt
            ? _cbcCipher!.CreateEncryptor(_cbcCipher.Key, iv)
            : _cbcCipher!.CreateDecryptor(_cbcCipher.Key, iv);
        return transform.TransformFinalBlock(payload.ToArray(), 0, payload.Length);
    }

    private void AdvanceSequenceNumber()
    {
        _sequenceNumber++;
        if (_sequenceNumber == 0)
        {
            throw new AuthenticationException("The TLS 1.2 record sequence number wrapped.");
        }
    }

    private byte[] BuildAdditionalData(
        ReadOnlySpan<byte> sequenceNumber,
        RuntimeTls13RecordType recordType,
        int plaintextLength)
    {
        var additionalData = new byte[13];
        sequenceNumber.CopyTo(additionalData);
        var recordHeader = BuildRecordHeader(recordType, plaintextLength);
        recordHeader.CopyTo(additionalData.AsSpan(sequenceNumber.Length));
        return additionalData;
    }

    private byte[] BuildRecord(RuntimeTls13RecordType recordType, ReadOnlySpan<byte> payload)
    {
        var record = new byte[5 + payload.Length];
        var header = BuildRecordHeader(recordType, payload.Length);
        header.CopyTo(record);
        payload.CopyTo(record.AsSpan(header.Length));
        return record;
    }

    private byte[] BuildRecordHeader(RuntimeTls13RecordType recordType, int payloadLength)
    {
        var header = new byte[5];
        header[0] = (byte)recordType;
        header[1] = (byte)(_recordVersion >> 8);
        header[2] = (byte)_recordVersion;
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(3, 2), checked((ushort)payloadLength));
        return header;
    }

    private static (int PaddingLength, int PaddingGood) ExtractPadding(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
        {
            return (0, 0);
        }

        var paddingByte = payload[^1];
        uint remaining = (uint)(payload.Length - 1) - paddingByte;
        var good = (byte)(unchecked((int)(~remaining)) >> 31);

        var bytesToCheck = Math.Min(256, payload.Length);
        for (var index = 0; index < bytesToCheck; index++)
        {
            uint delta = paddingByte - (uint)index;
            var mask = (byte)(unchecked((int)(~delta)) >> 31);
            var current = payload[payload.Length - 1 - index];
            good &= (byte)~((mask & paddingByte) ^ (mask & current));
        }

        good &= (byte)(good << 4);
        good &= (byte)(good << 2);
        good &= (byte)(good << 1);
        var paddingGood = (int)((sbyte)good >> 7) & 0x01;
        if (paddingGood == 0)
        {
            paddingByte = 0;
        }

        return (paddingByte + 1, paddingGood);
    }

    private static int RoundUp(int value, int alignment)
        => value + (alignment - (value % alignment)) % alignment;

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(RuntimeTls12TrafficProtector));
        }
    }
}

internal static class RuntimeTls12AlertExceptionFactory
{
    public static Exception Create(ReadOnlySpan<byte> payload, bool encrypted)
    {
        var prefix = encrypted ? "Encrypted TLS 1.2 alert" : "TLS 1.2 alert";
        if (payload.Length < 2)
        {
            return new AuthenticationException($"{prefix}: payload is truncated.");
        }

        return new AuthenticationException($"{prefix}: {Describe(payload[1])} (0x{payload[1]:X2}).");
    }

    private static string Describe(byte description)
        => description switch
        {
            0x00 => "close_notify",
            0x0A => "unexpected_message",
            0x14 => "bad_record_mac",
            0x15 => "decryption_failed",
            0x16 => "record_overflow",
            0x28 => "handshake_failure",
            0x2A => "bad_certificate",
            0x2B => "unsupported_certificate",
            0x2C => "certificate_revoked",
            0x2D => "certificate_expired",
            0x2E => "certificate_unknown",
            0x2F => "illegal_parameter",
            0x30 => "unknown_ca",
            0x46 => "protocol_version",
            0x47 => "insufficient_security",
            0x50 => "internal_error",
            0x6D => "missing_extension",
            0x70 => "unrecognized_name",
            _ => "unknown_alert"
        };
}

internal sealed class RuntimeTls12DuplexStream : Stream
{
    private readonly Stream _innerStream;
    private readonly RuntimeTls12TrafficProtector _readProtector;
    private readonly RuntimeTls12TrafficProtector _writeProtector;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ResizableByteQueue _applicationBuffer = new();

    private int _disposed;
    private bool _receivedCloseNotify;

    public RuntimeTls12DuplexStream(
        Stream innerStream,
        RuntimeTls12TrafficProtector readProtector,
        RuntimeTls12TrafficProtector writeProtector)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _readProtector = readProtector ?? throw new ArgumentNullException(nameof(readProtector));
        _writeProtector = writeProtector ?? throw new ArgumentNullException(nameof(writeProtector));
    }

    public override bool CanRead => Volatile.Read(ref _disposed) == 0 && _innerStream.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => Volatile.Read(ref _disposed) == 0 && _innerStream.CanWrite;

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

    public override void Flush()
        => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _innerStream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override int Read(Span<byte> buffer)
    {
        var temp = new byte[buffer.Length];
        var read = ReadAsync(temp.AsMemory(0, temp.Length), CancellationToken.None).AsTask().GetAwaiter().GetResult();
        temp.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        while (_applicationBuffer.Length == 0)
        {
            if (!await ReadApplicationDataAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }

        var count = Math.Min(buffer.Length, _applicationBuffer.Length);
        _applicationBuffer.Slice(0, count).CopyTo(buffer.Span);
        _applicationBuffer.Consume(count);
        return count;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray().AsMemory(), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
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
            while (!remaining.IsEmpty)
            {
                var currentLength = Math.Min(remaining.Length, 16 * 1024);
                var record = _writeProtector.Encrypt(
                    RuntimeTls13RecordType.ApplicationData,
                    remaining.Span[..currentLength]);
                await _innerStream.WriteAsync(record.AsMemory(0, record.Length), cancellationToken).ConfigureAwait(false);
                remaining = remaining[currentLength..];
            }

            await _innerStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (!disposing ||
            Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            base.Dispose(disposing);
            return;
        }

        TrySendCloseNotifyAsync().GetAwaiter().GetResult();
        _writeLock.Dispose();
        _readProtector.Dispose();
        _writeProtector.Dispose();
        _innerStream.Dispose();
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await TrySendCloseNotifyAsync().ConfigureAwait(false);
        _writeLock.Dispose();
        _readProtector.Dispose();
        _writeProtector.Dispose();
        await _innerStream.DisposeAsync().ConfigureAwait(false);
    }

    private async Task<bool> ReadApplicationDataAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var record = await RuntimeTls13Record.ReadAsync(
                    _innerStream,
                    allowEof: false,
                    cancellationToken)
                .ConfigureAwait(false);
            if (record is null)
            {
                return false;
            }

            switch (record.Type)
            {
                case RuntimeTls13RecordType.ChangeCipherSpec when RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload):
                    continue;
                case RuntimeTls13RecordType.Alert:
                    var alertPayload = _readProtector.Decrypt(RuntimeTls13RecordType.Alert, record.Payload);
                    if (alertPayload.Length >= 2 &&
                        alertPayload[1] == 0x00)
                    {
                        _receivedCloseNotify = true;
                        return false;
                    }

                    throw RuntimeTls12AlertExceptionFactory.Create(alertPayload, encrypted: true);
                case RuntimeTls13RecordType.Handshake:
                    _ = _readProtector.Decrypt(RuntimeTls13RecordType.Handshake, record.Payload);
                    continue;
                case RuntimeTls13RecordType.ApplicationData:
                    var applicationPayload = _readProtector.Decrypt(RuntimeTls13RecordType.ApplicationData, record.Payload);
                    if (applicationPayload.Length == 0)
                    {
                        continue;
                    }

                    _applicationBuffer.Append(applicationPayload);
                    return true;
                default:
                    throw new AuthenticationException(
                        $"Unexpected TLS record '{record.Type}' after TLS 1.2 handshake completion.");
            }
        }
    }

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
            throw new ObjectDisposedException(nameof(RuntimeTls12DuplexStream));
        }
    }
}

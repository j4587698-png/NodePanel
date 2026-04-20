using System.Buffers.Binary;
using System.Security.Cryptography;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class ShadowsocksAccount
{
    private ShadowsocksAccount(
        string cipher,
        ShadowsocksCipherKind kind,
        byte[] key)
    {
        Cipher = cipher;
        Kind = kind;
        Key = key;
    }

    public string Cipher { get; }

    public ShadowsocksCipherKind Kind { get; }

    public byte[] Key { get; }

    public bool IsAead => Kind != ShadowsocksCipherKind.None;

    public int KeySize => Kind switch
    {
        ShadowsocksCipherKind.Aes128Gcm => 16,
        ShadowsocksCipherKind.Aes256Gcm => 32,
        ShadowsocksCipherKind.ChaCha20Poly1305 => 32,
        ShadowsocksCipherKind.XChaCha20Poly1305 => 32,
        _ => 0
    };

    public int SaltSize => KeySize;

    public static ShadowsocksAccount Create(string cipher, string password)
    {
        var normalizedCipher = ShadowsocksCipherTypes.Normalize(cipher);
        var kind = normalizedCipher switch
        {
            ShadowsocksCipherTypes.Aes128Gcm => ShadowsocksCipherKind.Aes128Gcm,
            ShadowsocksCipherTypes.Aes256Gcm => ShadowsocksCipherKind.Aes256Gcm,
            ShadowsocksCipherTypes.ChaCha20Poly1305 => ShadowsocksCipherKind.ChaCha20Poly1305,
            ShadowsocksCipherTypes.XChaCha20Poly1305 => ShadowsocksCipherKind.XChaCha20Poly1305,
            ShadowsocksCipherTypes.None => ShadowsocksCipherKind.None,
            _ => throw new NotSupportedException($"Unsupported Shadowsocks cipher: {cipher}.")
        };

        if (kind != ShadowsocksCipherKind.None &&
            string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("Shadowsocks password is required for AEAD ciphers.");
        }

        return new ShadowsocksAccount(
            normalizedCipher,
            kind,
            DerivePasswordKey(password ?? string.Empty, kind switch
            {
                ShadowsocksCipherKind.Aes128Gcm => 16,
                ShadowsocksCipherKind.Aes256Gcm => 32,
                ShadowsocksCipherKind.ChaCha20Poly1305 => 32,
                ShadowsocksCipherKind.XChaCha20Poly1305 => 32,
                _ => 0
            }));
    }

    public ShadowsocksAeadSession CreateAeadSession(ReadOnlySpan<byte> salt)
    {
        if (!IsAead)
        {
            throw new InvalidOperationException("Shadowsocks AEAD session is not available for cipher 'none'.");
        }

        if (salt.Length != SaltSize)
        {
            throw new InvalidDataException("Shadowsocks salt length is invalid.");
        }

        var subkey = DeriveSubkey(Key, salt, KeySize);
        return new ShadowsocksAeadSession(
            Kind switch
            {
                ShadowsocksCipherKind.Aes128Gcm or ShadowsocksCipherKind.Aes256Gcm
                    => new AesGcmShadowsocksAead(subkey),
                ShadowsocksCipherKind.ChaCha20Poly1305
                    => new ChaCha20Poly1305ShadowsocksAead(subkey),
                ShadowsocksCipherKind.XChaCha20Poly1305
                    => new XChaCha20Poly1305ShadowsocksAead(subkey),
                _ => throw new InvalidOperationException($"Unsupported Shadowsocks AEAD cipher kind: {Kind}.")
            });
    }

    private static byte[] DerivePasswordKey(string password, int keySize)
    {
        if (keySize <= 0)
        {
            return Array.Empty<byte>();
        }

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        var key = new byte[keySize];
        var offset = 0;
        byte[] previous = [];

        while (offset < keySize)
        {
            using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            if (previous.Length > 0)
            {
                md5.AppendData(previous);
            }

            md5.AppendData(passwordBytes);
            previous = md5.GetHashAndReset();

            var toCopy = Math.Min(previous.Length, keySize - offset);
            previous.AsSpan(0, toCopy).CopyTo(key.AsSpan(offset));
            offset += toCopy;
        }

        return key;
    }

    private static byte[] DeriveSubkey(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> salt,
        int outputLength)
    {
        if (outputLength <= 0)
        {
            return Array.Empty<byte>();
        }

        var saltBytes = salt.ToArray();
        var keyBytes = key.ToArray();
        byte[] pseudorandomKey;
        using (var extract = new HMACSHA1(saltBytes))
        {
            pseudorandomKey = extract.ComputeHash(keyBytes);
        }

        var infoBytes = "ss-subkey"u8.ToArray();
        var result = new byte[outputLength];
        var previous = Array.Empty<byte>();
        var offset = 0;
        byte counter = 1;

        using var expand = new HMACSHA1(pseudorandomKey);
        while (offset < outputLength)
        {
            var input = new byte[previous.Length + infoBytes.Length + 1];
            previous.CopyTo(input, 0);
            infoBytes.CopyTo(input, previous.Length);
            input[^1] = counter;
            previous = expand.ComputeHash(input);

            var toCopy = Math.Min(previous.Length, outputLength - offset);
            previous.AsSpan(0, toCopy).CopyTo(result.AsSpan(offset));
            offset += toCopy;
            counter++;
        }

        CryptographicOperations.ZeroMemory(pseudorandomKey);
        return result;
    }
}

internal static class ShadowsocksProtocolCodec
{
    public static async ValueTask<ShadowsocksClientTcpStream> OpenClientTcpStreamAsync(
        Stream innerStream,
        ShadowsocksAccount account,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentNullException.ThrowIfNull(account);

        IShadowsocksStreamWriter requestWriter;
        if (account.IsAead)
        {
            var salt = RandomNumberGenerator.GetBytes(account.SaltSize);
            await innerStream.WriteAsync(salt, cancellationToken).ConfigureAwait(false);
            requestWriter = new ShadowsocksAeadStreamWriter(innerStream, account.CreateAeadSession(salt));
        }
        else
        {
            requestWriter = new ShadowsocksPlainStreamWriter(innerStream);
        }

        var requestHeader = EncodeTarget(host, port);
        await requestWriter.WriteAsync(requestHeader, cancellationToken).ConfigureAwait(false);
        await innerStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        return new ShadowsocksClientTcpStream(innerStream, account, requestWriter);
    }

    public static async ValueTask<ShadowsocksAcceptedTcpSession> AcceptServerTcpStreamAsync(
        Stream innerStream,
        ShadowsocksAccount account,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentNullException.ThrowIfNull(account);

        IShadowsocksStreamReader requestReader;
        if (account.IsAead)
        {
            var salt = new byte[account.SaltSize];
            await ReadExactAsync(innerStream, salt, cancellationToken).ConfigureAwait(false);
            requestReader = new ShadowsocksAeadStreamReader(innerStream, account.CreateAeadSession(salt));
        }
        else
        {
            requestReader = new ShadowsocksPlainStreamReader(innerStream);
        }

        var firstChunk = await ReadFirstRequestChunkAsync(requestReader, cancellationToken).ConfigureAwait(false);
        var target = DecodeTarget(firstChunk, out var consumed);
        var prefixedPayload = consumed < firstChunk.Length
            ? firstChunk.AsSpan(consumed).ToArray()
            : Array.Empty<byte>();

        IShadowsocksStreamWriter responseWriter;
        if (account.IsAead)
        {
            var responseSalt = RandomNumberGenerator.GetBytes(account.SaltSize);
            await innerStream.WriteAsync(responseSalt, cancellationToken).ConfigureAwait(false);
            responseWriter = new ShadowsocksAeadStreamWriter(innerStream, account.CreateAeadSession(responseSalt));
        }
        else
        {
            responseWriter = new ShadowsocksPlainStreamWriter(innerStream);
        }

        Stream readStream = new ShadowsocksReadStream(requestReader);
        if (prefixedPayload.Length > 0)
        {
            readStream = new PrefixedReadStream(readStream, prefixedPayload);
        }

        return new ShadowsocksAcceptedTcpSession(
            new ShadowsocksTarget(target.Host, target.Port),
            new ShadowsocksServerTcpStream(innerStream, readStream, responseWriter));
    }

    public static byte[] EncodeUdpPacket(
        ShadowsocksAccount account,
        string host,
        int port,
        ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(account);

        var target = EncodeTarget(host, port);
        if (!account.IsAead)
        {
            var buffer = new byte[target.Length + payload.Length];
            target.CopyTo(buffer, 0);
            payload.CopyTo(buffer.AsSpan(target.Length));
            return buffer;
        }

        var salt = RandomNumberGenerator.GetBytes(account.SaltSize);
        using var session = account.CreateAeadSession(salt);
        var plaintext = new byte[target.Length + payload.Length];
        target.CopyTo(plaintext, 0);
        payload.CopyTo(plaintext.AsSpan(target.Length));
        var ciphertext = session.EncryptPayload(plaintext);

        var packet = new byte[salt.Length + ciphertext.Length];
        salt.CopyTo(packet, 0);
        ciphertext.CopyTo(packet, salt.Length);
        return packet;
    }

    public static ShadowsocksUdpPacket DecodeUdpPacket(
        ShadowsocksAccount account,
        ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(account);

        ReadOnlySpan<byte> plaintext;
        if (account.IsAead)
        {
            if (payload.Length <= account.SaltSize)
            {
                throw new InvalidDataException("Shadowsocks UDP payload is incomplete.");
            }

            var salt = payload[..account.SaltSize];
            using var session = account.CreateAeadSession(salt);
            plaintext = session.DecryptPayload(payload[account.SaltSize..]);
        }
        else
        {
            plaintext = payload;
        }

        var target = DecodeTarget(plaintext, out var consumed);
        return new ShadowsocksUdpPacket(
            target.Host,
            target.Port,
            plaintext[consumed..].ToArray());
    }

    public static byte[] EncodeTarget(string host, int port)
    {
        var length = Socks5AddressCodec.GetSerializedLength(host);
        var buffer = new byte[length];
        _ = Socks5AddressCodec.WriteAddressPort(buffer, host, port);
        return buffer;
    }

    public static ShadowsocksTarget DecodeTarget(
        ReadOnlySpan<byte> buffer,
        out int consumed)
    {
        var target = Socks5AddressCodec.ReadAddressPort(buffer);
        consumed = target.Consumed;
        return new ShadowsocksTarget(target.Host, target.Port);
    }

    internal static async ValueTask<bool> TryReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (offset == 0)
                {
                    return false;
                }

                throw new EndOfStreamException("Shadowsocks payload ended unexpectedly.");
            }

            offset += read;
        }

        return true;
    }

    internal static async ValueTask ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        if (!await TryReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false))
        {
            throw new EndOfStreamException("Shadowsocks payload ended unexpectedly.");
        }
    }

    private static async ValueTask<byte[]> ReadFirstRequestChunkAsync(
        IShadowsocksStreamReader reader,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read <= 0)
        {
            throw new InvalidDataException("Shadowsocks TCP request header is missing.");
        }

        return buffer.AsSpan(0, read).ToArray();
    }
}

internal sealed record ShadowsocksTarget(string Host, int Port);

internal sealed record ShadowsocksUdpPacket(string Host, int Port, byte[] Payload);

internal sealed record ShadowsocksAcceptedTcpSession(
    ShadowsocksTarget Destination,
    Stream Stream);

internal enum ShadowsocksCipherKind
{
    None = 0,
    Aes128Gcm = 1,
    Aes256Gcm = 2,
    ChaCha20Poly1305 = 3,
    XChaCha20Poly1305 = 4
}

internal interface IShadowsocksStreamReader : IDisposable
{
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken);
}

internal interface IShadowsocksStreamWriter : IDisposable
{
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken);
}

internal sealed class ShadowsocksClientTcpStream : Stream, IInnerStreamAccessor
{
    private readonly ShadowsocksAccount _account;
    private readonly Stream _innerStream;
    private readonly SemaphoreSlim _readerInitializationLock = new(1, 1);
    private readonly IShadowsocksStreamWriter _requestWriter;

    private IShadowsocksStreamReader? _responseReader;
    private int _disposed;

    internal ShadowsocksClientTcpStream(
        Stream innerStream,
        ShadowsocksAccount account,
        IShadowsocksStreamWriter requestWriter)
    {
        _innerStream = innerStream;
        _account = account;
        _requestWriter = requestWriter;
    }

    public Stream InnerStream => _innerStream;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

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

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _requestWriter.WriteAsync(buffer, cancellationToken);
    }

    public override void Flush()
        => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _innerStream.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _responseReader?.Dispose();
        _requestWriter.Dispose();
        _readerInitializationLock.Dispose();
        await _innerStream.DisposeAsync().ConfigureAwait(false);
    }

    private async ValueTask<int> ReadCoreAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        var responseReader = await EnsureResponseReaderAsync(cancellationToken).ConfigureAwait(false);
        return await responseReader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<IShadowsocksStreamReader> EnsureResponseReaderAsync(CancellationToken cancellationToken)
    {
        if (_responseReader is not null)
        {
            return _responseReader;
        }

        await _readerInitializationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_responseReader is not null)
            {
                return _responseReader;
            }

            if (_account.IsAead)
            {
                var salt = new byte[_account.SaltSize];
                await ShadowsocksProtocolCodec.ReadExactAsync(_innerStream, salt, cancellationToken).ConfigureAwait(false);
                _responseReader = new ShadowsocksAeadStreamReader(
                    _innerStream,
                    _account.CreateAeadSession(salt));
            }
            else
            {
                _responseReader = new ShadowsocksPlainStreamReader(_innerStream);
            }

            return _responseReader;
        }
        finally
        {
            _readerInitializationLock.Release();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(ShadowsocksClientTcpStream));
        }
    }
}

internal sealed class ShadowsocksServerTcpStream : Stream, IInnerStreamAccessor
{
    private readonly Stream _innerStream;
    private readonly Stream _readStream;
    private readonly IShadowsocksStreamWriter _responseWriter;
    private int _disposed;

    internal ShadowsocksServerTcpStream(
        Stream innerStream,
        Stream readStream,
        IShadowsocksStreamWriter responseWriter)
    {
        _innerStream = innerStream;
        _readStream = readStream;
        _responseWriter = responseWriter;
    }

    public Stream InnerStream => _innerStream;

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

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
        => _readStream.Read(buffer, offset, count);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _readStream.ReadAsync(buffer, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        return _responseWriter.WriteAsync(buffer, cancellationToken);
    }

    public override void Flush()
        => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _innerStream.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _responseWriter.Dispose();
        await _readStream.DisposeAsync().ConfigureAwait(false);
        await _innerStream.DisposeAsync().ConfigureAwait(false);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(ShadowsocksServerTcpStream));
        }
    }
}

internal sealed class ShadowsocksReadStream : Stream
{
    private readonly IShadowsocksStreamReader _reader;

    public ShadowsocksReadStream(IShadowsocksStreamReader reader)
    {
        _reader = reader;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _reader.ReadAsync(buffer, cancellationToken);

    public override void Flush()
        => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();

    public override ValueTask DisposeAsync()
    {
        _reader.Dispose();
        return ValueTask.CompletedTask;
    }
}

internal sealed class ShadowsocksPlainStreamReader : IShadowsocksStreamReader
{
    private readonly Stream _innerStream;

    public ShadowsocksPlainStreamReader(Stream innerStream)
    {
        _innerStream = innerStream;
    }

    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        => _innerStream.ReadAsync(buffer, cancellationToken);

    public void Dispose()
    {
    }
}

internal sealed class ShadowsocksPlainStreamWriter : IShadowsocksStreamWriter
{
    private readonly Stream _innerStream;

    public ShadowsocksPlainStreamWriter(Stream innerStream)
    {
        _innerStream = innerStream;
    }

    public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        => _innerStream.WriteAsync(buffer, cancellationToken);

    public void Dispose()
    {
    }
}

internal sealed class ShadowsocksAeadStreamReader : IShadowsocksStreamReader
{
    private readonly Stream _innerStream;
    private readonly ShadowsocksAeadSession _session;

    private byte[]? _currentChunk;
    private int _currentOffset;
    private bool _completed;

    public ShadowsocksAeadStreamReader(Stream innerStream, ShadowsocksAeadSession session)
    {
        _innerStream = innerStream;
        _session = session;
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_completed)
        {
            return 0;
        }

        if (_currentChunk is null || _currentOffset >= _currentChunk.Length)
        {
            var nextChunk = await ReadNextChunkAsync(cancellationToken).ConfigureAwait(false);
            if (nextChunk is null)
            {
                _completed = true;
                return 0;
            }

            _currentChunk = nextChunk;
            _currentOffset = 0;
        }

        var count = Math.Min(buffer.Length, _currentChunk.Length - _currentOffset);
        _currentChunk.AsMemory(_currentOffset, count).CopyTo(buffer);
        _currentOffset += count;
        if (_currentOffset >= _currentChunk.Length)
        {
            _currentChunk = null;
            _currentOffset = 0;
        }

        return count;
    }

    public void Dispose()
        => _session.Dispose();

    private async ValueTask<byte[]?> ReadNextChunkAsync(CancellationToken cancellationToken)
    {
        var sizeBuffer = new byte[_session.EncryptedSizeBytes];
        if (!await ShadowsocksProtocolCodec.TryReadExactAsync(
                _innerStream,
                sizeBuffer,
                cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var encryptedPayloadSize = _session.DecryptSize(sizeBuffer);
        if (encryptedPayloadSize == _session.TagSize)
        {
            return null;
        }

        if (encryptedPayloadSize < _session.TagSize)
        {
            throw new InvalidDataException("Shadowsocks TCP chunk size is invalid.");
        }

        var payloadBuffer = new byte[encryptedPayloadSize];
        await ShadowsocksProtocolCodec.ReadExactAsync(
            _innerStream,
            payloadBuffer,
            cancellationToken).ConfigureAwait(false);
        return _session.DecryptPayload(payloadBuffer);
    }
}

internal sealed class ShadowsocksAeadStreamWriter : IShadowsocksStreamWriter
{
    private const int MaxFrameBytes = 8192;

    private readonly Stream _innerStream;
    private readonly ShadowsocksAeadSession _session;

    public ShadowsocksAeadStreamWriter(Stream innerStream, ShadowsocksAeadSession session)
    {
        _innerStream = innerStream;
        _session = session;
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        if (buffer.IsEmpty)
        {
            return;
        }

        var maxChunkPayloadBytes = MaxFrameBytes - _session.TagSize - _session.EncryptedSizeBytes;
        if (maxChunkPayloadBytes <= 0)
        {
            throw new InvalidOperationException("Shadowsocks AEAD frame budget is invalid.");
        }

        var remaining = buffer;
        while (!remaining.IsEmpty)
        {
            var chunkLength = Math.Min(remaining.Length, maxChunkPayloadBytes);
            var sizeFrame = _session.EncryptSize(chunkLength);
            var payloadFrame = _session.EncryptPayload(remaining.Span[..chunkLength]);
            await _innerStream.WriteAsync(sizeFrame, cancellationToken).ConfigureAwait(false);
            await _innerStream.WriteAsync(payloadFrame, cancellationToken).ConfigureAwait(false);
            remaining = remaining[chunkLength..];
        }
    }

    public void Dispose()
        => _session.Dispose();
}

internal sealed class ShadowsocksAeadSession : IDisposable
{
    private readonly IShadowsocksAead _aead;
    private readonly ShadowsocksNonceGenerator _nonceGenerator;

    public ShadowsocksAeadSession(IShadowsocksAead aead)
    {
        _aead = aead;
        _nonceGenerator = new ShadowsocksNonceGenerator(aead.NonceSize);
    }

    public int TagSize => _aead.TagSize;

    public int EncryptedSizeBytes => 2 + TagSize;

    public byte[] EncryptSize(int plaintextPayloadLength)
    {
        Span<byte> plaintext = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(plaintext, checked((ushort)plaintextPayloadLength));
        return Encrypt(plaintext);
    }

    public int DecryptSize(ReadOnlySpan<byte> ciphertext)
    {
        var plaintext = Decrypt(ciphertext);
        if (plaintext.Length != 2)
        {
            throw new InvalidDataException("Shadowsocks encrypted size frame is invalid.");
        }

        return BinaryPrimitives.ReadUInt16BigEndian(plaintext) + TagSize;
    }

    public byte[] EncryptPayload(ReadOnlySpan<byte> plaintext)
        => Encrypt(plaintext);

    public byte[] DecryptPayload(ReadOnlySpan<byte> ciphertext)
        => Decrypt(ciphertext);

    public void Dispose()
        => _aead.Dispose();

    private byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        var output = new byte[plaintext.Length + TagSize];
        _aead.Encrypt(
            _nonceGenerator.Next(),
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, TagSize));
        return output;
    }

    private byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < TagSize)
        {
            throw new InvalidDataException("Shadowsocks ciphertext is truncated.");
        }

        var plaintext = new byte[ciphertext.Length - TagSize];
        _aead.Decrypt(
            _nonceGenerator.Next(),
            ciphertext[..^TagSize],
            ciphertext[^TagSize..],
            plaintext);
        return plaintext;
    }
}

internal sealed class ShadowsocksNonceGenerator
{
    private readonly byte[] _nonce;

    public ShadowsocksNonceGenerator(int nonceSize)
    {
        if (nonceSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonceSize));
        }

        _nonce = new byte[nonceSize];
        Array.Fill(_nonce, byte.MaxValue);
    }

    public byte[] Next()
    {
        for (var index = 0; index < _nonce.Length; index++)
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

        return _nonce.ToArray();
    }
}

internal interface IShadowsocksAead : IDisposable
{
    int NonceSize { get; }

    int TagSize { get; }

    void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag);

    void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext);
}

internal sealed class AesGcmShadowsocksAead : IShadowsocksAead
{
    private const int TagBytes = 16;
    private readonly AesGcm _aead;

    public AesGcmShadowsocksAead(byte[] key)
    {
        _aead = new AesGcm(key, TagBytes);
    }

    public int NonceSize => 12;

    public int TagSize => TagBytes;

    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag)
        => _aead.Encrypt(nonce, plaintext, ciphertext, tag, ReadOnlySpan<byte>.Empty);

    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
        => _aead.Decrypt(nonce, ciphertext, tag, plaintext, ReadOnlySpan<byte>.Empty);

    public void Dispose()
        => _aead.Dispose();
}

internal sealed class ChaCha20Poly1305ShadowsocksAead : IShadowsocksAead
{
    private const int TagBytes = 16;
    private readonly ChaCha20Poly1305 _aead;

    public ChaCha20Poly1305ShadowsocksAead(byte[] key)
    {
        _aead = new ChaCha20Poly1305(key);
    }

    public int NonceSize => 12;

    public int TagSize => TagBytes;

    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag)
        => _aead.Encrypt(nonce, plaintext, ciphertext, tag, ReadOnlySpan<byte>.Empty);

    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
        => _aead.Decrypt(nonce, ciphertext, tag, plaintext, ReadOnlySpan<byte>.Empty);

    public void Dispose()
        => _aead.Dispose();
}

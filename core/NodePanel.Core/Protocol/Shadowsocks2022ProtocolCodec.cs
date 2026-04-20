using Blake3;
using System.Security.Cryptography;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class Shadowsocks2022Account
{
    internal const int IdentityHeaderBytes = 16;
    private const string SessionSubkeyContext = "shadowsocks 2022 session subkey";
    private const string IdentitySubkeyContext = "shadowsocks 2022 identity subkey";

    private Shadowsocks2022Account(
        string method,
        ShadowsocksCipherKind kind,
        int keySize,
        byte[] userKey,
        IReadOnlyList<byte[]> identityKeys,
        IReadOnlyList<byte[]> identityHeaderHashes,
        byte[] userIdentityHash)
    {
        Method = method;
        Kind = kind;
        KeySize = keySize;
        UserKey = userKey;
        IdentityKeys = identityKeys.Count == 0
            ? Array.Empty<byte[]>()
            : identityKeys.Select(static key => key.ToArray()).ToArray();
        IdentityHeaderHashes = identityHeaderHashes.Count == 0
            ? Array.Empty<byte[]>()
            : identityHeaderHashes.Select(static hash => hash.ToArray()).ToArray();
        UserIdentityHash = userIdentityHash.Length == 0
            ? Array.Empty<byte>()
            : userIdentityHash.ToArray();
        FirstIdentityHash = IdentityHeaderHashes.Count == 0
            ? Array.Empty<byte>()
            : IdentityHeaderHashes[0].ToArray();
    }

    public string Method { get; }

    public ShadowsocksCipherKind Kind { get; }

    public int KeySize { get; }

    public int SaltSize => KeySize;

    public byte[] UserKey { get; }

    internal IReadOnlyList<byte[]> IdentityKeys { get; }

    internal IReadOnlyList<byte[]> IdentityHeaderHashes { get; }

    internal byte[] UserIdentityHash { get; }

    internal byte[] FirstIdentityHash { get; }

    public bool HasIdentityHeader => IdentityKeys.Count > 0;

    public int IdentityHeaderLength => IdentityKeys.Count * IdentityHeaderBytes;

    public static Shadowsocks2022Account Create(string method, string key)
    {
        var normalizedMethod = ShadowsocksCipherTypes.Normalize(method);
        var (kind, keySize) = normalizedMethod switch
        {
            ShadowsocksCipherTypes.Blake3Aes128Gcm => (ShadowsocksCipherKind.Aes128Gcm, 16),
            ShadowsocksCipherTypes.Blake3Aes256Gcm => (ShadowsocksCipherKind.Aes256Gcm, 32),
            ShadowsocksCipherTypes.Blake3ChaCha20Poly1305 => (ShadowsocksCipherKind.ChaCha20Poly1305, 32),
            _ => throw new NotSupportedException($"Unsupported Shadowsocks 2022 method: {method}.")
        };

        var passwordMaterial = Shadowsocks2022PasswordMaterial.Parse(normalizedMethod, key);
        if (passwordMaterial.HasIdentityHeaders)
        {
            if (!ShadowsocksCipherTypes.Supports2022MultiUser(normalizedMethod))
            {
                throw new NotSupportedException("Shadowsocks 2022 identity headers require 2022-blake3-aes-*-gcm methods.");
            }
        }

        var userKey = DecodePreSharedKey(passwordMaterial.UserEncodedKey, keySize);
        var userIdentityHash = ComputeIdentityHash(userKey);
        var identityKeys = passwordMaterial.IdentityEncodedKeys
            .Select(encodedKey => DecodePreSharedKey(encodedKey, keySize))
            .ToArray();
        var identityHeaderHashes = identityKeys.Length == 0
            ? Array.Empty<byte[]>()
            : BuildIdentityHeaderHashes(identityKeys, userIdentityHash);

        return new Shadowsocks2022Account(
            normalizedMethod,
            kind,
            keySize,
            userKey,
            identityKeys,
            identityHeaderHashes,
            userIdentityHash);
    }

    public ShadowsocksAeadSession CreateAeadSession(ReadOnlySpan<byte> salt)
    {
        if (salt.Length != SaltSize)
        {
            throw new InvalidDataException("Shadowsocks 2022 salt length is invalid.");
        }

        var subkey = DeriveSessionSubkey(UserKey, salt, KeySize);
        return new ShadowsocksAeadSession(
            Kind switch
            {
                ShadowsocksCipherKind.Aes128Gcm or ShadowsocksCipherKind.Aes256Gcm
                    => new AesGcmShadowsocksAead(subkey),
                ShadowsocksCipherKind.ChaCha20Poly1305
                    => new ChaCha20Poly1305ShadowsocksAead(subkey),
                _ => throw new InvalidOperationException($"Unsupported Shadowsocks 2022 AEAD cipher kind: {Kind}.")
            });
    }

    public byte[] CreateIdentityHeader(ReadOnlySpan<byte> salt)
    {
        if (!HasIdentityHeader)
        {
            return Array.Empty<byte>();
        }

        var header = new byte[IdentityHeaderLength];
        for (var index = 0; index < IdentityKeys.Count; index++)
        {
            var identitySubkey = DeriveIdentitySubkey(IdentityKeys[index], salt, KeySize);
            try
            {
                var block = TransformIdentityBlock(identitySubkey, IdentityHeaderHashes[index], encrypt: true);
                block.CopyTo(header, index * IdentityHeaderBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(identitySubkey);
            }
        }

        return header;
    }

    public bool TryReadLeadingIdentityHeader(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> header,
        out byte[] identityHash)
    {
        var identityKey = GetLeadingIdentityKeyMaterial();
        if (identityKey.Length == 0)
        {
            identityHash = Array.Empty<byte>();
            return false;
        }

        if (header.Length != IdentityHeaderBytes)
        {
            identityHash = Array.Empty<byte>();
            return false;
        }

        var identitySubkey = DeriveIdentitySubkey(identityKey, salt, KeySize);
        try
        {
            identityHash = TransformIdentityBlock(identitySubkey, header, encrypt: false);
            return identityHash.Length == IdentityHeaderBytes;
        }
        catch (CryptographicException)
        {
            identityHash = Array.Empty<byte>();
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identitySubkey);
        }
    }

    public bool TryReadIdentityHeader(
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> header,
        out byte[] identityHash)
    {
        if (!HasIdentityHeader)
        {
            identityHash = Array.Empty<byte>();
            return false;
        }

        if (header.Length != IdentityHeaderLength)
        {
            identityHash = Array.Empty<byte>();
            return false;
        }

        for (var index = 0; index < IdentityKeys.Count; index++)
        {
            var identitySubkey = DeriveIdentitySubkey(IdentityKeys[index], salt, KeySize);
            try
            {
                var block = header.Slice(index * IdentityHeaderBytes, IdentityHeaderBytes);
                var currentIdentityHash = TransformIdentityBlock(identitySubkey, block, encrypt: false);
                if (!CryptographicOperations.FixedTimeEquals(currentIdentityHash, IdentityHeaderHashes[index]))
                {
                    identityHash = Array.Empty<byte>();
                    return false;
                }
            }
            catch (CryptographicException)
            {
                identityHash = Array.Empty<byte>();
                return false;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(identitySubkey);
            }
        }

        identityHash = UserIdentityHash.ToArray();
        return true;
    }

    public void ValidateIdentityHeader(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> header)
    {
        if (!HasIdentityHeader)
        {
            return;
        }

        if (!TryReadIdentityHeader(salt, header, out _))
        {
            throw new CryptographicException("Shadowsocks 2022 identity header is invalid.");
        }
    }

    private ReadOnlySpan<byte> GetLeadingIdentityKeyMaterial()
    {
        if (Kind is not (ShadowsocksCipherKind.Aes128Gcm or ShadowsocksCipherKind.Aes256Gcm))
        {
            return ReadOnlySpan<byte>.Empty;
        }

        if (IdentityKeys.Count > 0)
        {
            return IdentityKeys[0];
        }

        return UserKey;
    }

    private static byte[] DecodePreSharedKey(string key, int expectedBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        byte[] preSharedKey;
        try
        {
            preSharedKey = Convert.FromBase64String(key.Trim());
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Shadowsocks 2022 key must be a valid base64 string.", ex);
        }

        if (preSharedKey.Length != expectedBytes)
        {
            throw new InvalidOperationException($"Shadowsocks 2022 key must decode to {expectedBytes} bytes.");
        }

        return preSharedKey;
    }

    private static byte[] DeriveSessionSubkey(
        ReadOnlySpan<byte> preSharedKey,
        ReadOnlySpan<byte> salt,
        int keySize)
        => DeriveSubkey(SessionSubkeyContext, preSharedKey, salt, keySize);

    private static byte[] DeriveIdentitySubkey(
        ReadOnlySpan<byte> preSharedKey,
        ReadOnlySpan<byte> salt,
        int keySize)
        => DeriveSubkey(IdentitySubkeyContext, preSharedKey, salt, keySize);

    private static byte[] DeriveSubkey(
        string context,
        ReadOnlySpan<byte> preSharedKey,
        ReadOnlySpan<byte> salt,
        int keySize)
    {
        var subkey = new byte[keySize];
        using var hasher = Hasher.NewDeriveKey(context);
        hasher.Update(preSharedKey);
        hasher.Update(salt);
        hasher.Finalize(subkey);
        return subkey;
    }

    private static byte[][] BuildIdentityHeaderHashes(
        IReadOnlyList<byte[]> identityKeys,
        ReadOnlySpan<byte> userIdentityHash)
    {
        var identityHeaderHashes = new byte[identityKeys.Count][];
        for (var index = 0; index < identityKeys.Count; index++)
        {
            identityHeaderHashes[index] = index + 1 < identityKeys.Count
                ? ComputeIdentityHash(identityKeys[index + 1])
                : userIdentityHash.ToArray();
        }

        return identityHeaderHashes;
    }

    private static byte[] ComputeIdentityHash(ReadOnlySpan<byte> userKey)
    {
        var fullHash = new byte[Hash.Size];
        Hasher.Hash(userKey, fullHash);
        return fullHash.AsSpan(0, IdentityHeaderBytes).ToArray();
    }

    private static byte[] TransformIdentityBlock(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> block,
        bool encrypt)
    {
        if (block.Length != IdentityHeaderBytes)
        {
            throw new InvalidDataException("Shadowsocks 2022 identity header block length is invalid.");
        }

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key.ToArray();
        using var transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return transform.TransformFinalBlock(block.ToArray(), 0, block.Length);
    }
}

internal sealed record Shadowsocks2022PasswordMaterial(
    string Method,
    int KeySize,
    IReadOnlyList<string> EncodedKeys)
{
    public bool HasIdentityHeaders => EncodedKeys.Count > 1;

    public IReadOnlyList<string> IdentityEncodedKeys => EncodedKeys.Count <= 1
        ? Array.Empty<string>()
        : EncodedKeys.Take(EncodedKeys.Count - 1).ToArray();

    public string UserEncodedKey => EncodedKeys[^1];

    public static Shadowsocks2022PasswordMaterial Parse(string method, string password)
    {
        var normalizedMethod = ShadowsocksCipherTypes.Normalize(method);
        var keySize = normalizedMethod switch
        {
            ShadowsocksCipherTypes.Blake3Aes128Gcm => 16,
            ShadowsocksCipherTypes.Blake3Aes256Gcm => 32,
            ShadowsocksCipherTypes.Blake3ChaCha20Poly1305 => 32,
            _ => throw new NotSupportedException($"Unsupported Shadowsocks 2022 method: {method}.")
        };

        if (string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("Shadowsocks 2022 key is required.");
        }

        var segments = password
            .Split(':', StringSplitOptions.None)
            .Select(static segment => segment.Trim())
            .ToArray();
        if (segments.Length == 0 || segments.Any(static segment => segment.Length == 0))
        {
            throw new InvalidOperationException("Shadowsocks 2022 key contains an empty password segment.");
        }

        foreach (var segment in segments)
        {
            ValidateBase64Segment(segment, keySize);
        }

        return new Shadowsocks2022PasswordMaterial(
            normalizedMethod,
            keySize,
            segments);
    }

    private static void ValidateBase64Segment(string segment, int keySize)
    {
        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(segment);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Shadowsocks 2022 key must be a valid base64 string or a colon-separated list of valid base64 strings.", ex);
        }

        if (decoded.Length != keySize)
        {
            throw new InvalidOperationException($"Shadowsocks 2022 key must decode to {keySize} bytes.");
        }
    }
}

internal static class Shadowsocks2022ProtocolCodec
{
    public static async ValueTask<Shadowsocks2022ClientTcpStream> OpenClientTcpStreamAsync(
        Stream innerStream,
        Shadowsocks2022Account account,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentNullException.ThrowIfNull(account);

        var salt = RandomNumberGenerator.GetBytes(account.SaltSize);
        await innerStream.WriteAsync(salt, cancellationToken).ConfigureAwait(false);
        if (account.HasIdentityHeader)
        {
            var identityHeader = account.CreateIdentityHeader(salt);
            await innerStream.WriteAsync(identityHeader, cancellationToken).ConfigureAwait(false);
        }

        var requestWriter = new ShadowsocksAeadStreamWriter(innerStream, account.CreateAeadSession(salt));
        var requestHeader = ShadowsocksProtocolCodec.EncodeTarget(host, port);
        await requestWriter.WriteAsync(requestHeader, cancellationToken).ConfigureAwait(false);
        await innerStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        return new Shadowsocks2022ClientTcpStream(innerStream, account, requestWriter);
    }

    public static async ValueTask<Shadowsocks2022AcceptedTcpSession> AcceptServerTcpStreamAsync(
        Stream innerStream,
        Shadowsocks2022Account account,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentNullException.ThrowIfNull(account);

        var salt = new byte[account.SaltSize];
        await ShadowsocksProtocolCodec.ReadExactAsync(innerStream, salt, cancellationToken).ConfigureAwait(false);
        if (account.HasIdentityHeader)
        {
            var identityHeader = new byte[account.IdentityHeaderLength];
            await ShadowsocksProtocolCodec.ReadExactAsync(innerStream, identityHeader, cancellationToken).ConfigureAwait(false);
            account.ValidateIdentityHeader(salt, identityHeader);
        }

        var requestReader = new ShadowsocksAeadStreamReader(innerStream, account.CreateAeadSession(salt));
        var firstChunk = await ReadFirstRequestChunkAsync(requestReader, cancellationToken).ConfigureAwait(false);
        var target = ShadowsocksProtocolCodec.DecodeTarget(firstChunk, out var consumed);
        var prefixedPayload = consumed < firstChunk.Length
            ? firstChunk.AsSpan(consumed).ToArray()
            : Array.Empty<byte>();

        var responseSalt = RandomNumberGenerator.GetBytes(account.SaltSize);
        await innerStream.WriteAsync(responseSalt, cancellationToken).ConfigureAwait(false);
        var responseWriter = new ShadowsocksAeadStreamWriter(innerStream, account.CreateAeadSession(responseSalt));

        Stream readStream = new ShadowsocksReadStream(requestReader);
        if (prefixedPayload.Length > 0)
        {
            readStream = new PrefixedReadStream(readStream, prefixedPayload);
        }

        return new Shadowsocks2022AcceptedTcpSession(
            new ShadowsocksTarget(target.Host, target.Port),
            new Shadowsocks2022ServerTcpStream(innerStream, readStream, responseWriter));
    }

    public static byte[] EncodeUdpPacket(
        Shadowsocks2022Account account,
        string host,
        int port,
        ReadOnlySpan<byte> payload,
        bool includeIdentityHeader = true)
    {
        ArgumentNullException.ThrowIfNull(account);

        var salt = RandomNumberGenerator.GetBytes(account.SaltSize);
        using var session = account.CreateAeadSession(salt);
        var target = ShadowsocksProtocolCodec.EncodeTarget(host, port);
        var plaintext = new byte[target.Length + payload.Length];
        target.CopyTo(plaintext, 0);
        payload.CopyTo(plaintext.AsSpan(target.Length));
        var ciphertext = session.EncryptPayload(plaintext);
        var identityHeader = account.HasIdentityHeader && includeIdentityHeader
            ? account.CreateIdentityHeader(salt)
            : Array.Empty<byte>();

        var packet = new byte[salt.Length + identityHeader.Length + ciphertext.Length];
        salt.CopyTo(packet, 0);
        if (identityHeader.Length > 0)
        {
            identityHeader.CopyTo(packet, salt.Length);
        }

        ciphertext.CopyTo(packet, salt.Length + identityHeader.Length);
        return packet;
    }

    public static ShadowsocksUdpPacket DecodeUdpPacket(
        Shadowsocks2022Account account,
        ReadOnlySpan<byte> payload)
    {
        ArgumentNullException.ThrowIfNull(account);

        if (payload.Length <= account.SaltSize)
        {
            throw new InvalidDataException("Shadowsocks 2022 UDP payload is incomplete.");
        }

        var salt = payload[..account.SaltSize];

        if (account.HasIdentityHeader)
        {
            if (TryDecodeUdpPacketCore(account, payload, salt, hasIdentityHeader: true, out var packet))
            {
                return packet;
            }

            if (TryDecodeUdpPacketCore(account, payload, salt, hasIdentityHeader: false, out packet))
            {
                return packet;
            }

            throw new CryptographicException("Shadowsocks 2022 UDP identity header is invalid.");
        }

        if (TryDecodeUdpPacketCore(account, payload, salt, hasIdentityHeader: false, out var decoded))
        {
            return decoded;
        }

        throw new InvalidDataException("Shadowsocks 2022 UDP payload is incomplete.");
    }

    private static async ValueTask<byte[]> ReadFirstRequestChunkAsync(
        IShadowsocksStreamReader reader,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[8192];
        var read = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read <= 0)
        {
            throw new InvalidDataException("Shadowsocks 2022 TCP request header is missing.");
        }

        return buffer.AsSpan(0, read).ToArray();
    }

    private static bool TryDecodeUdpPacketCore(
        Shadowsocks2022Account account,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> salt,
        bool hasIdentityHeader,
        out ShadowsocksUdpPacket packet)
    {
        var offset = account.SaltSize;
        if (hasIdentityHeader)
        {
            if (payload.Length <= offset + account.IdentityHeaderLength)
            {
                packet = default!;
                return false;
            }

            var identityHeader = payload.Slice(offset, account.IdentityHeaderLength);
            if (!account.TryReadIdentityHeader(salt, identityHeader, out _))
            {
                packet = default!;
                return false;
            }

            offset += account.IdentityHeaderLength;
        }

        if (payload.Length <= offset)
        {
            packet = default!;
            return false;
        }

        using var session = account.CreateAeadSession(salt);
        var plaintext = session.DecryptPayload(payload[offset..]);
        var target = ShadowsocksProtocolCodec.DecodeTarget(plaintext, out var consumed);
        packet = new ShadowsocksUdpPacket(
            target.Host,
            target.Port,
            plaintext[consumed..].ToArray());
        return true;
    }
}

internal sealed record Shadowsocks2022AcceptedTcpSession(
    ShadowsocksTarget Destination,
    Stream Stream);

internal sealed class Shadowsocks2022ClientTcpStream : Stream, IInnerStreamAccessor
{
    private readonly Shadowsocks2022Account _account;
    private readonly Stream _innerStream;
    private readonly SemaphoreSlim _readerInitializationLock = new(1, 1);
    private readonly IShadowsocksStreamWriter _requestWriter;

    private IShadowsocksStreamReader? _responseReader;
    private int _disposed;

    internal Shadowsocks2022ClientTcpStream(
        Stream innerStream,
        Shadowsocks2022Account account,
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

            var salt = new byte[_account.SaltSize];
            await ShadowsocksProtocolCodec.ReadExactAsync(_innerStream, salt, cancellationToken).ConfigureAwait(false);
            _responseReader = new ShadowsocksAeadStreamReader(
                _innerStream,
                _account.CreateAeadSession(salt));
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
            throw new ObjectDisposedException(nameof(Shadowsocks2022ClientTcpStream));
        }
    }
}

internal sealed class Shadowsocks2022ServerTcpStream : Stream, IInnerStreamAccessor
{
    private readonly Stream _innerStream;
    private readonly Stream _readStream;
    private readonly IShadowsocksStreamWriter _responseWriter;
    private int _disposed;

    internal Shadowsocks2022ServerTcpStream(
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
            throw new ObjectDisposedException(nameof(Shadowsocks2022ServerTcpStream));
        }
    }
}

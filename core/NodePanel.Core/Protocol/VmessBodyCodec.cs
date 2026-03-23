using System.Buffers.Binary;
using System.Security.Cryptography;

namespace NodePanel.Core.Protocol;

internal sealed class VmessDataStream : Stream
{
    private readonly Stream _inner;
    private readonly VmessBodyReader _reader;
    private readonly VmessBodyWriter _writer;

    private bool _responseCompleted;

    public VmessDataStream(Stream inner, VmessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        _inner = inner;
        _reader = VmessBodyReader.CreateRequestReader(inner, request);
        _writer = VmessBodyWriter.CreateResponseWriter(inner, request);
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    internal ValueTask<byte[]?> ReadPacketAsync(CancellationToken cancellationToken)
        => _reader.ReadPacketAsync(cancellationToken);

    internal ValueTask WritePacketAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        => _writer.WritePacketAsync(payload, cancellationToken);

    public async ValueTask CompleteResponseAsync(CancellationToken cancellationToken)
    {
        if (_responseCompleted)
        {
            return;
        }

        _responseCompleted = true;
        await _writer.CompleteAsync(cancellationToken).ConfigureAwait(false);
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _reader.ReadStreamAsync(buffer, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _writer.WriteStreamAsync(buffer, cancellationToken);

    public override void Flush()
        => _inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();
}

internal sealed class VmessBodyReader
{
    private readonly Stream _inner;
    private readonly IVmessBodyCipher _cipher;
    private readonly IVmessChunkSizeCodec? _sizeCodec;
    private readonly IVmessPaddingLengthGenerator? _paddingGenerator;
    private readonly VmessTransferType _transferType;
    private readonly bool _framed;

    private byte[]? _currentChunk;
    private int _currentChunkOffset;
    private bool _completed;

    private VmessBodyReader(
        Stream inner,
        IVmessBodyCipher cipher,
        IVmessChunkSizeCodec? sizeCodec,
        IVmessPaddingLengthGenerator? paddingGenerator,
        VmessTransferType transferType,
        bool framed)
    {
        _inner = inner;
        _cipher = cipher;
        _sizeCodec = sizeCodec;
        _paddingGenerator = paddingGenerator;
        _transferType = transferType;
        _framed = framed;
    }

    public static VmessBodyReader CreateRequestReader(Stream inner, VmessRequest request)
    {
        var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
        var transferType = VmessBodyCodecFactory.GetTransferType(request.Command);
        var framed = VmessBodyCodecFactory.RequiresFraming(security, request.Option);
        var payloadCipher = VmessBodyCodecFactory.CreatePayloadCipher(security, request.RequestBodyKey, request.RequestBodyIv);
        var frameOptions = VmessBodyCodecFactory.CreateRequestFrameOptions(request, security, framed);

        return new VmessBodyReader(
            inner,
            payloadCipher,
            frameOptions.SizeCodec,
            frameOptions.PaddingGenerator,
            transferType,
            framed);
    }

    public async ValueTask<int> ReadStreamAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_transferType != VmessTransferType.Stream)
        {
            throw new NotSupportedException("VMess body stream reads are only available for stream transfer mode.");
        }

        if (!_framed)
        {
            return await _inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        if (_completed)
        {
            return 0;
        }

        if (_currentChunk is null || _currentChunkOffset >= _currentChunk.Length)
        {
            var nextChunk = await ReadNextChunkAsync(cancellationToken).ConfigureAwait(false);
            if (nextChunk is null)
            {
                _completed = true;
                return 0;
            }

            _currentChunk = nextChunk;
            _currentChunkOffset = 0;
        }

        var available = _currentChunk.Length - _currentChunkOffset;
        var count = Math.Min(buffer.Length, available);
        _currentChunk.AsMemory(_currentChunkOffset, count).CopyTo(buffer);
        _currentChunkOffset += count;
        if (_currentChunkOffset >= _currentChunk.Length)
        {
            _currentChunk = null;
            _currentChunkOffset = 0;
        }

        return count;
    }

    public async ValueTask<byte[]?> ReadPacketAsync(CancellationToken cancellationToken)
    {
        if (_transferType != VmessTransferType.Packet)
        {
            throw new NotSupportedException("VMess body packet reads are only available for packet transfer mode.");
        }

        if (!_framed)
        {
            throw new NotSupportedException("VMess packet transfer requires framed body encoding.");
        }

        if (_completed)
        {
            return null;
        }

        var packet = await ReadNextChunkAsync(cancellationToken).ConfigureAwait(false);
        if (packet is null)
        {
            _completed = true;
            return null;
        }

        return packet;
    }

    private async ValueTask<byte[]?> ReadNextChunkAsync(CancellationToken cancellationToken)
    {
        if (!_framed || _sizeCodec is null)
        {
            throw new InvalidOperationException("VMess chunk reader is not configured for framed mode.");
        }

        var sizeBuffer = new byte[_sizeCodec.HeaderLength];
        await TrojanProtocolCodec.ReadExactAsync(_inner, sizeBuffer, cancellationToken).ConfigureAwait(false);

        var paddingLength = _paddingGenerator?.NextPaddingLength() ?? 0;
        var encodedSize = _sizeCodec.ReadSize(sizeBuffer);
        var minimumTerminatorSize = _cipher.Overhead + paddingLength;

        if (encodedSize == minimumTerminatorSize)
        {
            return null;
        }

        if (encodedSize < minimumTerminatorSize)
        {
            throw new InvalidDataException("VMess body chunk size is invalid.");
        }

        var encryptedLength = encodedSize - paddingLength;
        if (encryptedLength < _cipher.Overhead)
        {
            throw new InvalidDataException("VMess body ciphertext length is invalid.");
        }

        var encryptedPayload = new byte[encodedSize];
        await TrojanProtocolCodec.ReadExactAsync(_inner, encryptedPayload, cancellationToken).ConfigureAwait(false);

        return _cipher.Decrypt(encryptedPayload.AsSpan(0, encryptedLength));
    }
}

internal sealed class VmessBodyWriter
{
    private const int MaxFrameBytes = 8192;

    private readonly Stream _inner;
    private readonly IVmessBodyCipher _cipher;
    private readonly IVmessChunkSizeCodec? _sizeCodec;
    private readonly IVmessPaddingLengthGenerator? _paddingGenerator;
    private readonly VmessTransferType _transferType;
    private readonly bool _framed;
    private readonly int _maxPaddingLength;

    private VmessBodyWriter(
        Stream inner,
        IVmessBodyCipher cipher,
        IVmessChunkSizeCodec? sizeCodec,
        IVmessPaddingLengthGenerator? paddingGenerator,
        VmessTransferType transferType,
        bool framed)
    {
        _inner = inner;
        _cipher = cipher;
        _sizeCodec = sizeCodec;
        _paddingGenerator = paddingGenerator;
        _transferType = transferType;
        _framed = framed;
        _maxPaddingLength = paddingGenerator?.MaxPaddingLength ?? 0;
    }

    public static VmessBodyWriter CreateResponseWriter(Stream inner, VmessRequest request)
    {
        var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
        var transferType = VmessBodyCodecFactory.GetTransferType(request.Command);
        var framed = VmessBodyCodecFactory.RequiresFraming(security, request.Option);
        var responseBodyKey = VmessHandshakeReader.DeriveResponseBodyKey(request.RequestBodyKey);
        var responseBodyIv = VmessHandshakeReader.DeriveResponseBodyIv(request.RequestBodyIv);
        var payloadCipher = VmessBodyCodecFactory.CreatePayloadCipher(security, responseBodyKey, responseBodyIv);
        var frameOptions = VmessBodyCodecFactory.CreateResponseFrameOptions(request, security, framed, responseBodyIv);

        return new VmessBodyWriter(
            inner,
            payloadCipher,
            frameOptions.SizeCodec,
            frameOptions.PaddingGenerator,
            transferType,
            framed);
    }

    public async ValueTask WriteStreamAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_transferType != VmessTransferType.Stream)
        {
            throw new NotSupportedException("VMess body stream writes are only available for stream transfer mode.");
        }

        if (!_framed)
        {
            if (!buffer.IsEmpty)
            {
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        var remaining = buffer;
        var maxPayloadLength = GetMaxStreamPayloadLength();
        while (!remaining.IsEmpty)
        {
            var chunkLength = Math.Min(remaining.Length, maxPayloadLength);
            await WriteChunkAsync(remaining[..chunkLength], cancellationToken).ConfigureAwait(false);
            remaining = remaining[chunkLength..];
        }
    }

    public async ValueTask WritePacketAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (_transferType != VmessTransferType.Packet)
        {
            throw new NotSupportedException("VMess body packet writes are only available for packet transfer mode.");
        }

        if (!_framed)
        {
            throw new NotSupportedException("VMess packet transfer requires framed body encoding.");
        }

        await WriteChunkAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask CompleteAsync(CancellationToken cancellationToken)
    {
        if (!_framed)
        {
            return;
        }

        await WriteChunkAsync(ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
    }

    private int GetMaxStreamPayloadLength()
    {
        if (!_framed || _sizeCodec is null)
        {
            return MaxFrameBytes;
        }

        var maxPayloadLength = MaxFrameBytes - _cipher.Overhead - _sizeCodec.HeaderLength - _maxPaddingLength;
        if (maxPayloadLength <= 0)
        {
            throw new InvalidOperationException("VMess stream chunk budget is invalid.");
        }

        return maxPayloadLength;
    }

    private async ValueTask WriteChunkAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (!_framed || _sizeCodec is null)
        {
            if (!payload.IsEmpty)
            {
                await _inner.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        var paddingLength = _paddingGenerator?.NextPaddingLength() ?? 0;
        var encryptedPayload = _cipher.Encrypt(payload.Span);
        var totalLength = encryptedPayload.Length + paddingLength;

        var sizeBuffer = new byte[_sizeCodec.HeaderLength];
        _sizeCodec.WriteSize(totalLength, sizeBuffer);
        await _inner.WriteAsync(sizeBuffer, cancellationToken).ConfigureAwait(false);

        if (encryptedPayload.Length > 0)
        {
            await _inner.WriteAsync(encryptedPayload, cancellationToken).ConfigureAwait(false);
        }

        if (paddingLength > 0)
        {
            var paddingBuffer = GC.AllocateUninitializedArray<byte>(paddingLength);
            RandomNumberGenerator.Fill(paddingBuffer);
            await _inner.WriteAsync(paddingBuffer, cancellationToken).ConfigureAwait(false);
        }
    }
}

internal static class VmessBodyCodecFactory
{
    public static VmessBodyFrameOptions CreateRequestFrameOptions(VmessRequest request, VmessSecurityType security, bool framed)
    {
        if (!framed)
        {
            return VmessBodyFrameOptions.Direct;
        }

        var shakeCodec = VmessRequestOptions.Has(request.Option, VmessRequestOptions.ChunkMasking)
            ? new ShakeChunkSizeCodec(request.RequestBodyIv)
            : null;
        var paddingGenerator = CreatePaddingGenerator(request.Option, shakeCodec);
        var sizeCodec = CreateRequestSizeCodec(request, security, shakeCodec);
        return new VmessBodyFrameOptions(sizeCodec, paddingGenerator);
    }

    public static VmessBodyFrameOptions CreateResponseFrameOptions(
        VmessRequest request,
        VmessSecurityType security,
        bool framed,
        ReadOnlySpan<byte> responseBodyIv)
    {
        if (!framed)
        {
            return VmessBodyFrameOptions.Direct;
        }

        var shakeCodec = VmessRequestOptions.Has(request.Option, VmessRequestOptions.ChunkMasking)
            ? new ShakeChunkSizeCodec(responseBodyIv)
            : null;
        var paddingGenerator = CreatePaddingGenerator(request.Option, shakeCodec);
        var sizeCodec = CreateResponseSizeCodec(request, security, shakeCodec);
        return new VmessBodyFrameOptions(sizeCodec, paddingGenerator);
    }

    public static IVmessBodyCipher CreatePayloadCipher(
        VmessSecurityType security,
        ReadOnlySpan<byte> bodyKey,
        ReadOnlySpan<byte> bodyIv)
    {
        return security switch
        {
            VmessSecurityType.None => new NoOpBodyCipher(),
            VmessSecurityType.Aes128Gcm => new AesGcmBodyCipher(bodyKey, bodyIv),
            VmessSecurityType.ChaCha20Poly1305 => new ChaCha20Poly1305BodyCipher(bodyKey, bodyIv),
            _ => throw new NotSupportedException($"Unsupported VMess security type: {security}.")
        };
    }

    public static VmessSecurityType NormalizeSecurity(VmessSecurityType security)
        => security == VmessSecurityType.Zero ? VmessSecurityType.None : security;

    public static bool RequiresFraming(VmessSecurityType security, byte option)
        => security is VmessSecurityType.Aes128Gcm or VmessSecurityType.ChaCha20Poly1305 ||
           VmessRequestOptions.Has(option, VmessRequestOptions.ChunkStream);

    public static VmessTransferType GetTransferType(VmessCommand command)
        => command == VmessCommand.Udp ? VmessTransferType.Packet : VmessTransferType.Stream;

    private static IVmessChunkSizeCodec CreateRequestSizeCodec(
        VmessRequest request,
        VmessSecurityType security,
        ShakeChunkSizeCodec? shakeCodec)
    {
        if (security is VmessSecurityType.Aes128Gcm or VmessSecurityType.ChaCha20Poly1305 &&
            VmessRequestOptions.Has(request.Option, VmessRequestOptions.AuthenticatedLength))
        {
            return new AeadChunkSizeCodec(CreateAuthenticatedLengthCipher(security, request.RequestBodyKey, request.RequestBodyIv));
        }

        return shakeCodec is not null
            ? shakeCodec
            : new PlainChunkSizeCodec();
    }

    private static IVmessChunkSizeCodec CreateResponseSizeCodec(
        VmessRequest request,
        VmessSecurityType security,
        ShakeChunkSizeCodec? shakeCodec)
    {
        if (security is VmessSecurityType.Aes128Gcm or VmessSecurityType.ChaCha20Poly1305 &&
            VmessRequestOptions.Has(request.Option, VmessRequestOptions.AuthenticatedLength))
        {
            return new AeadChunkSizeCodec(CreateAuthenticatedLengthCipher(security, request.RequestBodyKey, request.RequestBodyIv));
        }

        return shakeCodec is not null
            ? shakeCodec
            : new PlainChunkSizeCodec();
    }

    private static IVmessPaddingLengthGenerator? CreatePaddingGenerator(byte option, ShakeChunkSizeCodec? shakeCodec)
    {
        if (!VmessRequestOptions.Has(option, VmessRequestOptions.GlobalPadding))
        {
            return null;
        }

        return shakeCodec ?? throw new NotSupportedException("VMess global padding requires chunk masking.");
    }

    private static IVmessBodyCipher CreateAuthenticatedLengthCipher(
        VmessSecurityType security,
        ReadOnlySpan<byte> requestBodyKey,
        ReadOnlySpan<byte> requestBodyIv)
    {
        var authenticatedLengthKey = VmessAeadKdf.Kdf16(requestBodyKey, "auth_len"u8.ToArray());
        return security switch
        {
            VmessSecurityType.Aes128Gcm => new AesGcmBodyCipher(authenticatedLengthKey, requestBodyIv),
            VmessSecurityType.ChaCha20Poly1305 => new ChaCha20Poly1305BodyCipher(authenticatedLengthKey, requestBodyIv),
            _ => throw new NotSupportedException($"Authenticated length is not supported for VMess security type: {security}.")
        };
    }
}

internal readonly record struct VmessBodyFrameOptions(
    IVmessChunkSizeCodec? SizeCodec,
    IVmessPaddingLengthGenerator? PaddingGenerator)
{
    public static VmessBodyFrameOptions Direct { get; } = new(null, null);
}

internal enum VmessTransferType
{
    Stream = 0,
    Packet = 1
}

internal interface IVmessChunkSizeCodec
{
    int HeaderLength { get; }

    int ReadSize(ReadOnlySpan<byte> buffer);

    void WriteSize(int size, Span<byte> destination);
}

internal interface IVmessPaddingLengthGenerator
{
    int MaxPaddingLength { get; }

    int NextPaddingLength();
}

internal interface IVmessBodyCipher
{
    int Overhead { get; }

    byte[] Decrypt(ReadOnlySpan<byte> ciphertext);

    byte[] Encrypt(ReadOnlySpan<byte> plaintext);
}

internal sealed class PlainChunkSizeCodec : IVmessChunkSizeCodec
{
    public int HeaderLength => 2;

    public int ReadSize(ReadOnlySpan<byte> buffer)
        => BinaryPrimitives.ReadUInt16BigEndian(buffer);

    public void WriteSize(int size, Span<byte> destination)
        => BinaryPrimitives.WriteUInt16BigEndian(destination, checked((ushort)size));
}

internal sealed class ShakeChunkSizeCodec : IVmessChunkSizeCodec, IVmessPaddingLengthGenerator
{
    private readonly Shake128Xof _shake;

    public ShakeChunkSizeCodec(ReadOnlySpan<byte> seed)
    {
        _shake = new Shake128Xof(seed);
    }

    public int HeaderLength => 2;

    public int MaxPaddingLength => 64;

    public int NextPaddingLength()
        => _shake.NextUInt16() % MaxPaddingLength;

    public int ReadSize(ReadOnlySpan<byte> buffer)
        => BinaryPrimitives.ReadUInt16BigEndian(buffer) ^ _shake.NextUInt16();

    public void WriteSize(int size, Span<byte> destination)
        => BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)(checked((ushort)size) ^ _shake.NextUInt16()));
}

internal sealed class AeadChunkSizeCodec : IVmessChunkSizeCodec
{
    private readonly IVmessBodyCipher _cipher;

    public AeadChunkSizeCodec(IVmessBodyCipher cipher)
    {
        _cipher = cipher;
    }

    public int HeaderLength => 2 + _cipher.Overhead;

    public int ReadSize(ReadOnlySpan<byte> buffer)
    {
        var plaintext = _cipher.Decrypt(buffer);
        if (plaintext.Length != 2)
        {
            throw new InvalidDataException("VMess authenticated chunk size is invalid.");
        }

        return BinaryPrimitives.ReadUInt16BigEndian(plaintext) + _cipher.Overhead;
    }

    public void WriteSize(int size, Span<byte> destination)
    {
        if (size < _cipher.Overhead)
        {
            throw new InvalidDataException("VMess authenticated chunk size is invalid.");
        }

        Span<byte> plaintext = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(plaintext, checked((ushort)(size - _cipher.Overhead)));
        var encrypted = _cipher.Encrypt(plaintext);
        if (encrypted.Length != HeaderLength)
        {
            throw new InvalidDataException("VMess authenticated chunk size length is invalid.");
        }

        encrypted.CopyTo(destination);
    }
}

internal sealed class NoOpBodyCipher : IVmessBodyCipher
{
    public int Overhead => 0;

    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
        => ciphertext.ToArray();

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
        => plaintext.ToArray();
}

internal sealed class AesGcmBodyCipher : IVmessBodyCipher
{
    private const int TagSizeBytes = 16;

    private readonly AesGcm _aead;
    private readonly VmessChunkNonceGenerator _nonceGenerator;

    public AesGcmBodyCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonceSeed)
    {
        _aead = new AesGcm(key.ToArray(), TagSizeBytes);
        _nonceGenerator = new VmessChunkNonceGenerator(nonceSeed, 12);
    }

    public int Overhead => TagSizeBytes;

    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < TagSizeBytes)
        {
            throw new InvalidDataException("VMess AES-GCM ciphertext is truncated.");
        }

        var nonce = _nonceGenerator.Next();
        var plaintext = new byte[ciphertext.Length - TagSizeBytes];
        _aead.Decrypt(
            nonce,
            ciphertext[..^TagSizeBytes],
            ciphertext[^TagSizeBytes..],
            plaintext,
            ReadOnlySpan<byte>.Empty);
        return plaintext;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        var nonce = _nonceGenerator.Next();
        var output = new byte[plaintext.Length + TagSizeBytes];
        _aead.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, TagSizeBytes),
            ReadOnlySpan<byte>.Empty);
        return output;
    }
}

internal sealed class ChaCha20Poly1305BodyCipher : IVmessBodyCipher
{
    private const int TagSizeBytes = 16;

    private readonly ChaCha20Poly1305 _aead;
    private readonly VmessChunkNonceGenerator _nonceGenerator;

    public ChaCha20Poly1305BodyCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonceSeed)
    {
        _aead = new ChaCha20Poly1305(GenerateChaCha20Poly1305Key(key));
        _nonceGenerator = new VmessChunkNonceGenerator(nonceSeed, 12);
    }

    public int Overhead => TagSizeBytes;

    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        if (ciphertext.Length < TagSizeBytes)
        {
            throw new InvalidDataException("VMess ChaCha20-Poly1305 ciphertext is truncated.");
        }

        var nonce = _nonceGenerator.Next();
        var plaintext = new byte[ciphertext.Length - TagSizeBytes];
        _aead.Decrypt(
            nonce,
            ciphertext[..^TagSizeBytes],
            ciphertext[^TagSizeBytes..],
            plaintext,
            ReadOnlySpan<byte>.Empty);
        return plaintext;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        var nonce = _nonceGenerator.Next();
        var output = new byte[plaintext.Length + TagSizeBytes];
        _aead.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, TagSizeBytes),
            ReadOnlySpan<byte>.Empty);
        return output;
    }

    private static byte[] GenerateChaCha20Poly1305Key(ReadOnlySpan<byte> key)
    {
        var derivedKey = new byte[32];
        var firstHalf = MD5.HashData(key.ToArray());
        firstHalf.CopyTo(derivedKey, 0);

        var secondHalf = MD5.HashData(derivedKey.AsSpan(0, 16).ToArray());
        secondHalf.CopyTo(derivedKey, 16);
        return derivedKey;
    }
}

internal sealed class VmessChunkNonceGenerator
{
    private readonly byte[] _nonce;
    private readonly int _nonceLength;

    private ushort _counter;

    public VmessChunkNonceGenerator(ReadOnlySpan<byte> nonceSeed, int nonceLength)
    {
        if (nonceLength <= 0 || nonceSeed.Length < nonceLength)
        {
            throw new ArgumentOutOfRangeException(nameof(nonceLength), nonceLength, "VMess chunk nonce length is invalid.");
        }

        _nonce = nonceSeed.ToArray();
        _nonceLength = nonceLength;
    }

    public byte[] Next()
    {
        BinaryPrimitives.WriteUInt16BigEndian(_nonce.AsSpan(0, 2), _counter);
        _counter++;
        return _nonce.AsSpan(0, _nonceLength).ToArray();
    }
}

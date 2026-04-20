using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal enum VlessVisionCommand : byte
{
    Continue = 0x00,
    End = 0x01,
    Direct = 0x02
}

internal readonly record struct VlessVisionPaddingSeed(
    int LongThreshold,
    int LongRandomRange,
    int LongPaddingBase,
    int ShortRandomRange)
{
    public static VlessVisionPaddingSeed Default { get; } = new(900, 500, 900, 256);

    public static VlessVisionPaddingSeed FromTestSeed(IReadOnlyList<uint>? values)
    {
        if (values is null || values.Count < 4)
        {
            return Default;
        }

        return new VlessVisionPaddingSeed(
            ClampToInt(values[0]),
            ClampToInt(values[1]),
            ClampToInt(values[2]),
            ClampToInt(values[3]));
    }

    private static int ClampToInt(uint value)
        => value > int.MaxValue ? int.MaxValue : (int)value;
}

internal sealed class VlessVisionTrafficState
{
    public VlessVisionTrafficState(ReadOnlySpan<byte> userUuid)
    {
        if (userUuid.Length != VlessVisionPaddingCodec.UserUuidLength)
        {
            throw new ArgumentOutOfRangeException(nameof(userUuid), "Vision traffic state requires a 16-byte VLESS user UUID.");
        }

        UserUuid = userUuid.ToArray();
    }

    public byte[] UserUuid { get; }

    public int NumberOfPacketToFilter { get; set; } = 8;

    public bool EnableXtls { get; set; }

    public bool IsTls12OrAbove { get; set; }

    public bool IsTls { get; set; }

    public ushort Cipher { get; set; }

    public int RemainingServerHello { get; set; } = -1;

    public VlessVisionTrafficLinkState Inbound { get; } = new();

    public VlessVisionTrafficLinkState Outbound { get; } = new();
}

internal sealed class VlessVisionTrafficLinkState
{
    public bool WithinPaddingBuffers { get; set; } = true;

    public bool ReaderDirectCopy { get; set; }

    public int RemainingCommand { get; set; } = -1;

    public int RemainingContent { get; set; } = -1;

    public int RemainingPadding { get; set; } = -1;

    public int CurrentCommand { get; set; }

    public bool IsPadding { get; set; } = true;

    public bool WriterDirectCopy { get; set; }
}

internal sealed class VlessVisionDuplexStream : Stream, IInnerStreamAccessor
{
    private readonly Stream _innerStream;
    private readonly VlessVisionReadPipe _readPipe;
    private readonly VlessVisionWritePipe _writePipe;

    public VlessVisionDuplexStream(
        Stream innerStream,
        VlessVisionTrafficState trafficState,
        bool readIsUplink,
        bool writeIsUplink,
        VlessVisionPaddingSeed? paddingSeed = null)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        ArgumentNullException.ThrowIfNull(trafficState);

        _readPipe = new VlessVisionReadPipe(innerStream, trafficState, readIsUplink);
        _writePipe = new VlessVisionWritePipe(innerStream, trafficState, writeIsUplink, paddingSeed ?? VlessVisionPaddingSeed.Default);
    }

    public Stream InnerStream => _innerStream;

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

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _readPipe.ReadAsync(buffer, cancellationToken);

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _writePipe.WriteAsync(buffer, cancellationToken);

    internal ValueTask WriteCamouflagePaddingAsync(CancellationToken cancellationToken)
        => _writePipe.WriteAsync(ReadOnlyMemory<byte>.Empty, cancellationToken);

    public override void Flush()
        => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _innerStream.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync()
        => ValueTask.CompletedTask;
}

internal sealed class VlessVisionReadPipe
{
    private readonly Stream _innerStream;
    private readonly byte[] _readBuffer = new byte[VlessVisionPaddingCodec.MaxFrameSize];
    private readonly ResizableByteQueue _input = new();
    private readonly ResizableByteQueue _output = new();
    private readonly VlessVisionTrafficState _trafficState;
    private readonly VlessVisionTrafficLinkState _state;

    public VlessVisionReadPipe(
        Stream innerStream,
        VlessVisionTrafficState trafficState,
        bool isUplink)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _trafficState = trafficState ?? throw new ArgumentNullException(nameof(trafficState));
        _state = isUplink ? trafficState.Inbound : trafficState.Outbound;
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (buffer.Length == 0)
        {
            return 0;
        }

        if (_output.Length > 0)
        {
            return _output.Read(buffer.Span);
        }

        if (!_state.WithinPaddingBuffers || _state.ReaderDirectCopy)
        {
            if (_input.Length > 0)
            {
                return _input.Read(buffer.Span);
            }

            var rawRead = await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (rawRead > 0)
            {
                VlessVisionTlsClassifier.Inspect(buffer.Span[..rawRead], _trafficState);
            }

            return rawRead;
        }

        while (_output.Length == 0)
        {
            var read = await _innerStream.ReadAsync(_readBuffer.AsMemory(0, _readBuffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (_input.Length > 0)
                {
                    throw new InvalidDataException("Incomplete VLESS vision frame.");
                }

                return 0;
            }

            _input.Append(_readBuffer.AsSpan(0, read));
            DecodeBufferedInput();

            if ((_state.ReaderDirectCopy || !_state.WithinPaddingBuffers) &&
                _output.Length == 0 &&
                _input.Length > 0)
            {
                return _input.Read(buffer.Span);
            }
        }

        return _output.Read(buffer.Span);
    }

    private void DecodeBufferedInput()
    {
        while (_input.Length > 0 && _state.WithinPaddingBuffers)
        {
            if (_state.RemainingCommand == -1 &&
                _state.RemainingContent == -1 &&
                _state.RemainingPadding == -1)
            {
                if (_input.Length < VlessVisionPaddingCodec.InitialFramePrefixLength)
                {
                    return;
                }

                if (!_input.StartsWith(_trafficState.UserUuid))
                {
                    AppendDecodedOutput(_input.Span);
                    _input.Clear();
                    _state.WithinPaddingBuffers = false;
                    return;
                }

                _input.Consume(VlessVisionPaddingCodec.UserUuidLength);
                _state.RemainingCommand = VlessVisionPaddingCodec.FrameMetadataLength;
            }

            while (_state.RemainingCommand > 0)
            {
                if (_input.Length == 0)
                {
                    return;
                }

                var data = _input.PeekByte(0);
                _input.Consume(1);

                switch (_state.RemainingCommand)
                {
                    case 5:
                        _state.CurrentCommand = data;
                        break;
                    case 4:
                        _state.RemainingContent = data << 8;
                        break;
                    case 3:
                        _state.RemainingContent |= data;
                        break;
                    case 2:
                        _state.RemainingPadding = data << 8;
                        break;
                    case 1:
                        _state.RemainingPadding |= data;
                        break;
                }

                _state.RemainingCommand--;
            }

            if (_state.RemainingContent > 0)
            {
                var count = Math.Min(_state.RemainingContent, _input.Length);
                if (count == 0)
                {
                    return;
                }

                AppendDecodedOutput(_input.Slice(0, count));
                _input.Consume(count);
                _state.RemainingContent -= count;
                if (_state.RemainingContent > 0)
                {
                    return;
                }
            }

            if (_state.RemainingPadding > 0)
            {
                var count = Math.Min(_state.RemainingPadding, _input.Length);
                if (count == 0)
                {
                    return;
                }

                _input.Consume(count);
                _state.RemainingPadding -= count;
                if (_state.RemainingPadding > 0)
                {
                    return;
                }
            }

            if (_state.RemainingCommand <= 0 &&
                _state.RemainingContent <= 0 &&
                _state.RemainingPadding <= 0)
            {
                if (_state.CurrentCommand == (int)VlessVisionCommand.Continue)
                {
                    _state.RemainingCommand = VlessVisionPaddingCodec.FrameMetadataLength;
                    continue;
                }

                _state.RemainingCommand = -1;
                _state.RemainingContent = -1;
                _state.RemainingPadding = -1;
                _state.WithinPaddingBuffers = false;
                _state.ReaderDirectCopy = _state.CurrentCommand == (int)VlessVisionCommand.Direct;

                if (_input.Length > 0)
                {
                    AppendDecodedOutput(_input.Span);
                    _input.Clear();
                }

                return;
            }
        }
    }

    private void AppendDecodedOutput(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0)
        {
            return;
        }

        VlessVisionTlsClassifier.Inspect(payload, _trafficState);
        _output.Append(payload);
    }
}

internal sealed class VlessVisionWritePipe
{
    private readonly Stream _innerStream;
    private readonly VlessVisionPaddingSeed _paddingSeed;
    private readonly VlessVisionTrafficState _trafficState;
    private readonly VlessVisionTrafficLinkState _state;

    private byte[]? _writeOnceUserUuid;

    public VlessVisionWritePipe(
        Stream innerStream,
        VlessVisionTrafficState trafficState,
        bool isUplink,
        VlessVisionPaddingSeed paddingSeed)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _trafficState = trafficState ?? throw new ArgumentNullException(nameof(trafficState));
        _state = isUplink ? trafficState.Outbound : trafficState.Inbound;
        _paddingSeed = paddingSeed;
        _writeOnceUserUuid = trafficState.UserUuid.ToArray();
    }

    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        if (buffer.Length > 0)
        {
            VlessVisionTlsClassifier.Inspect(buffer.Span, _trafficState);
        }

        if (_state.WriterDirectCopy || !_state.IsPadding)
        {
            if (buffer.Length > 0)
            {
                await _innerStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }

            return;
        }

        if (buffer.Length == 0)
        {
            var camouflageFrame = VlessVisionPaddingCodec.CreatePaddingFrame(
                ReadOnlySpan<byte>.Empty,
                VlessVisionCommand.Continue,
                ref _writeOnceUserUuid,
                longPadding: true,
                _paddingSeed);
            await _innerStream.WriteAsync(camouflageFrame.AsMemory(0, camouflageFrame.Length), cancellationToken).ConfigureAwait(false);
            return;
        }

        using var encoded = new MemoryStream();
        var segments = VlessVisionPaddingCodec.ReshapePayload(buffer);
        var isCompleteTlsRecord = VlessVisionPaddingCodec.IsCompleteTlsRecord(buffer.Span);
        var longPadding = _trafficState.IsTls;

        for (var index = 0; index < segments.Count; index++)
        {
            var segment = segments[index];
            if (_trafficState.IsTls &&
                segment.Length >= 6 &&
                segment.Span[..3].SequenceEqual(VlessVisionPaddingCodec.TlsApplicationDataStart) &&
                isCompleteTlsRecord)
            {
                if (_trafficState.EnableXtls)
                {
                    _state.WriterDirectCopy = true;
                }

                var command = index == segments.Count - 1
                    ? _trafficState.EnableXtls
                        ? VlessVisionCommand.Direct
                        : VlessVisionCommand.End
                    : VlessVisionCommand.Continue;

                var paddedSegment = VlessVisionPaddingCodec.CreatePaddingFrame(
                    segment.Span,
                    command,
                    ref _writeOnceUserUuid,
                    longPadding,
                    _paddingSeed);
                await encoded.WriteAsync(paddedSegment.AsMemory(0, paddedSegment.Length), cancellationToken).ConfigureAwait(false);
                _state.IsPadding = false;
                longPadding = false;
                continue;
            }

            if (!_trafficState.IsTls12OrAbove &&
                _trafficState.NumberOfPacketToFilter <= 1)
            {
                var paddedSegment = VlessVisionPaddingCodec.CreatePaddingFrame(
                    segment.Span,
                    VlessVisionCommand.End,
                    ref _writeOnceUserUuid,
                    longPadding,
                    _paddingSeed);
                await encoded.WriteAsync(paddedSegment.AsMemory(0, paddedSegment.Length), cancellationToken).ConfigureAwait(false);
                _state.IsPadding = false;

                for (var rawIndex = index + 1; rawIndex < segments.Count; rawIndex++)
                {
                    await encoded.WriteAsync(segments[rawIndex], cancellationToken).ConfigureAwait(false);
                }

                break;
            }

            var currentCommand = VlessVisionCommand.Continue;
            if (index == segments.Count - 1 && !_state.IsPadding)
            {
                currentCommand = _trafficState.EnableXtls
                    ? VlessVisionCommand.Direct
                    : VlessVisionCommand.End;
            }

            var currentFrame = VlessVisionPaddingCodec.CreatePaddingFrame(
                segment.Span,
                currentCommand,
                ref _writeOnceUserUuid,
                longPadding,
                _paddingSeed);
            await encoded.WriteAsync(currentFrame.AsMemory(0, currentFrame.Length), cancellationToken).ConfigureAwait(false);
        }

        if (encoded.Length > 0)
        {
            await _innerStream.WriteAsync(encoded.GetBuffer().AsMemory(0, checked((int)encoded.Length)), cancellationToken).ConfigureAwait(false);
        }
    }
}

internal static class VlessVisionPaddingCodec
{
    public const int UserUuidLength = 16;
    public const int FrameMetadataLength = 5;
    public const int InitialFramePrefixLength = UserUuidLength + FrameMetadataLength;
    public const int MaxFrameSize = 8192;
    public const int MaxContentLength = MaxFrameSize - InitialFramePrefixLength;

    public static ReadOnlySpan<byte> TlsApplicationDataStart => [0x17, 0x03, 0x03];

    public static byte[] CreatePaddingFrame(
        ReadOnlySpan<byte> payload,
        VlessVisionCommand command,
        ref byte[]? writeOnceUserUuid,
        bool longPadding,
        VlessVisionPaddingSeed paddingSeed)
    {
        if (payload.Length > MaxContentLength)
        {
            throw new ArgumentOutOfRangeException(nameof(payload), payload.Length, "Vision payload exceeds the maximum framed content size.");
        }

        var contentLength = payload.Length;
        var paddingLength = CreatePaddingLength(contentLength, longPadding, paddingSeed);
        if (paddingLength > MaxContentLength - contentLength)
        {
            paddingLength = MaxContentLength - contentLength;
        }

        var hasUuidPrefix = writeOnceUserUuid is { Length: UserUuidLength };
        var frame = new byte[(hasUuidPrefix ? UserUuidLength : 0) + FrameMetadataLength + contentLength + paddingLength];
        var offset = 0;
        if (hasUuidPrefix)
        {
            writeOnceUserUuid!.CopyTo(frame, 0);
            offset += UserUuidLength;
            writeOnceUserUuid = null;
        }

        frame[offset++] = (byte)command;
        frame[offset++] = (byte)(contentLength >> 8);
        frame[offset++] = (byte)contentLength;
        frame[offset++] = (byte)(paddingLength >> 8);
        frame[offset++] = (byte)paddingLength;

        if (contentLength > 0)
        {
            payload.CopyTo(frame.AsSpan(offset, contentLength));
            offset += contentLength;
        }

        if (paddingLength > 0)
        {
            RandomNumberGenerator.Fill(frame.AsSpan(offset, paddingLength));
        }

        return frame;
    }

    public static IReadOnlyList<ReadOnlyMemory<byte>> ReshapePayload(ReadOnlyMemory<byte> payload)
    {
        if (payload.Length <= MaxContentLength)
        {
            return [payload];
        }

        var segments = new List<ReadOnlyMemory<byte>>();
        var remaining = payload;
        while (remaining.Length > MaxContentLength)
        {
            var chunk = remaining[..MaxContentLength];
            var splitIndex = chunk.Span.LastIndexOf(TlsApplicationDataStart);
            if (splitIndex < 21 || splitIndex > MaxContentLength - 21)
            {
                splitIndex = MaxFrameSize / 2;
            }

            segments.Add(remaining[..splitIndex]);
            remaining = remaining[splitIndex..];
        }

        if (remaining.Length > 0)
        {
            segments.Add(remaining);
        }

        return segments;
    }

    public static bool IsCompleteTlsRecord(ReadOnlySpan<byte> payload)
    {
        var headerLength = 5;
        var recordLength = 0;
        var index = 0;

        while (index < payload.Length)
        {
            if (headerLength > 0)
            {
                var current = payload[index++];
                switch (headerLength)
                {
                    case 5 when current != 0x17:
                    case 4 when current != 0x03:
                    case 3 when current != 0x03:
                        return false;
                    case 2:
                        recordLength = current << 8;
                        break;
                    case 1:
                        recordLength |= current;
                        break;
                }

                headerLength--;
                continue;
            }

            if (recordLength <= 0)
            {
                return false;
            }

            var remaining = payload.Length - index;
            if (remaining < recordLength)
            {
                return false;
            }

            index += recordLength;
            recordLength = 0;
            headerLength = 5;
        }

        return headerLength == 5 && recordLength == 0;
    }

    private static int CreatePaddingLength(
        int contentLength,
        bool longPadding,
        VlessVisionPaddingSeed paddingSeed)
    {
        if (contentLength < paddingSeed.LongThreshold && longPadding)
        {
            return NextInt(paddingSeed.LongRandomRange) + paddingSeed.LongPaddingBase - contentLength;
        }

        return NextInt(paddingSeed.ShortRandomRange);
    }

    private static int NextInt(int maxExclusive)
        => maxExclusive <= 0 ? 0 : RandomNumberGenerator.GetInt32(maxExclusive);
}

internal static class VlessVisionTlsClassifier
{
    private static readonly byte[] Tls13SupportedVersions = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
    private static readonly byte[] TlsClientHandshakeStart = [0x16, 0x03];
    private static readonly byte[] TlsServerHandshakeStart = [0x16, 0x03, 0x03];

    public static void Inspect(ReadOnlySpan<byte> payload, VlessVisionTrafficState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (payload.Length == 0 || state.NumberOfPacketToFilter <= 0)
        {
            return;
        }

        state.NumberOfPacketToFilter--;

        if (payload.Length >= 6)
        {
            var start = payload[..6];
            if (start[..3].SequenceEqual(TlsServerHandshakeStart) &&
                start[5] == 0x02)
            {
                state.RemainingServerHello = ((start[3] << 8) | start[4]) + 5;
                state.IsTls12OrAbove = true;
                state.IsTls = true;
                if (payload.Length >= 79 && state.RemainingServerHello >= 79)
                {
                    var sessionIdLength = payload[43];
                    var cipherIndex = 43 + sessionIdLength + 1;
                    if (cipherIndex + 1 < payload.Length)
                    {
                        state.Cipher = (ushort)((payload[cipherIndex] << 8) | payload[cipherIndex + 1]);
                    }
                }
            }
            else if (start[..2].SequenceEqual(TlsClientHandshakeStart) &&
                     start[5] == 0x01)
            {
                state.IsTls = true;
            }
        }

        if (state.RemainingServerHello <= 0)
        {
            return;
        }

        var end = Math.Min(state.RemainingServerHello, payload.Length);
        state.RemainingServerHello -= payload.Length;
        if (payload[..end].IndexOf(Tls13SupportedVersions) >= 0)
        {
            state.EnableXtls = state.Cipher != 0x1305;
            state.NumberOfPacketToFilter = 0;
            return;
        }

        if (state.RemainingServerHello <= 0)
        {
            state.NumberOfPacketToFilter = 0;
        }
    }
}

internal sealed class ResizableByteQueue
{
    private byte[] _buffer = Array.Empty<byte>();
    private int _offset;
    private int _length;

    public int Length => _length;

    public ReadOnlySpan<byte> Span => _buffer.AsSpan(_offset, _length);

    public void Append(ReadOnlySpan<byte> source)
    {
        if (source.Length == 0)
        {
            return;
        }

        EnsureCapacity(_length + source.Length);
        source.CopyTo(_buffer.AsSpan(_offset + _length, source.Length));
        _length += source.Length;
    }

    public bool StartsWith(ReadOnlySpan<byte> prefix)
        => _length >= prefix.Length && Span[..prefix.Length].SequenceEqual(prefix);

    public byte PeekByte(int index)
    {
        if ((uint)index >= (uint)_length)
        {
            throw new ArgumentOutOfRangeException(nameof(index));
        }

        return _buffer[_offset + index];
    }

    public ReadOnlySpan<byte> Slice(int offset, int length)
    {
        if (offset < 0 || length < 0 || offset + length > _length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset));
        }

        return _buffer.AsSpan(_offset + offset, length);
    }

    public int Read(Span<byte> destination)
    {
        var count = Math.Min(destination.Length, _length);
        if (count == 0)
        {
            return 0;
        }

        Span[..count].CopyTo(destination);
        Consume(count);
        return count;
    }

    public void Consume(int count)
    {
        if (count < 0 || count > _length)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        _offset += count;
        _length -= count;
        if (_length == 0)
        {
            _offset = 0;
        }
        else if (_offset > _buffer.Length / 2)
        {
            Compact();
        }
    }

    public void Clear()
    {
        _offset = 0;
        _length = 0;
    }

    private void EnsureCapacity(int required)
    {
        if (_buffer.Length == 0)
        {
            _buffer = new byte[Math.Max(256, required)];
            return;
        }

        if (_offset + required <= _buffer.Length)
        {
            return;
        }

        if (required <= _buffer.Length)
        {
            Compact();
            return;
        }

        var newBuffer = new byte[Math.Max(_buffer.Length * 2, required)];
        Span.CopyTo(newBuffer);
        _buffer = newBuffer;
        _offset = 0;
    }

    private void Compact()
    {
        if (_length > 0)
        {
            Span.CopyTo(_buffer);
        }

        _offset = 0;
    }
}

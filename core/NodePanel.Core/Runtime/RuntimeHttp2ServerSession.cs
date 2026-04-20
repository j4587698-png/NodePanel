using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeHttp2ServerSession : IAsyncDisposable
{
    private const int DefaultInitialWindowSize = 65_535;
    private const int DefaultMaxFrameSize = 16_384;
    private const int WindowUpdateThreshold = DefaultMaxFrameSize;
    private static readonly TimeSpan DefaultKeepAliveAckTimeout = TimeSpan.FromSeconds(20);
    private static readonly byte[] ClientConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();
    private static readonly byte[] RemainingClientConnectionPreface = "SM\r\n\r\n"u8.ToArray();

    private readonly Stream _transportStream;
    private readonly RuntimeHttp2ServerSessionOptions _options;
    private readonly SemaphoreSlim _frameWriteLock = new(1, 1);
    private readonly object _stateLock = new();
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly Channel<AcceptedRequest> _acceptedRequests = Channel.CreateUnbounded<AcceptedRequest>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true
        });

    private Task? _keepAliveLoopTask;
    private TaskCompletionSource<bool>? _pendingPingAckTcs;
    private byte[]? _pendingPingPayload;
    private Task? _receiveLoopTask;
    private TaskCompletionSource<bool>? _sendWindowWaiter;
    private readonly Dictionary<int, StreamState> _streams = new();
    private long _connectionSendWindow = DefaultInitialWindowSize;
    private long _keepAlivePingSequence;
    private long _lastActivityTimestampMilliseconds = Environment.TickCount64;
    private int _remoteInitialWindowSize = DefaultInitialWindowSize;
    private int _remoteMaxFrameSize = DefaultMaxFrameSize;
    private Exception? _terminalException;
    private int _disposed;

    private RuntimeHttp2ServerSession(
        Stream transportStream,
        RuntimeHttp2ServerSessionOptions options)
    {
        _transportStream = transportStream ?? throw new ArgumentNullException(nameof(transportStream));
        _options = options ?? RuntimeHttp2ServerSessionOptions.Default;
    }

    public static async ValueTask<RuntimeHttp2ServerSession> AcceptAsync(
        Stream transportStream,
        CancellationToken cancellationToken,
        RuntimeHttp2ServerSessionOptions? options = null)
        => await CreateAsync(transportStream, prefaceTailOnly: false, cancellationToken, options).ConfigureAwait(false);

    public static async ValueTask<RuntimeHttp2ServerSession> AcceptAfterPrefaceHeadAsync(
        Stream transportStream,
        CancellationToken cancellationToken,
        RuntimeHttp2ServerSessionOptions? options = null)
        => await CreateAsync(transportStream, prefaceTailOnly: true, cancellationToken, options).ConfigureAwait(false);

    private static async ValueTask<RuntimeHttp2ServerSession> CreateAsync(
        Stream transportStream,
        bool prefaceTailOnly,
        CancellationToken cancellationToken,
        RuntimeHttp2ServerSessionOptions? options)
    {
        var session = new RuntimeHttp2ServerSession(
            transportStream,
            RuntimeHttp2ServerSessionOptions.Normalize(options));
        try
        {
            await session.InitializeAsync(prefaceTailOnly, cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<AcceptedRequest?> AcceptRequestAsync(CancellationToken cancellationToken)
    {
        AcceptedRequest request;
        try
        {
            request = await _acceptedRequests.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
            }

            return null;
        }

        return request;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetimeCts.Cancel();
        _acceptedRequests.Writer.TryComplete(new ObjectDisposedException(nameof(RuntimeHttp2ServerSession)));
        CompletePendingPingAck(new ObjectDisposedException(nameof(RuntimeHttp2ServerSession)));
        SignalSendWindowWaiter();
        CompleteStreams(new ObjectDisposedException(nameof(RuntimeHttp2ServerSession)));

        try
        {
            await _transportStream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        if (_receiveLoopTask is not null)
        {
            try
            {
                await _receiveLoopTask.ConfigureAwait(false);
            }
            catch
            {
            }
        }

        if (_keepAliveLoopTask is not null)
        {
            try
            {
                await _keepAliveLoopTask.ConfigureAwait(false);
            }
            catch
            {
            }
        }

        _frameWriteLock.Dispose();
        _lifetimeCts.Dispose();
    }

    internal async ValueTask<int> ReadAsync(
        StreamState state,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (buffer.Length == 0)
        {
            return 0;
        }

        if (!await EnsureReadBufferAsync(state, cancellationToken).ConfigureAwait(false))
        {
            ThrowIfFaulted(state);
            return 0;
        }

        var readBuffer = state.ReadBuffer!;
        var available = readBuffer.Length - state.ReadBufferOffset;
        var read = Math.Min(buffer.Length, available);
        readBuffer.AsMemory(state.ReadBufferOffset, read).CopyTo(buffer);
        state.ReadBufferOffset += read;
        if (state.ReadBufferOffset >= readBuffer.Length)
        {
            state.ReadBuffer = null;
            state.ReadBufferOffset = 0;
        }

        await OnBytesConsumedAsync(state, read, cancellationToken).ConfigureAwait(false);
        return read;
    }

    internal async ValueTask WriteAsync(
        StreamState state,
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (buffer.Length == 0)
        {
            return;
        }

        await state.WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var offset = 0;
            while (offset < buffer.Length)
            {
                await WaitForSendWindowAsync(state, cancellationToken).ConfigureAwait(false);

                int chunkLength;
                lock (_stateLock)
                {
                    ThrowIfFaultedCore();
                    EnsureWritableStateCore(state);
                    chunkLength = (int)Math.Min(
                        Math.Min(_connectionSendWindow, state.SendWindow),
                        Math.Min(_remoteMaxFrameSize, buffer.Length - offset));
                    _connectionSendWindow -= chunkLength;
                    state.SendWindow -= chunkLength;
                }

                if (chunkLength <= 0)
                {
                    continue;
                }

                await WriteFrameAsync(
                        Http2FrameType.Data,
                        Http2FrameFlags.None,
                        state.StreamId,
                        buffer.Slice(offset, chunkLength),
                        cancellationToken)
                    .ConfigureAwait(false);
                offset += chunkLength;
            }
        }
        finally
        {
            state.WriteLock.Release();
        }
    }

    internal async ValueTask WriteResponseHeadersAsync(
        StreamState state,
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        bool endStream,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(headers);

        byte[] payload;
        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            EnsureWritableStateCore(state);
            if (state.ResponseHeadersSent)
            {
                throw new InvalidOperationException("HTTP/2 response headers were already sent.");
            }

            state.ResponseHeadersSent = true;
            payload = BuildResponseHeaderBlock(statusCode, headers);
        }

        await WriteFrameAsync(
                Http2FrameType.Headers,
                endStream
                    ? Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream
                    : Http2FrameFlags.EndHeaders,
                state.StreamId,
                payload,
                cancellationToken)
            .ConfigureAwait(false);

        if (endStream)
        {
            FinalizeLocalCompletion(state);
        }
    }

    internal async ValueTask CompleteResponseAsync(
        StreamState state,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            EnsureWritableStateCore(state);
            if (!state.ResponseHeadersSent)
            {
                throw new InvalidOperationException("HTTP/2 response headers must be sent before completing the response.");
            }
        }

        await WriteFrameAsync(
                Http2FrameType.Data,
                Http2FrameFlags.EndStream,
                state.StreamId,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);

        FinalizeLocalCompletion(state);
    }

    internal async ValueTask WriteResponseTrailersAsync(
        StreamState state,
        IReadOnlyDictionary<string, string> trailers,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(trailers);

        byte[] payload;
        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            EnsureWritableStateCore(state);
            if (!state.ResponseHeadersSent)
            {
                throw new InvalidOperationException("HTTP/2 response headers must be sent before writing response trailers.");
            }

            payload = BuildResponseHeaderBlock(trailers);
        }

        await WriteFrameAsync(
                Http2FrameType.Headers,
                Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                state.StreamId,
                payload,
                cancellationToken)
            .ConfigureAwait(false);

        FinalizeLocalCompletion(state);
    }

    internal async ValueTask ResetStreamAsync(
        StreamState state,
        uint errorCode,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        var shouldSendReset = false;
        lock (_stateLock)
        {
            if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            _streams.Remove(state.StreamId);
            state.LocalCompleted = true;
            state.SessionClosed = true;
            shouldSendReset = _terminalException is null && state.TerminalException is null;
        }

        state.Incoming.Writer.TryComplete();
        SignalSendWindowWaiter();

        try
        {
            if (shouldSendReset)
            {
                await WriteRstStreamAsync(state.StreamId, errorCode, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            state.WriteLock.Dispose();
        }
    }

    private async Task InitializeAsync(bool prefaceTailOnly, CancellationToken cancellationToken)
    {
        await ReadClientConnectionPrefaceAsync(prefaceTailOnly, cancellationToken).ConfigureAwait(false);
        await WriteServerSettingsAsync(cancellationToken).ConfigureAwait(false);
        await WriteSettingsAckAsync(cancellationToken).ConfigureAwait(false);
        _receiveLoopTask = ReceiveLoopAsync(_lifetimeCts.Token);
        if (_options.KeepAliveInterval > TimeSpan.Zero)
        {
            _keepAliveLoopTask = KeepAliveLoopAsync(_lifetimeCts.Token);
        }
    }

    private async Task ReadClientConnectionPrefaceAsync(
        bool prefaceTailOnly,
        CancellationToken cancellationToken)
    {
        var expectedPreface = prefaceTailOnly ? RemainingClientConnectionPreface : ClientConnectionPreface;
        var preface = await ReadExactBytesAsync(_transportStream, expectedPreface.Length, cancellationToken).ConfigureAwait(false);
        if (!preface.AsSpan().SequenceEqual(expectedPreface))
        {
            throw new InvalidDataException("HTTP/2 client preface is invalid.");
        }

        var frameHeader = await ReadFrameHeaderAsync(_transportStream, cancellationToken).ConfigureAwait(false);
        if (frameHeader.Type != Http2FrameType.Settings ||
            frameHeader.StreamId != 0 ||
            (frameHeader.Flags & Http2FrameFlags.Ack) == Http2FrameFlags.Ack)
        {
            throw new InvalidDataException("HTTP/2 client preface must be followed by a SETTINGS frame.");
        }

        var payload = frameHeader.Length == 0
            ? Array.Empty<byte>()
            : await ReadExactBytesAsync(_transportStream, frameHeader.Length, cancellationToken).ConfigureAwait(false);
        RecordActivity();
        ApplySettingsPayload(payload);
    }

    private async Task<bool> EnsureReadBufferAsync(
        StreamState state,
        CancellationToken cancellationToken)
    {
        if (state.ReadBuffer is not null && state.ReadBufferOffset < state.ReadBuffer.Length)
        {
            return true;
        }

        try
        {
            state.ReadBuffer = await state.Incoming.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            state.ReadBufferOffset = 0;
            return true;
        }
        catch (ChannelClosedException)
        {
            state.ReadBuffer = null;
            state.ReadBufferOffset = 0;
            return false;
        }
    }

    private async Task OnBytesConsumedAsync(
        StreamState state,
        int count,
        CancellationToken cancellationToken)
    {
        if (count <= 0)
        {
            return;
        }

        int windowUpdateBytes = 0;
        lock (_stateLock)
        {
            if (state.SessionClosed ||
                !_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state))
            {
                return;
            }

            state.PendingWindowUpdateBytes += count;
            if (state.PendingWindowUpdateBytes >= WindowUpdateThreshold)
            {
                windowUpdateBytes = state.PendingWindowUpdateBytes;
                state.PendingWindowUpdateBytes = 0;
            }
        }

        if (windowUpdateBytes > 0)
        {
            await SendWindowUpdatePairAsync(state, windowUpdateBytes, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WaitForSendWindowAsync(
        StreamState state,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            Task waiterTask;
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureWritableStateCore(state);
                if (_connectionSendWindow > 0 && state.SendWindow > 0)
                {
                    return;
                }

                _sendWindowWaiter ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                waiterTask = _sendWindowWaiter.Task;
            }

            await waiterTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var frameHeader = await TryReadFrameHeaderAsync(_transportStream, cancellationToken).ConfigureAwait(false);
                if (frameHeader is null)
                {
                    _acceptedRequests.Writer.TryComplete();
                    CompleteStreams(null);
                    return;
                }

                var currentFrameHeader = frameHeader.Value;
                var payload = currentFrameHeader.Length == 0
                    ? Array.Empty<byte>()
                    : await ReadExactBytesAsync(_transportStream, currentFrameHeader.Length, cancellationToken).ConfigureAwait(false);
                RecordActivity();

                switch (currentFrameHeader.Type)
                {
                    case Http2FrameType.Settings:
                        await HandleSettingsFrameAsync(currentFrameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.WindowUpdate:
                        HandleWindowUpdateFrame(currentFrameHeader, payload);
                        break;
                    case Http2FrameType.Headers:
                        await HandleHeadersFrameAsync(currentFrameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.Data:
                        await HandleDataFrameAsync(currentFrameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.Ping:
                        await HandlePingFrameAsync(currentFrameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.RstStream:
                        HandleRstStreamFrame(currentFrameHeader, payload);
                        break;
                    case Http2FrameType.GoAway:
                        HandleGoAwayFrame(payload);
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _acceptedRequests.Writer.TryComplete();
            CompleteStreams(null);
        }
        catch (Exception ex)
        {
            Fail(ex);
        }
    }

    private async Task HandleSettingsFrameAsync(
        Http2FrameHeader frameHeader,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (frameHeader.StreamId != 0)
        {
            throw new InvalidDataException("HTTP/2 SETTINGS frame must use stream id 0.");
        }

        if ((frameHeader.Flags & Http2FrameFlags.Ack) == Http2FrameFlags.Ack)
        {
            if (payload.Length != 0)
            {
                throw new InvalidDataException("HTTP/2 SETTINGS ACK frame must not carry a payload.");
            }

            return;
        }

        ApplySettingsPayload(payload);
        await WriteSettingsAckAsync(cancellationToken).ConfigureAwait(false);
    }

    private void ApplySettingsPayload(byte[] payload)
    {
        if (payload.Length % 6 != 0)
        {
            throw new InvalidDataException("HTTP/2 SETTINGS payload length must be a multiple of 6 bytes.");
        }

        for (var offset = 0; offset < payload.Length; offset += 6)
        {
            var identifier = ReadUInt16(payload, offset);
            var value = ReadUInt32(payload, offset + 2);
            switch (identifier)
            {
                case Http2SettingsIdentifiers.InitialWindowSize:
                {
                    if (value > int.MaxValue)
                    {
                        throw new InvalidDataException("HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE exceeded the supported range.");
                    }

                    ApplyInitialWindowSize((int)value);
                    break;
                }
                case Http2SettingsIdentifiers.MaxFrameSize:
                {
                    if (value is < 16_384 or > 16_777_215)
                    {
                        throw new InvalidDataException("HTTP/2 SETTINGS_MAX_FRAME_SIZE is invalid.");
                    }

                    lock (_stateLock)
                    {
                        _remoteMaxFrameSize = (int)value;
                    }

                    break;
                }
            }
        }

        SignalSendWindowWaiter();
    }

    private void ApplyInitialWindowSize(int value)
    {
        lock (_stateLock)
        {
            var delta = value - _remoteInitialWindowSize;
            _remoteInitialWindowSize = value;
            foreach (var state in _streams.Values)
            {
                state.SendWindow += delta;
            }
        }

        SignalSendWindowWaiter();
    }

    private async Task HandleHeadersFrameAsync(
        Http2FrameHeader frameHeader,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (frameHeader.StreamId == 0)
        {
            throw new InvalidDataException("HTTP/2 HEADERS frame must use a non-zero stream id.");
        }

        var headerBlock = await ReadHeaderBlockAsync(frameHeader, payload, cancellationToken).ConfigureAwait(false);

        var acceptedState = GetStreamState(frameHeader.StreamId);
        if (acceptedState is null)
        {
            IReadOnlyDictionary<string, string> headers;
            try
            {
                headers = DecodeHeaders(headerBlock);
            }
            catch (InvalidDataException ex)
            {
                throw new InvalidDataException(
                    $"Failed to decode HTTP/2 request headers. Header block: {Convert.ToHexString(headerBlock)}",
                    ex);
            }

            if (!headers.TryGetValue(":method", out var method) || string.IsNullOrWhiteSpace(method) ||
                !headers.TryGetValue(":path", out var target) || string.IsNullOrWhiteSpace(target))
            {
                throw new InvalidDataException("HTTP/2 request is missing required pseudo headers.");
            }

            var state = new StreamState(frameHeader.StreamId, _remoteInitialWindowSize)
            {
                RemoteCompleted = (frameHeader.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream
            };

            lock (_stateLock)
            {
                if (_streams.ContainsKey(frameHeader.StreamId))
                {
                    throw new InvalidOperationException($"HTTP/2 stream id {frameHeader.StreamId} was opened more than once.");
                }

                _streams.Add(frameHeader.StreamId, state);
            }

            if (state.RemoteCompleted)
            {
                state.Incoming.Writer.TryComplete();
            }

            _acceptedRequests.Writer.TryWrite(new AcceptedRequest(this, state, headers));
            return;
        }

        if ((frameHeader.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream)
        {
            FinalizeRemoteCompletion(acceptedState);
        }
    }

    private async Task HandleDataFrameAsync(
        Http2FrameHeader frameHeader,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var state = GetStreamState(frameHeader.StreamId);
        if (state is null)
        {
            return;
        }

        var data = UnwrapDataPayload(frameHeader, payload);
        if (data.Length > 0)
        {
            await state.Incoming.Writer.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        }

        if ((frameHeader.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream)
        {
            FinalizeRemoteCompletion(state);
        }
    }

    private async Task HandlePingFrameAsync(
        Http2FrameHeader frameHeader,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (frameHeader.StreamId != 0)
        {
            throw new InvalidDataException("HTTP/2 PING frame must use stream id 0.");
        }

        if (payload.Length != 8)
        {
            throw new InvalidDataException("HTTP/2 PING payload length must be 8 bytes.");
        }

        if ((frameHeader.Flags & Http2FrameFlags.Ack) == Http2FrameFlags.Ack)
        {
            TaskCompletionSource<bool>? pingAckTcs = null;
            lock (_stateLock)
            {
                if (_pendingPingPayload is not null &&
                    payload.AsSpan().SequenceEqual(_pendingPingPayload))
                {
                    pingAckTcs = _pendingPingAckTcs;
                    _pendingPingAckTcs = null;
                    _pendingPingPayload = null;
                }
            }

            pingAckTcs?.TrySetResult(true);
            return;
        }

        await WriteFrameAsync(
                Http2FrameType.Ping,
                Http2FrameFlags.Ack,
                streamId: 0,
                payload,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private void HandleWindowUpdateFrame(Http2FrameHeader frameHeader, byte[] payload)
    {
        if (payload.Length != 4)
        {
            throw new InvalidDataException("HTTP/2 WINDOW_UPDATE payload length must be 4 bytes.");
        }

        var increment = (int)(ReadUInt32(payload, 0) & 0x7FFF_FFFFu);
        if (increment <= 0)
        {
            throw new InvalidDataException("HTTP/2 WINDOW_UPDATE increment must be positive.");
        }

        lock (_stateLock)
        {
            if (frameHeader.StreamId == 0)
            {
                _connectionSendWindow += increment;
            }
            else if (_streams.TryGetValue(frameHeader.StreamId, out var state))
            {
                state.SendWindow += increment;
            }
        }

        SignalSendWindowWaiter();
    }

    private void HandleRstStreamFrame(Http2FrameHeader frameHeader, byte[] payload)
    {
        var state = GetStreamState(frameHeader.StreamId);
        if (state is null)
        {
            return;
        }

        if (payload.Length != 4)
        {
            throw new InvalidDataException("HTTP/2 RST_STREAM payload length must be 4 bytes.");
        }

        var errorCode = ReadUInt32(payload, 0);
        var exception = new IOException($"HTTP/2 stream was reset by the peer. Error code: {errorCode.ToString(CultureInfo.InvariantCulture)}.");
        state.TerminalException = exception;
        CompleteState(state, exception);
        SignalSendWindowWaiter();
    }

    private void HandleGoAwayFrame(byte[] payload)
    {
        if (payload.Length < 8)
        {
            throw new InvalidDataException("HTTP/2 GOAWAY payload is too short.");
        }

        var errorCode = ReadUInt32(payload, 4);
        if (errorCode != 0)
        {
            throw new IOException($"HTTP/2 peer sent GOAWAY. Error code: {errorCode.ToString(CultureInfo.InvariantCulture)}.");
        }
    }

    private async Task SendWindowUpdatePairAsync(
        StreamState state,
        int increment,
        CancellationToken cancellationToken)
    {
        if (increment <= 0 || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        var payload = new byte[4];
        WriteUInt32(payload, 0, (uint)increment);

        try
        {
            await WriteFrameAsync(
                    Http2FrameType.WindowUpdate,
                    Http2FrameFlags.None,
                    streamId: 0,
                    payload,
                    cancellationToken)
                .ConfigureAwait(false);
            await WriteFrameAsync(
                    Http2FrameType.WindowUpdate,
                    Http2FrameFlags.None,
                    state.StreamId,
                    payload,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task WriteServerSettingsAsync(CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> settingsPayload = ReadOnlyMemory<byte>.Empty;
        if (_options.InitialReceiveWindowSize > 0)
        {
            var payload = new byte[6];
            WriteUInt16(payload, 0, Http2SettingsIdentifiers.InitialWindowSize);
            WriteUInt32(payload, 2, checked((uint)_options.InitialReceiveWindowSize));
            settingsPayload = payload;
        }

        await WriteFrameAsync(
                Http2FrameType.Settings,
                Http2FrameFlags.None,
                streamId: 0,
                settingsPayload,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task WriteSettingsAckAsync(CancellationToken cancellationToken)
        => await WriteFrameAsync(
                Http2FrameType.Settings,
                Http2FrameFlags.Ack,
                streamId: 0,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);

    private async Task<byte[]> ReadHeaderBlockAsync(
        Http2FrameHeader frameHeader,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var fragment = UnwrapHeaderBlockFragment(frameHeader, payload);
        if ((frameHeader.Flags & Http2FrameFlags.EndHeaders) == Http2FrameFlags.EndHeaders)
        {
            return fragment;
        }

        using var buffer = new MemoryStream(fragment.Length + DefaultMaxFrameSize);
        if (fragment.Length > 0)
        {
            buffer.Write(fragment, 0, fragment.Length);
        }

        while (true)
        {
            var continuationHeader = await ReadFrameHeaderAsync(_transportStream, cancellationToken).ConfigureAwait(false);
            if (continuationHeader.Type != Http2FrameType.Continuation ||
                continuationHeader.StreamId != frameHeader.StreamId)
            {
                throw new InvalidDataException("HTTP/2 CONTINUATION frame sequence is invalid.");
            }

            var continuationPayload = continuationHeader.Length == 0
                ? Array.Empty<byte>()
                : await ReadExactBytesAsync(_transportStream, continuationHeader.Length, cancellationToken).ConfigureAwait(false);
            RecordActivity();
            if (continuationPayload.Length > 0)
            {
                buffer.Write(continuationPayload, 0, continuationPayload.Length);
            }

            if ((continuationHeader.Flags & Http2FrameFlags.EndHeaders) == Http2FrameFlags.EndHeaders)
            {
                return buffer.ToArray();
            }
        }
    }

    private async Task WriteFrameAsync(
        byte frameType,
        Http2FrameFlags flags,
        int streamId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var frameHeader = Http2FrameHeader.Create(payload.Length, frameType, flags, streamId);

        await _frameWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteFrameHeaderAsync(frameHeader, cancellationToken).ConfigureAwait(false);
            if (payload.Length > 0)
            {
                await _transportStream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            }

            await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            RecordActivity();
        }
        finally
        {
            _frameWriteLock.Release();
        }
    }

    private async Task WriteFrameHeaderAsync(
        Http2FrameHeader frameHeader,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)((frameHeader.Length >> 16) & 0xFF);
        header[1] = (byte)((frameHeader.Length >> 8) & 0xFF);
        header[2] = (byte)(frameHeader.Length & 0xFF);
        header[3] = frameHeader.Type;
        header[4] = (byte)frameHeader.Flags;
        header[5] = (byte)((frameHeader.StreamId >> 24) & 0x7F);
        header[6] = (byte)((frameHeader.StreamId >> 16) & 0xFF);
        header[7] = (byte)((frameHeader.StreamId >> 8) & 0xFF);
        header[8] = (byte)(frameHeader.StreamId & 0xFF);
        await _transportStream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
    }

    private async Task WriteRstStreamAsync(
        int streamId,
        uint errorCode,
        CancellationToken cancellationToken)
    {
        var payload = new byte[4];
        WriteUInt32(payload, 0, errorCode);
        await WriteFrameAsync(
                Http2FrameType.RstStream,
                Http2FrameFlags.None,
                streamId,
                payload,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task KeepAliveLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var delay = GetKeepAliveDelay();
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }

                if (!ShouldSendKeepAlivePing())
                {
                    continue;
                }

                await SendKeepAlivePingAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Fail(ex);
        }
    }

    private TimeSpan GetKeepAliveDelay()
    {
        var elapsedMilliseconds = Math.Max(0, Environment.TickCount64 - Volatile.Read(ref _lastActivityTimestampMilliseconds));
        var remaining = _options.KeepAliveInterval - TimeSpan.FromMilliseconds(elapsedMilliseconds);
        return remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero;
    }

    private bool ShouldSendKeepAlivePing()
    {
        if (_options.KeepAliveInterval <= TimeSpan.Zero)
        {
            return false;
        }

        if (Environment.TickCount64 - Volatile.Read(ref _lastActivityTimestampMilliseconds) <
            (long)_options.KeepAliveInterval.TotalMilliseconds)
        {
            return false;
        }

        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            return _pendingPingAckTcs is null &&
                   (_options.PermitKeepAliveWithoutStreams || _streams.Count > 0);
        }
    }

    private async Task SendKeepAlivePingAsync(CancellationToken cancellationToken)
    {
        var pingPayload = CreateKeepAlivePingPayload();
        TaskCompletionSource<bool> pingAckTcs;

        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            if (_pendingPingAckTcs is not null)
            {
                return;
            }

            pingAckTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingPingAckTcs = pingAckTcs;
            _pendingPingPayload = pingPayload;
        }

        try
        {
            await WriteFrameAsync(
                    Http2FrameType.Ping,
                    Http2FrameFlags.None,
                    streamId: 0,
                    pingPayload,
                    cancellationToken)
                .ConfigureAwait(false);
            await pingAckTcs.Task
                .WaitAsync(GetKeepAliveTimeout(), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            var exception = new IOException("HTTP/2 keepalive PING acknowledgement timed out.");
            CompletePendingPingAck(exception, pingAckTcs);
            throw exception;
        }
        catch
        {
            CompletePendingPingAck(new OperationCanceledException("HTTP/2 keepalive PING did not complete."), pingAckTcs);
            throw;
        }
    }

    private TimeSpan GetKeepAliveTimeout()
        => _options.KeepAliveTimeout > TimeSpan.Zero
            ? _options.KeepAliveTimeout
            : DefaultKeepAliveAckTimeout;

    private byte[] CreateKeepAlivePingPayload()
    {
        var payload = new byte[8];
        var sequence = Interlocked.Increment(ref _keepAlivePingSequence);
        WriteUInt32(payload, 0, (uint)(sequence >> 32));
        WriteUInt32(payload, 4, (uint)(sequence & 0xFFFF_FFFF));
        return payload;
    }

    private void CompletePendingPingAck(
        Exception exception,
        TaskCompletionSource<bool>? expectedPingAckTcs = null)
    {
        TaskCompletionSource<bool>? pingAckTcs = null;

        lock (_stateLock)
        {
            if (expectedPingAckTcs is not null &&
                !ReferenceEquals(_pendingPingAckTcs, expectedPingAckTcs))
            {
                return;
            }

            pingAckTcs = _pendingPingAckTcs;
            _pendingPingAckTcs = null;
            _pendingPingPayload = null;
        }

        pingAckTcs?.TrySetException(exception);
    }

    private void RecordActivity()
        => Volatile.Write(ref _lastActivityTimestampMilliseconds, Environment.TickCount64);

    private void FinalizeRemoteCompletion(StreamState state)
    {
        bool fullyClosed;
        lock (_stateLock)
        {
            if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            state.RemoteCompleted = true;
            fullyClosed = state.LocalCompleted;
            if (fullyClosed)
            {
                _streams.Remove(state.StreamId);
                state.SessionClosed = true;
            }
        }

        state.Incoming.Writer.TryComplete();
        SignalSendWindowWaiter();
        if (fullyClosed)
        {
            state.WriteLock.Dispose();
        }
    }

    private void FinalizeLocalCompletion(StreamState state)
    {
        bool fullyClosed;
        lock (_stateLock)
        {
            if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            state.LocalCompleted = true;
            fullyClosed = state.RemoteCompleted;
            if (fullyClosed)
            {
                _streams.Remove(state.StreamId);
                state.SessionClosed = true;
            }
        }

        SignalSendWindowWaiter();
        if (fullyClosed)
        {
            state.WriteLock.Dispose();
        }
    }

    private void CompleteState(StreamState state, Exception? exception)
    {
        lock (_stateLock)
        {
            if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            _streams.Remove(state.StreamId);
            state.SessionClosed = true;
        }

        if (exception is null)
        {
            state.Incoming.Writer.TryComplete();
        }
        else
        {
            state.TerminalException ??= exception;
            state.Incoming.Writer.TryComplete(exception);
        }

        state.WriteLock.Dispose();
    }

    private StreamState? GetStreamState(int streamId)
    {
        lock (_stateLock)
        {
            return _streams.TryGetValue(streamId, out var state)
                ? state
                : null;
        }
    }

    private bool IsRemoteCompleted(StreamState state)
    {
        lock (_stateLock)
        {
            return state.RemoteCompleted;
        }
    }

    private void EnsureReadableStateCore(StreamState state)
    {
        if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
            !ReferenceEquals(tracked, state) ||
            state.SessionClosed)
        {
            throw new IOException("HTTP/2 stream is no longer active.");
        }
    }

    private void EnsureWritableStateCore(StreamState state)
    {
        EnsureReadableStateCore(state);
        if (state.LocalCompleted)
        {
            throw new IOException("HTTP/2 response stream is already closed.");
        }
    }

    private void ThrowIfFaulted(StreamState state)
    {
        if (state.TerminalException is not null)
        {
            ExceptionDispatchInfo.Capture(state.TerminalException).Throw();
        }

        lock (_stateLock)
        {
            ThrowIfFaultedCore();
        }
    }

    private void ThrowIfFaultedCore()
    {
        if (_terminalException is not null)
        {
            ExceptionDispatchInfo.Capture(_terminalException).Throw();
        }
    }

    private void CompleteStreams(Exception? exception)
    {
        StreamState[] states;
        lock (_stateLock)
        {
            if (_streams.Count == 0)
            {
                return;
            }

            states = _streams.Values.ToArray();
            _streams.Clear();
        }

        foreach (var state in states)
        {
            state.SessionClosed = true;
            if (exception is null)
            {
                state.Incoming.Writer.TryComplete();
            }
            else
            {
                state.TerminalException ??= exception;
                state.Incoming.Writer.TryComplete(exception);
            }

            state.WriteLock.Dispose();
        }
    }

    private void Fail(Exception exception)
    {
        lock (_stateLock)
        {
            _terminalException ??= exception;
        }

        _acceptedRequests.Writer.TryComplete(exception);
        CompletePendingPingAck(exception);
        CompleteStreams(exception);
        SignalSendWindowWaiter();
        _lifetimeCts.Cancel();

        try
        {
            _transportStream.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        catch
        {
        }
    }

    private void SignalSendWindowWaiter()
    {
        TaskCompletionSource<bool>? waiter;
        lock (_stateLock)
        {
            waiter = _sendWindowWaiter;
            _sendWindowWaiter = null;
        }

        waiter?.TrySetResult(true);
    }

    private static Dictionary<string, string> DecodeHeaders(byte[] headerBlock)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            if ((first & 0x80) != 0)
            {
                var index = ReadHpackInteger(headerBlock, ref offset, 7);
                if (TryResolveIndexedHeader(index, out var indexedName, out var indexedValue))
                {
                    headers[indexedName] = indexedValue;
                }

                continue;
            }

            if ((first & 0xE0) == 0x20)
            {
                _ = ReadHpackInteger(headerBlock, ref offset, 5);
                continue;
            }

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var name = nameIndex == 0
                ? ReadHpackString(headerBlock, ref offset)
                : ResolveIndexedHeaderName(nameIndex);
            var value = ReadHpackString(headerBlock, ref offset);
            if (!string.IsNullOrWhiteSpace(name))
            {
                headers[name] = value;
            }
        }

        return headers;
    }

    private static byte[] BuildResponseHeaderBlock(
        int statusCode,
        IReadOnlyDictionary<string, string> headers)
    {
        using var buffer = new MemoryStream(256);
        WriteLiteralHeaderFieldWithoutIndexing(
            buffer,
            nameIndex: 0,
            name: ":status",
            value: statusCode.ToString(CultureInfo.InvariantCulture));

        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            WriteLiteralHeaderFieldWithoutIndexing(
                buffer,
                nameIndex: 0,
                name: name.Trim().ToLowerInvariant(),
                value: value.Trim());
        }

        return buffer.ToArray();
    }

    private static byte[] BuildResponseHeaderBlock(IReadOnlyDictionary<string, string> headers)
    {
        using var buffer = new MemoryStream(128);
        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            WriteLiteralHeaderFieldWithoutIndexing(
                buffer,
                nameIndex: 0,
                name: name.Trim().ToLowerInvariant(),
                value: value.Trim());
        }

        return buffer.ToArray();
    }

    private static bool TryResolveIndexedHeader(
        int index,
        out string name,
        out string value)
    {
        switch (index)
        {
            case 1: name = ":authority"; value = string.Empty; return true;
            case 2: name = ":method"; value = "GET"; return true;
            case 3: name = ":method"; value = "POST"; return true;
            case 4: name = ":path"; value = "/"; return true;
            case 5: name = ":path"; value = "/index.html"; return true;
            case 6: name = ":scheme"; value = "http"; return true;
            case 7: name = ":scheme"; value = "https"; return true;
            case 8: name = ":status"; value = "200"; return true;
            case 9: name = ":status"; value = "204"; return true;
            case 10: name = ":status"; value = "206"; return true;
            case 11: name = ":status"; value = "304"; return true;
            case 12: name = ":status"; value = "400"; return true;
            case 13: name = ":status"; value = "404"; return true;
            case 14: name = ":status"; value = "500"; return true;
            case 15: name = "accept-charset"; value = string.Empty; return true;
            case 16: name = "accept-encoding"; value = "gzip, deflate"; return true;
            case 17: name = "accept-language"; value = string.Empty; return true;
            case 18: name = "accept-ranges"; value = string.Empty; return true;
            case 19: name = "accept"; value = string.Empty; return true;
            case 20: name = "access-control-allow-origin"; value = string.Empty; return true;
            case 21: name = "age"; value = string.Empty; return true;
            case 22: name = "allow"; value = string.Empty; return true;
            case 23: name = "authorization"; value = string.Empty; return true;
            case 24: name = "cache-control"; value = string.Empty; return true;
            case 25: name = "content-disposition"; value = string.Empty; return true;
            case 26: name = "content-encoding"; value = string.Empty; return true;
            case 27: name = "content-language"; value = string.Empty; return true;
            case 28: name = "content-length"; value = string.Empty; return true;
            case 29: name = "content-location"; value = string.Empty; return true;
            case 30: name = "content-range"; value = string.Empty; return true;
            case 31: name = "content-type"; value = string.Empty; return true;
            case 32: name = "cookie"; value = string.Empty; return true;
            case 33: name = "date"; value = string.Empty; return true;
            case 34: name = "etag"; value = string.Empty; return true;
            case 35: name = "expect"; value = string.Empty; return true;
            case 36: name = "expires"; value = string.Empty; return true;
            case 37: name = "from"; value = string.Empty; return true;
            case 38: name = "host"; value = string.Empty; return true;
            case 39: name = "if-match"; value = string.Empty; return true;
            case 40: name = "if-modified-since"; value = string.Empty; return true;
            case 41: name = "if-none-match"; value = string.Empty; return true;
            case 42: name = "if-range"; value = string.Empty; return true;
            case 43: name = "if-unmodified-since"; value = string.Empty; return true;
            case 44: name = "last-modified"; value = string.Empty; return true;
            case 45: name = "link"; value = string.Empty; return true;
            case 46: name = "location"; value = string.Empty; return true;
            case 47: name = "max-forwards"; value = string.Empty; return true;
            case 48: name = "proxy-authenticate"; value = string.Empty; return true;
            case 49: name = "proxy-authorization"; value = string.Empty; return true;
            case 50: name = "range"; value = string.Empty; return true;
            case 51: name = "referer"; value = string.Empty; return true;
            case 52: name = "refresh"; value = string.Empty; return true;
            case 53: name = "retry-after"; value = string.Empty; return true;
            case 54: name = "server"; value = string.Empty; return true;
            case 55: name = "set-cookie"; value = string.Empty; return true;
            case 56: name = "strict-transport-security"; value = string.Empty; return true;
            case 57: name = "transfer-encoding"; value = string.Empty; return true;
            case 58: name = "user-agent"; value = string.Empty; return true;
            case 59: name = "vary"; value = string.Empty; return true;
            case 60: name = "via"; value = string.Empty; return true;
            case 61: name = "www-authenticate"; value = string.Empty; return true;
            default:
                name = string.Empty;
                value = string.Empty;
                return false;
        }
    }

    private static string ResolveIndexedHeaderName(int index)
        => TryResolveIndexedHeader(index, out var name, out _)
            ? name
            : string.Empty;

    private static int ReadHpackInteger(byte[] buffer, ref int offset, int prefixBits)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
        }

        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            if (offset >= buffer.Length)
            {
                throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
            }

            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static string ReadHpackString(byte[] buffer, ref int offset)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var huffmanEncoded = (buffer[offset] & 0x80) != 0;
        var length = ReadHpackInteger(buffer, ref offset, 7);
        if (length < 0 || offset + length > buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var value = huffmanEncoded
            ? RuntimeHpackHuffman.DecodeToUtf8String(buffer.AsSpan(offset, length))
            : Encoding.UTF8.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static byte[] UnwrapHeaderBlockFragment(Http2FrameHeader frameHeader, byte[] payload)
    {
        var start = 0;
        var end = payload.Length;

        if ((frameHeader.Flags & Http2FrameFlags.Padded) == Http2FrameFlags.Padded)
        {
            if (payload.Length == 0)
            {
                throw new InvalidDataException("HTTP/2 PADDED frame payload is empty.");
            }

            var paddingLength = payload[0];
            start++;
            end -= paddingLength;
        }

        if ((frameHeader.Flags & Http2FrameFlags.Priority) == Http2FrameFlags.Priority)
        {
            start += 5;
        }

        if (start > end || end > payload.Length)
        {
            throw new InvalidDataException("HTTP/2 HEADERS frame padding is invalid.");
        }

        var result = new byte[end - start];
        if (result.Length > 0)
        {
            Buffer.BlockCopy(payload, start, result, 0, result.Length);
        }

        return result;
    }

    private static byte[] UnwrapDataPayload(Http2FrameHeader frameHeader, byte[] payload)
    {
        var start = 0;
        var end = payload.Length;

        if ((frameHeader.Flags & Http2FrameFlags.Padded) == Http2FrameFlags.Padded)
        {
            if (payload.Length == 0)
            {
                throw new InvalidDataException("HTTP/2 PADDED DATA frame payload is empty.");
            }

            var paddingLength = payload[0];
            start++;
            end -= paddingLength;
        }

        if (start > end || end > payload.Length)
        {
            throw new InvalidDataException("HTTP/2 DATA frame padding is invalid.");
        }

        var result = new byte[end - start];
        if (result.Length > 0)
        {
            Buffer.BlockCopy(payload, start, result, 0, result.Length);
        }

        return result;
    }

    private static void WriteLiteralHeaderFieldWithoutIndexing(
        MemoryStream buffer,
        int nameIndex,
        string? name,
        string value)
    {
        WriteInteger(buffer, nameIndex, prefixBits: 4, prefixMask: 0x00);
        if (nameIndex == 0)
        {
            WriteString(buffer, name ?? string.Empty);
        }

        WriteString(buffer, value);
    }

    private static void WriteInteger(MemoryStream buffer, int value, int prefixBits, byte prefixMask)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        if (value < maxPrefixValue)
        {
            buffer.WriteByte((byte)(prefixMask | value));
            return;
        }

        buffer.WriteByte((byte)(prefixMask | maxPrefixValue));
        var remaining = value - maxPrefixValue;
        while (remaining >= 128)
        {
            buffer.WriteByte((byte)((remaining % 128) + 128));
            remaining /= 128;
        }

        buffer.WriteByte((byte)remaining);
    }

    private static void WriteString(MemoryStream buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }

    private static async Task<Http2FrameHeader> ReadFrameHeaderAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = await ReadExactBytesAsync(stream, 9, cancellationToken).ConfigureAwait(false);
        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var type = header[3];
        var flags = (Http2FrameFlags)header[4];
        var streamId =
            ((header[5] & 0x7F) << 24) |
            (header[6] << 16) |
            (header[7] << 8) |
            header[8];

        return Http2FrameHeader.Create(length, type, flags, streamId);
    }

    private static async Task<Http2FrameHeader?> TryReadFrameHeaderAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        if (!await TryReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var type = header[3];
        var flags = (Http2FrameFlags)header[4];
        var streamId =
            ((header[5] & 0x7F) << 24) |
            (header[6] << 16) |
            (header[7] << 8) |
            header[8];

        return Http2FrameHeader.Create(length, type, flags, streamId);
    }

    private static async Task<byte[]> ReadExactBytesAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading an HTTP/2 frame.");
            }

            offset += read;
        }

        return buffer;
    }

    private static async ValueTask<bool> TryReadExactAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                if (offset == 0)
                {
                    return false;
                }

                throw new EndOfStreamException("Unexpected EOF while reading an HTTP/2 frame.");
            }

            offset += read;
        }

        return true;
    }

    private static ushort ReadUInt16(byte[] buffer, int offset)
        => (ushort)((buffer[offset] << 8) | buffer[offset + 1]);

    private static uint ReadUInt32(byte[] buffer, int offset)
        => ((uint)buffer[offset] << 24) |
           ((uint)buffer[offset + 1] << 16) |
           ((uint)buffer[offset + 2] << 8) |
           buffer[offset + 3];

    private static void WriteUInt16(byte[] buffer, int offset, ushort value)
    {
        buffer[offset] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 1] = (byte)(value & 0xFF);
    }

    private static void WriteUInt32(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)((value >> 24) & 0xFF);
        buffer[offset + 1] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 3] = (byte)(value & 0xFF);
    }

    internal sealed class AcceptedRequest : IAsyncDisposable
    {
        private readonly RuntimeHttp2ServerSession _session;
        private readonly StreamState _state;
        private readonly RequestBodyStream _requestBody;
        private ResponseBodyStream? _responseBody;
        private int _responseStarted;
        private int _disposed;

        internal AcceptedRequest(
            RuntimeHttp2ServerSession session,
            StreamState state,
            IReadOnlyDictionary<string, string> headers)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _state = state ?? throw new ArgumentNullException(nameof(state));
            Headers = headers ?? throw new ArgumentNullException(nameof(headers));
            Method = Headers.TryGetValue(":method", out var method) ? method : string.Empty;
            Target = Headers.TryGetValue(":path", out var path) ? path : string.Empty;
            var querySeparator = Target.IndexOf('?');
            Path = querySeparator >= 0 ? Target[..querySeparator] : Target;
            Host = Headers.TryGetValue(":authority", out var authority)
                ? authority
                : Headers.TryGetValue("host", out var host)
                    ? host
                    : string.Empty;
            _requestBody = new RequestBodyStream(_session, _state);
        }

        public string Method { get; }

        public string Target { get; }

        public string Path { get; }

        public string Host { get; }

        public IReadOnlyDictionary<string, string> Headers { get; }

        public Stream Body => _requestBody;

        public bool ResponseStarted => Volatile.Read(ref _responseStarted) != 0;

        public bool RemoteCompleted => _session.IsRemoteCompleted(_state);

        public async Task WriteHeadersOnlyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken)
        {
            if (Interlocked.CompareExchange(ref _responseStarted, 1, 0) != 0)
            {
                throw new InvalidOperationException("HTTP/2 response was already started.");
            }

            await _session.WriteResponseHeadersAsync(_state, statusCode, headers, endStream: true, cancellationToken)
                .ConfigureAwait(false);
        }

        public async Task<Stream> OpenResponseBodyAsync(
            int statusCode,
            IReadOnlyDictionary<string, string> headers,
            CancellationToken cancellationToken,
            bool completeOnDispose = true)
        {
            if (Interlocked.CompareExchange(ref _responseStarted, 1, 0) != 0)
            {
                throw new InvalidOperationException("HTTP/2 response was already started.");
            }

            await _session.WriteResponseHeadersAsync(_state, statusCode, headers, endStream: false, cancellationToken)
                .ConfigureAwait(false);
            _responseBody = new ResponseBodyStream(_session, _state, completeOnDispose);
            return _responseBody;
        }

        public async Task WriteTrailersAsync(
            IReadOnlyDictionary<string, string> trailers,
            CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref _responseStarted) == 0)
            {
                throw new InvalidOperationException("HTTP/2 response must be started before writing trailers.");
            }

            await _session.WriteResponseTrailersAsync(_state, trailers, cancellationToken).ConfigureAwait(false);
        }

        public ValueTask AbortAsync(
            uint errorCode,
            CancellationToken cancellationToken)
            => _session.ResetStreamAsync(_state, errorCode, cancellationToken);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Exception? requestException = null;
            try
            {
                await _requestBody.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                requestException = ex;
            }

            if (_responseBody is not null)
            {
                try
                {
                    await _responseBody.DisposeAsync().ConfigureAwait(false);
                }
                catch when (requestException is not null)
                {
                }
            }

            if (requestException is not null)
            {
                ExceptionDispatchInfo.Capture(requestException).Throw();
            }
        }
    }

    internal sealed class StreamState
    {
        public StreamState(int streamId, int initialSendWindow)
        {
            StreamId = streamId;
            SendWindow = initialSendWindow;
        }

        public int StreamId { get; }

        public Channel<byte[]> Incoming { get; } = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(32)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });

        public SemaphoreSlim WriteLock { get; } = new(1, 1);

        public long SendWindow { get; set; }

        public byte[]? ReadBuffer { get; set; }

        public int ReadBufferOffset { get; set; }

        public int PendingWindowUpdateBytes { get; set; }

        public bool ResponseHeadersSent { get; set; }

        public bool RemoteCompleted { get; set; }

        public bool LocalCompleted { get; set; }

        public bool SessionClosed { get; set; }

        public Exception? TerminalException { get; set; }
    }

    private sealed class RequestBodyStream : Stream
    {
        private readonly RuntimeHttp2ServerSession _session;
        private readonly StreamState _state;
        private int _disposed;

        public RequestBodyStream(RuntimeHttp2ServerSession session, StreamState state)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _state = state ?? throw new ArgumentNullException(nameof(state));
        }

        public override bool CanRead => Volatile.Read(ref _disposed) == 0;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _session.ReadAsync(_state, buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public override ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _disposed, 1);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ResponseBodyStream : Stream
    {
        private readonly RuntimeHttp2ServerSession _session;
        private readonly StreamState _state;
        private readonly bool _completeOnDispose;
        private int _disposed;

        public ResponseBodyStream(
            RuntimeHttp2ServerSession session,
            StreamState state,
            bool completeOnDispose)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _state = state ?? throw new ArgumentNullException(nameof(state));
            _completeOnDispose = completeOnDispose;
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _session.WriteAsync(_state, buffer, cancellationToken);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            if (_completeOnDispose)
            {
                await _session.CompleteResponseAsync(_state, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private readonly record struct Http2FrameHeader(int Length, byte Type, Http2FrameFlags Flags, int StreamId)
    {
        public static Http2FrameHeader Create(int length, byte type, Http2FrameFlags flags, int streamId)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            if (streamId < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(streamId));
            }

            return new Http2FrameHeader(length, type, flags, streamId);
        }
    }

    [Flags]
    private enum Http2FrameFlags : byte
    {
        None = 0,
        Ack = 0x1,
        EndStream = 0x1,
        EndHeaders = 0x4,
        Padded = 0x8,
        Priority = 0x20
    }

    private static class Http2FrameType
    {
        public const byte Data = 0x0;
        public const byte Headers = 0x1;
        public const byte RstStream = 0x3;
        public const byte Settings = 0x4;
        public const byte Ping = 0x6;
        public const byte GoAway = 0x7;
        public const byte WindowUpdate = 0x8;
        public const byte Continuation = 0x9;
    }

    private static class Http2SettingsIdentifiers
    {
        public const ushort InitialWindowSize = 0x4;
        public const ushort MaxFrameSize = 0x5;
    }
}

using System.Buffers;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class Http2TunnelSession : IAsyncDisposable
{
    private const int DefaultInitialWindowSize = 65_535;
    private const int DefaultMaxFrameSize = 16_384;
    private const int WindowUpdateThreshold = DefaultMaxFrameSize;
    private const uint RstStreamCancelErrorCode = 0x8;
    private static readonly byte[] ClientConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();
    private static readonly TimeSpan DefaultKeepAliveAckTimeout = TimeSpan.FromSeconds(20);

    private readonly Stream _transportStream;
    private readonly SemaphoreSlim _frameWriteLock = new(1, 1);
    private readonly SemaphoreSlim _openGate = new(1, 1);
    private readonly object _stateLock = new();
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly Http2TunnelSessionOptions _options;
    private readonly Action<Http2TunnelSession>? _terminatedCallback;

    private Task? _keepAliveLoopTask;
    private Task? _receiveLoopTask;
    private TaskCompletionSource<bool>? _pendingPingAckTcs;
    private byte[]? _pendingPingPayload;
    private TaskCompletionSource<bool>? _sendWindowWaiter;
    private readonly TaskCompletionSource<bool> _serverSettingsReceivedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Dictionary<int, TunnelStreamState> _streams = new();
    private long _connectionSendWindow = DefaultInitialWindowSize;
    private long _keepAlivePingSequence;
    private int _remoteInitialWindowSize = DefaultInitialWindowSize;
    private int _remoteMaxFrameSize = DefaultMaxFrameSize;
    private int _remoteMaxConcurrentStreams = int.MaxValue;
    private int _nextStreamId = 1;
    private long _lastActivityTimestampMilliseconds = Environment.TickCount64;
    private bool _serverSettingsReceived;
    private bool _receivedGoAway;
    private bool _terminationNotified;
    private Exception? _terminalException;
    private int _disposed;

    private Http2TunnelSession(
        Stream transportStream,
        Http2TunnelSessionOptions options,
        Action<Http2TunnelSession>? terminatedCallback)
    {
        _transportStream = transportStream ?? throw new ArgumentNullException(nameof(transportStream));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _terminatedCallback = terminatedCallback;
    }

    public static async ValueTask<Http2TunnelSession> CreateAsync(
        Stream transportStream,
        CancellationToken cancellationToken,
        Http2TunnelSessionOptions? options = null,
        Action<Http2TunnelSession>? terminatedCallback = null)
    {
        var session = new Http2TunnelSession(
            transportStream,
            options ?? Http2TunnelSessionOptions.Default,
            terminatedCallback);
        try
        {
            await session.InitializeAsync(cancellationToken).ConfigureAwait(false);
            return session;
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public bool CanOpenNewStream
    {
        get
        {
            lock (_stateLock)
            {
                return CanOpenNewStreamCore();
            }
        }
    }

    public bool CanReuseConnection
    {
        get
        {
            lock (_stateLock)
            {
                return IsReusableCore();
            }
        }
    }

    public async ValueTask<Stream> OpenConnectStreamAsync(
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose = false)
    {
        ArgumentNullException.ThrowIfNull(connectHeaders);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(initialPayload);

        return await OpenRequestStreamAsync(
                BuildConnectHeaderBlock(
                    connectHeaders,
                    HttpOutboundHandler.FormatAuthority(destination.Host, destination.Port)),
                initialPayload,
                waitForSuccessfulStatus: true,
                cancellationToken,
                disposeSessionOnClose)
            .ConfigureAwait(false);
    }

    public async ValueTask<Stream> OpenGrpcStreamAsync(
        string authority,
        string scheme,
        string path,
        IReadOnlyDictionary<string, string> requestHeaders,
        byte[] initialPayload,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        return await OpenHttpRequestStreamAsync(
                "POST",
                authority.Trim(),
                scheme.Trim(),
                path.Trim(),
                requestHeaders,
                initialPayload,
                waitForSuccessfulStatus: false,
                cancellationToken,
                disposeSessionOnClose,
                gracefulCloseOnDispose: true)
            .ConfigureAwait(false);
    }

    public async ValueTask<Stream> OpenGetStreamAsync(
        string authority,
        string scheme,
        string path,
        IReadOnlyDictionary<string, string> requestHeaders,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(requestHeaders);

        return await OpenHttpRequestStreamAsync(
                "GET",
                authority.Trim(),
                scheme.Trim(),
                path.Trim(),
                requestHeaders,
                Array.Empty<byte>(),
                waitForSuccessfulStatus: true,
                cancellationToken,
                disposeSessionOnClose,
                endStreamOnHeaders: true)
            .ConfigureAwait(false);
    }

    public async ValueTask<Stream> OpenHttpRequestStreamAsync(
        string method,
        string authority,
        string scheme,
        string path,
        IReadOnlyDictionary<string, string> requestHeaders,
        byte[] initialPayload,
        bool waitForSuccessfulStatus,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose = false,
        bool gracefulCloseOnDispose = false,
        bool endStreamOnHeaders = false,
        bool completeRequestAfterInitialPayload = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        return await OpenRequestStreamAsync(
                BuildHttpRequestHeaderBlock(
                    requestHeaders,
                    method.Trim(),
                    authority.Trim(),
                    scheme.Trim(),
                path.Trim()),
                initialPayload,
                waitForSuccessfulStatus,
                cancellationToken,
                disposeSessionOnClose,
                gracefulCloseOnDispose,
                endStreamOnHeaders,
                completeRequestAfterInitialPayload)
            .ConfigureAwait(false);
    }

    internal async ValueTask<PendingRequest> StartHttpRequestAsync(
        string method,
        string authority,
        string scheme,
        string path,
        IReadOnlyDictionary<string, string> requestHeaders,
        byte[] initialPayload,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose = false,
        bool endStreamOnHeaders = false,
        bool completeRequestAfterInitialPayload = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        return await StartRequestAsync(
                BuildHttpRequestHeaderBlock(
                    requestHeaders,
                    method.Trim(),
                    authority.Trim(),
                    scheme.Trim(),
                path.Trim()),
                initialPayload,
                cancellationToken,
                disposeSessionOnClose,
                gracefulCloseOnDispose: false,
                endStreamOnHeaders,
                completeRequestAfterInitialPayload)
            .ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetimeCts.Cancel();
        _serverSettingsReceivedTcs.TrySetCanceled();
        CompletePendingPingAck(new ObjectDisposedException(nameof(Http2TunnelSession)));
        SignalSendWindowWaiter();
        CompleteStreams(new ObjectDisposedException(nameof(Http2TunnelSession)));

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

        NotifyTerminated();
        _frameWriteLock.Dispose();
        _openGate.Dispose();
        _lifetimeCts.Dispose();
    }

    internal async ValueTask<int> ReadAsync(
        TunnelStreamState state,
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
        TunnelStreamState state,
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
                    EnsureActiveStateCore(state);
                    if (state.LocalClosed || state.RemoteCompleted)
                    {
                        throw new IOException("HTTP/2 stream is already closed.");
                    }

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

    internal async ValueTask CloseStreamAsync(TunnelStreamState state)
    {
        if (state.SessionClosed)
        {
            return;
        }

        bool shouldSendRst;
        bool shouldDisposeSession;
        lock (_stateLock)
        {
            if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state))
            {
                state.SessionClosed = true;
                return;
            }

            state.LocalClosed = true;
            state.SessionClosed = true;
            shouldSendRst = _terminalException is null &&
                            !_receivedGoAway &&
                            !state.ResetSent &&
                            !state.RemoteCompleted;
            _streams.Remove(state.StreamId);
            shouldDisposeSession = _receivedGoAway && _streams.Count == 0;
        }

        state.Incoming.Writer.TryComplete();
        SignalSendWindowWaiter();

        if (shouldSendRst)
        {
            try
            {
                await WriteRstStreamAsync(state.StreamId, RstStreamCancelErrorCode, CancellationToken.None)
                    .ConfigureAwait(false);
                state.ResetSent = true;
            }
            catch
            {
            }
        }

        state.WriteLock.Dispose();

        if (shouldDisposeSession)
        {
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _receiveLoopTask = ReceiveLoopAsync(_lifetimeCts.Token);
        await SendClientConnectionPrefaceAsync(cancellationToken).ConfigureAwait(false);
        if (_options.KeepAliveInterval > TimeSpan.Zero)
        {
            _keepAliveLoopTask = KeepAliveLoopAsync(_lifetimeCts.Token);
        }
    }

    private async Task<bool> EnsureReadBufferAsync(
        TunnelStreamState state,
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
        TunnelStreamState state,
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
        TunnelStreamState state,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            Task waiterTask;
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureActiveStateCore(state);
                if (!state.LocalClosed &&
                    !state.RemoteCompleted &&
                    _connectionSendWindow > 0 &&
                    state.SendWindow > 0)
                {
                    return;
                }

                if (state.LocalClosed || state.RemoteCompleted)
                {
                    throw new IOException("HTTP/2 stream is already closed.");
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
                var frameHeader = await ReadFrameHeaderAsync(_transportStream, cancellationToken).ConfigureAwait(false);
                if (!_serverSettingsReceived)
                {
                    if (frameHeader.Type != Http2FrameType.Settings || frameHeader.StreamId != 0)
                    {
                        throw new InvalidDataException("HTTP/2 server preface must start with a SETTINGS frame.");
                    }

                    _serverSettingsReceived = true;
                    _serverSettingsReceivedTcs.TrySetResult(true);
                }

                var payload = frameHeader.Length == 0
                    ? Array.Empty<byte>()
                    : await ReadExactBytesAsync(_transportStream, frameHeader.Length, cancellationToken).ConfigureAwait(false);
                RecordActivity();

                switch (frameHeader.Type)
                {
                    case Http2FrameType.Settings:
                        await HandleSettingsFrameAsync(frameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.WindowUpdate:
                        HandleWindowUpdateFrame(frameHeader, payload);
                        break;
                    case Http2FrameType.Headers:
                        await HandleHeadersFrameAsync(frameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.Data:
                        await HandleDataFrameAsync(frameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.Ping:
                        await HandlePingFrameAsync(frameHeader, payload, cancellationToken).ConfigureAwait(false);
                        break;
                    case Http2FrameType.RstStream:
                        HandleRstStreamFrame(frameHeader, payload);
                        break;
                    case Http2FrameType.GoAway:
                        HandleGoAwayFrame(payload);
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            CompleteStreams(null);
        }
        catch (EndOfStreamException)
        {
            Fail(new EndOfStreamException("Unexpected EOF while reading the HTTP/2 proxy stream."));
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

        if (payload.Length % 6 != 0)
        {
            throw new InvalidDataException("HTTP/2 SETTINGS payload length must be a multiple of 6 bytes.");
        }

        for (var offset = 0; offset < payload.Length; offset += 6)
        {
            var settingId = ReadUInt16(payload, offset);
            var settingValue = ReadUInt32(payload, offset + 2);
            switch (settingId)
            {
                case Http2SettingsIdentifiers.InitialWindowSize:
                    if (settingValue > int.MaxValue)
                    {
                        throw new InvalidDataException("HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE exceeded the supported range.");
                    }

                    ApplyInitialWindowSize((int)settingValue);
                    break;
                case Http2SettingsIdentifiers.MaxFrameSize:
                    if (settingValue is < 16_384 or > 16_777_215)
                    {
                        throw new InvalidDataException("HTTP/2 SETTINGS_MAX_FRAME_SIZE is invalid.");
                    }

                    lock (_stateLock)
                    {
                        _remoteMaxFrameSize = (int)settingValue;
                    }

                    SignalSendWindowWaiter();
                    break;
                case Http2SettingsIdentifiers.MaxConcurrentStreams:
                    lock (_stateLock)
                    {
                        _remoteMaxConcurrentStreams = settingValue > int.MaxValue
                            ? int.MaxValue
                            : (int)settingValue;
                    }

                    break;
            }
        }

        await WriteFrameAsync(
                Http2FrameType.Settings,
                Http2FrameFlags.Ack,
                streamId: 0,
                ReadOnlyMemory<byte>.Empty,
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

    private async Task HandleHeadersFrameAsync(
        Http2FrameHeader frameHeader,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var state = GetStreamState(frameHeader.StreamId);
        if (state is null)
        {
            return;
        }

        var headerBlock = await ReadHeaderBlockAsync(frameHeader, payload, cancellationToken).ConfigureAwait(false);
        if (!state.ResponseStatusCodeTcs.Task.IsCompleted)
        {
            if (!TryReadStatusCode(headerBlock, out var statusCode))
            {
                throw new InvalidDataException("HTTP/2 response is missing a valid :status pseudo header.");
            }

            if (statusCode != 200)
            {
                var exception = new IOException(
                    $"HTTP/2 request responded with non-200 status: {statusCode.ToString(CultureInfo.InvariantCulture)}.");
                state.TerminalException = exception;
                state.RemoteCompleted = true;
                state.Incoming.Writer.TryComplete(exception);
                state.ResponseStatusCodeTcs.TrySetException(exception);
                SignalSendWindowWaiter();
                return;
            }

            state.ResponseStatusCodeTcs.TrySetResult(statusCode);
        }

        if (TryReadGrpcStatus(headerBlock, out var grpcStatus))
        {
            if (grpcStatus != 0)
            {
                var exception = new IOException(
                    $"gRPC request completed with non-zero grpc-status: {grpcStatus.ToString(CultureInfo.InvariantCulture)}.");
                state.TerminalException = exception;
                state.RemoteCompleted = true;
                state.Incoming.Writer.TryComplete(exception);
                state.ResponseStatusCodeTcs.TrySetException(exception);
                SignalSendWindowWaiter();
                return;
            }

            if ((frameHeader.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream)
            {
                FinalizeRemoteCompletion(state);
            }

            return;
        }

        if ((frameHeader.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream)
        {
            FinalizeRemoteCompletion(state);
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
        var exception = new IOException(
            $"HTTP/2 stream was reset by the peer. Error code: {errorCode.ToString(CultureInfo.InvariantCulture)}.");
        state.TerminalException = exception;
        state.RemoteCompleted = true;
        state.Incoming.Writer.TryComplete(exception);
        state.ResponseStatusCodeTcs.TrySetException(exception);
        SignalSendWindowWaiter();
    }

    private void HandleGoAwayFrame(byte[] payload)
    {
        if (payload.Length < 8)
        {
            throw new InvalidDataException("HTTP/2 GOAWAY payload is too short.");
        }

        var errorCode = ReadUInt32(payload, 4);
        lock (_stateLock)
        {
            _receivedGoAway = true;
        }

        if (errorCode != 0)
        {
            throw new IOException(
                $"HTTP/2 proxy sent GOAWAY. Error code: {errorCode.ToString(CultureInfo.InvariantCulture)}.");
        }
    }

    private async Task SendClientConnectionPrefaceAsync(CancellationToken cancellationToken)
    {
        await _frameWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _transportStream
                .WriteAsync(ClientConnectionPreface.AsMemory(0, ClientConnectionPreface.Length), cancellationToken)
                .ConfigureAwait(false);

            var settingsCount = _options.InitialReceiveWindowSize > 0 ? 2 : 1;
            var settingsPayload = new byte[settingsCount * 6];
            WriteUInt16(settingsPayload, 0, Http2SettingsIdentifiers.EnablePush);
            WriteUInt32(settingsPayload, 2, 0);
            if (_options.InitialReceiveWindowSize > 0)
            {
                WriteUInt16(settingsPayload, 6, Http2SettingsIdentifiers.InitialWindowSize);
                WriteUInt32(settingsPayload, 8, checked((uint)_options.InitialReceiveWindowSize));
            }

            var frameHeader = Http2FrameHeader.Create(
                settingsPayload.Length,
                Http2FrameType.Settings,
                Http2FrameFlags.None,
                streamId: 0);
            await WriteFrameHeaderAsync(frameHeader, cancellationToken).ConfigureAwait(false);
            await _transportStream.WriteAsync(settingsPayload.AsMemory(0, settingsPayload.Length), cancellationToken).ConfigureAwait(false);
            await _transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            RecordActivity();
        }
        finally
        {
            _frameWriteLock.Release();
        }
    }

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

    private async Task WriteHeaderBlockAsync(
        int streamId,
        byte[] headerBlock,
        bool endStream,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        var isFirstFrame = true;
        var maxFrameSize = GetRemoteMaxFrameSize();

        while (offset < headerBlock.Length || (headerBlock.Length == 0 && isFirstFrame))
        {
            var chunkLength = Math.Min(maxFrameSize, headerBlock.Length - offset);
            var frameType = isFirstFrame ? Http2FrameType.Headers : Http2FrameType.Continuation;
            var flags = Http2FrameFlags.None;
            if (isFirstFrame && endStream)
            {
                flags |= Http2FrameFlags.EndStream;
            }

            if (offset + chunkLength >= headerBlock.Length)
            {
                flags |= Http2FrameFlags.EndHeaders;
            }

            var payload = chunkLength == 0
                ? ReadOnlyMemory<byte>.Empty
                : headerBlock.AsMemory(offset, chunkLength);
            await WriteFrameAsync(frameType, flags, streamId, payload, cancellationToken).ConfigureAwait(false);

            if (headerBlock.Length == 0)
            {
                break;
            }

            offset += chunkLength;
            isFirstFrame = false;
        }
    }

    private async Task SendWindowUpdatePairAsync(
        TunnelStreamState state,
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
        var header = ArrayPool<byte>.Shared.Rent(9);
        try
        {
            header[0] = (byte)((frameHeader.Length >> 16) & 0xFF);
            header[1] = (byte)((frameHeader.Length >> 8) & 0xFF);
            header[2] = (byte)(frameHeader.Length & 0xFF);
            header[3] = frameHeader.Type;
            header[4] = (byte)frameHeader.Flags;
            header[5] = (byte)((frameHeader.StreamId >> 24) & 0x7F);
            header[6] = (byte)((frameHeader.StreamId >> 16) & 0xFF);
            header[7] = (byte)((frameHeader.StreamId >> 8) & 0xFF);
            header[8] = (byte)(frameHeader.StreamId & 0xFF);

            await _transportStream.WriteAsync(header.AsMemory(0, 9), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(header);
        }
    }

    private async Task KeepAliveLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await WaitForServerSettingsAsync(cancellationToken).ConfigureAwait(false);

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

    private int GetRemoteMaxFrameSize()
    {
        lock (_stateLock)
        {
            return _remoteMaxFrameSize;
        }
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

    private TunnelStreamState? GetStreamState(int streamId)
    {
        lock (_stateLock)
        {
            return _streams.TryGetValue(streamId, out var state)
                ? state
                : null;
        }
    }

    private bool IsRemoteCompleted(TunnelStreamState state)
    {
        lock (_stateLock)
        {
            return state.RemoteCompleted;
        }
    }

    private void EnsureActiveStateCore(TunnelStreamState state)
    {
        if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
            !ReferenceEquals(tracked, state) ||
            state.SessionClosed)
        {
            throw new IOException("HTTP/2 stream is no longer active.");
        }
    }

    private Task WaitForServerSettingsAsync(CancellationToken cancellationToken)
    {
        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            if (_serverSettingsReceived)
            {
                return Task.CompletedTask;
            }
        }

        return _serverSettingsReceivedTcs.Task.WaitAsync(cancellationToken);
    }

    private void ThrowIfFaulted(TunnelStreamState state)
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
        if (exception is not null)
        {
            _serverSettingsReceivedTcs.TrySetException(exception);
        }

        TunnelStreamState[] states;
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
                continue;
            }

            state.TerminalException ??= exception;
            state.Incoming.Writer.TryComplete(exception);
            state.ResponseStatusCodeTcs.TrySetException(exception);
        }
    }

    private void Fail(Exception exception)
    {
        lock (_stateLock)
        {
            _terminalException ??= exception;
        }

        CompletePendingPingAck(exception);
        CompleteStreams(exception);
        SignalSendWindowWaiter();
        NotifyTerminated();
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

    private void NotifyTerminated()
    {
        if (_terminationNotified)
        {
            return;
        }

        _terminationNotified = true;
        _terminatedCallback?.Invoke(this);
    }

    private bool CanOpenNewStreamCore()
        => IsReusableCore() &&
           _streams.Count < _remoteMaxConcurrentStreams;

    private bool IsReusableCore()
        => Volatile.Read(ref _disposed) == 0 &&
           _terminalException is null &&
           !_receivedGoAway &&
           _nextStreamId > 0;

    private async ValueTask<Stream> OpenRequestStreamAsync(
        byte[] headerBlock,
        byte[] initialPayload,
        bool waitForSuccessfulStatus,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose,
        bool gracefulCloseOnDispose = false,
        bool endStreamOnHeaders = false,
        bool completeRequestAfterInitialPayload = false)
    {
        await using var pendingRequest = await StartRequestAsync(
                headerBlock,
                initialPayload,
                cancellationToken,
                disposeSessionOnClose,
                gracefulCloseOnDispose,
                endStreamOnHeaders,
                completeRequestAfterInitialPayload)
            .ConfigureAwait(false);

        if (waitForSuccessfulStatus)
        {
            await pendingRequest.WaitForSuccessfulStatusAsync(cancellationToken).ConfigureAwait(false);
        }

        return pendingRequest.DetachResponseStream();
    }

    private async ValueTask<PendingRequest> StartRequestAsync(
        byte[] headerBlock,
        byte[] initialPayload,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose,
        bool gracefulCloseOnDispose = false,
        bool endStreamOnHeaders = false,
        bool completeRequestAfterInitialPayload = false)
    {
        ArgumentNullException.ThrowIfNull(headerBlock);
        ArgumentNullException.ThrowIfNull(initialPayload);

        if (endStreamOnHeaders && completeRequestAfterInitialPayload && initialPayload.Length > 0)
        {
            throw new ArgumentException(
                "HTTP/2 request completion mode cannot end on headers and after the initial payload at the same time.",
                nameof(completeRequestAfterInitialPayload));
        }

        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        TunnelStreamState state;
        await _openGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                if (_receivedGoAway)
                {
                    throw new InvalidOperationException("HTTP/2 proxy session can no longer accept new streams after GOAWAY.");
                }

                if (_streams.Count >= _remoteMaxConcurrentStreams)
                {
                    throw new InvalidOperationException("HTTP/2 proxy session reached the remote concurrent stream limit.");
                }

                if (_nextStreamId <= 0)
                {
                    throw new InvalidOperationException("HTTP/2 proxy session exhausted the available client stream identifiers.");
                }

                var streamId = _nextStreamId;
                _nextStreamId = streamId == int.MaxValue ? -1 : streamId + 2;

                state = new TunnelStreamState(streamId, _remoteInitialWindowSize);
                _streams.Add(streamId, state);
            }
        }
        finally
        {
            _openGate.Release();
        }

        try
        {
            var writesCompleted = endStreamOnHeaders && initialPayload.Length == 0;
            await WriteHeaderBlockAsync(state.StreamId, headerBlock, endStream: writesCompleted, cancellationToken)
                .ConfigureAwait(false);
            if (writesCompleted)
            {
                state.LocalClosed = true;
            }

            if (initialPayload.Length > 0)
            {
                await WaitForServerSettingsAsync(cancellationToken).ConfigureAwait(false);
                await WriteAsync(state, initialPayload, cancellationToken).ConfigureAwait(false);
            }

            if (completeRequestAfterInitialPayload)
            {
                await CompleteRequestAsync(state, cancellationToken).ConfigureAwait(false);
            }

            state.HandshakeCompleted = true;
            return new PendingRequest(
                this,
                state,
                new TunnelStream(this, state, disposeSessionOnClose, gracefulCloseOnDispose, initialPayload.Length));
        }
        catch
        {
            await DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async ValueTask CompleteRequestAsync(
        TunnelStreamState state,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        var completeIncoming = false;
        var disposeSession = false;
        await state.WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            bool shouldWriteEndStream;
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureActiveStateCore(state);
                if (state.LocalClosed)
                {
                    return;
                }

                shouldWriteEndStream = !state.RemoteCompleted;
                state.LocalClosed = true;
                state.LocalCloseInProgress = shouldWriteEndStream;
                if (!shouldWriteEndStream)
                {
                    _streams.Remove(state.StreamId);
                    state.SessionClosed = true;
                    completeIncoming = true;
                    disposeSession = _receivedGoAway && _streams.Count == 0;
                }
            }

            SignalSendWindowWaiter();
            if (!shouldWriteEndStream)
            {
                return;
            }

            await WriteFrameAsync(
                    Http2FrameType.Data,
                    Http2FrameFlags.EndStream,
                    state.StreamId,
                    ReadOnlyMemory<byte>.Empty,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            var disposeWriteLock = false;
            lock (_stateLock)
            {
                if (state.LocalCloseInProgress)
                {
                    state.LocalCloseInProgress = false;
                    disposeWriteLock = state.SessionClosed;
                }
            }

            state.WriteLock.Release();
            if (disposeWriteLock)
            {
                state.WriteLock.Dispose();
            }
        }

        if (completeIncoming)
        {
            state.Incoming.Writer.TryComplete();
        }

        if (disposeSession)
        {
            await DisposeAsync().ConfigureAwait(false);
        }
    }

    private void FinalizeRemoteCompletion(TunnelStreamState state)
    {
        var fullyClosed = false;
        var disposeWriteLock = false;
        var disposeSession = false;
        lock (_stateLock)
        {
            if (!_streams.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            state.RemoteCompleted = true;
            fullyClosed = state.LocalClosed;
            if (fullyClosed)
            {
                _streams.Remove(state.StreamId);
                state.SessionClosed = true;
                disposeWriteLock = !state.LocalCloseInProgress;
                disposeSession = _receivedGoAway && _streams.Count == 0;
            }
        }

        state.Incoming.Writer.TryComplete();
        SignalSendWindowWaiter();
        if (disposeWriteLock)
        {
            state.WriteLock.Dispose();
        }

        if (disposeSession)
        {
            _ = DisposeAsync().AsTask();
        }
    }

    private static byte[] BuildConnectHeaderBlock(
        IReadOnlyDictionary<string, string> connectHeaders,
        string authority)
    {
        ArgumentNullException.ThrowIfNull(connectHeaders);

        var buffer = new MemoryStream(256);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 2, name: null, value: "CONNECT");
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 1, name: null, value: authority);

        foreach (var (name, value) in connectHeaders)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                string.IsNullOrWhiteSpace(value) ||
                string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase) ||
                IsConnectionSpecificHeader(name))
            {
                continue;
            }

            var normalizedName = name.Trim().ToLowerInvariant();
            var nameIndex = normalizedName switch
            {
                "user-agent" => 58,
                "proxy-authorization" => 49,
                _ => 0
            };
            WriteLiteralHeaderFieldWithoutIndexing(
                buffer,
                nameIndex,
                nameIndex == 0 ? normalizedName : null,
                value.Trim());
        }

        return buffer.ToArray();
    }

    private static byte[] BuildGrpcHeaderBlock(
        IReadOnlyDictionary<string, string> requestHeaders,
        string authority,
        string scheme,
        string path)
        => BuildHttpRequestHeaderBlock(requestHeaders, "POST", authority, scheme, path);

    private static byte[] BuildGetHeaderBlock(
        IReadOnlyDictionary<string, string> requestHeaders,
        string authority,
        string scheme,
        string path)
        => BuildHttpRequestHeaderBlock(requestHeaders, "GET", authority, scheme, path);

    private static byte[] BuildHttpRequestHeaderBlock(
        IReadOnlyDictionary<string, string> requestHeaders,
        string method,
        string authority,
        string scheme,
        string path)
    {
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentException.ThrowIfNullOrWhiteSpace(method);

        var buffer = new MemoryStream(256);
        var normalizedMethod = method.Trim().ToUpperInvariant();
        switch (normalizedMethod)
        {
            case "GET":
                WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 2, name: null, value: "GET");
                break;
            case "POST":
                WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 2, name: null, value: "POST");
                break;
            default:
                WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 0, name: ":method", value: normalizedMethod);
                break;
        }

        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 1, name: null, value: authority);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 6, name: null, value: scheme);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 4, name: null, value: path);

        foreach (var (name, value) in requestHeaders)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                string.IsNullOrWhiteSpace(value) ||
                string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase) ||
                IsConnectionSpecificHeader(name))
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

    private static bool IsConnectionSpecificHeader(string name)
        => name.Trim().ToLowerInvariant() switch
        {
            "connection" => true,
            "proxy-connection" => true,
            "keep-alive" => true,
            "transfer-encoding" => true,
            "upgrade" => true,
            _ => false
        };

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

    private static bool TryReadStatusCode(ReadOnlySpan<byte> headerBlock, out int statusCode)
        => TryReadIntegerHeaderValue(headerBlock, ":status", out statusCode);

    private static bool TryReadGrpcStatus(ReadOnlySpan<byte> headerBlock, out int grpcStatus)
        => TryReadIntegerHeaderValue(headerBlock, "grpc-status", out grpcStatus);

    private static bool TryReadIntegerHeaderValue(
        ReadOnlySpan<byte> headerBlock,
        string headerName,
        out int headerValue)
    {
        headerValue = 0;
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            if ((first & 0x80) != 0)
            {
                var index = ReadInteger(headerBlock, ref offset, 7);
                if (!TryResolveStaticHeader(index, out var indexedHeader))
                {
                    continue;
                }

                if (string.Equals(indexedHeader.Name, headerName, StringComparison.Ordinal) &&
                    int.TryParse(indexedHeader.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
                {
                    return true;
                }

                continue;
            }

            if ((first & 0xE0) == 0x20)
            {
                _ = ReadInteger(headerBlock, ref offset, 5);
                continue;
            }

            var prefixBits = (first & 0x40) != 0 ? 6 : 4;
            var nameIndex = ReadInteger(headerBlock, ref offset, prefixBits);
            var literalHeaderName = ResolveLiteralHeaderName(headerBlock, ref offset, nameIndex);
            var literalHeaderValue = ReadString(headerBlock, ref offset, decode: string.Equals(literalHeaderName, headerName, StringComparison.Ordinal));
            if (string.Equals(literalHeaderName, headerName, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(literalHeaderValue) &&
                int.TryParse(literalHeaderValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
            {
                return true;
            }
        }

        return false;
    }

    private static string? ResolveLiteralHeaderName(
        ReadOnlySpan<byte> headerBlock,
        ref int offset,
        int nameIndex)
    {
        if (nameIndex == 0)
        {
            return ReadString(headerBlock, ref offset, decode: true);
        }

        return TryResolveStaticHeader(nameIndex, out var header) ? header.Name : null;
    }

    private static string? ReadString(ReadOnlySpan<byte> buffer, ref int offset, bool decode)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var huffmanEncoded = (buffer[offset] & 0x80) != 0;
        var length = ReadInteger(buffer, ref offset, 7);
        if (length < 0 || offset + length > buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var valueSlice = buffer.Slice(offset, length);
        offset += length;
        if (!decode)
        {
            return null;
        }

        return huffmanEncoded
            ? RuntimeHpackHuffman.DecodeToUtf8String(valueSlice)
            : Encoding.UTF8.GetString(valueSlice);
    }

    private static int ReadInteger(ReadOnlySpan<byte> buffer, ref int offset, int prefixBits)
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

    private static bool TryResolveStaticHeader(int index, out Http2StaticHeader header)
    {
        header = default;
        if (index <= 0 || index >= Http2StaticHeaders.Length)
        {
            return false;
        }

        header = Http2StaticHeaders[index];
        return true;
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

    internal sealed class TunnelStreamState
    {
        public TunnelStreamState(int streamId, int initialSendWindow)
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

        public TaskCompletionSource<int> ResponseStatusCodeTcs { get; }
            = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public SemaphoreSlim WriteLock { get; } = new(1, 1);

        public long SendWindow { get; set; }

        public byte[]? ReadBuffer { get; set; }

        public int ReadBufferOffset { get; set; }

        public int PendingWindowUpdateBytes { get; set; }

        public bool HandshakeCompleted { get; set; }

        public bool RemoteCompleted { get; set; }

        public bool LocalClosed { get; set; }

        public bool LocalCloseInProgress { get; set; }

        public bool SessionClosed { get; set; }

        public bool ResetSent { get; set; }

        public Exception? TerminalException { get; set; }
    }

    internal sealed class PendingRequest : IAsyncDisposable
    {
        private Stream? _responseStream;

        internal PendingRequest(
            Http2TunnelSession session,
            TunnelStreamState state,
            Stream responseStream)
        {
            ArgumentNullException.ThrowIfNull(session);
            State = state ?? throw new ArgumentNullException(nameof(state));
            _responseStream = responseStream ?? throw new ArgumentNullException(nameof(responseStream));
        }

        internal TunnelStreamState State { get; }

        public async ValueTask WaitForSuccessfulStatusAsync(CancellationToken cancellationToken)
        {
            _ = await State.ResponseStatusCodeTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask DrainResponseAsync(CancellationToken cancellationToken)
        {
            await WaitForSuccessfulStatusAsync(cancellationToken).ConfigureAwait(false);
            if (_responseStream is null)
            {
                throw new ObjectDisposedException(nameof(PendingRequest));
            }

            await _responseStream.CopyToAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
        }

        public Stream DetachResponseStream()
        {
            if (_responseStream is null)
            {
                throw new ObjectDisposedException(nameof(PendingRequest));
            }

            var responseStream = _responseStream;
            _responseStream = null;
            return responseStream;
        }

        public async ValueTask DisposeAsync()
        {
            if (_responseStream is null)
            {
                return;
            }

            await _responseStream.DisposeAsync().ConfigureAwait(false);
            _responseStream = null;
        }
    }

    private sealed class TunnelStream : Stream, IInitialPayloadSentMetadata
    {
        private readonly Http2TunnelSession _session;
        private readonly TunnelStreamState _state;
        private readonly bool _disposeSessionOnClose;
        private readonly bool _gracefulCloseOnDispose;
        private int _disposed;

        public TunnelStream(
            Http2TunnelSession session,
            TunnelStreamState state,
            bool disposeSessionOnClose,
            bool gracefulCloseOnDispose,
            int sentInitialPayloadBytes)
        {
            _session = session;
            _state = state;
            _disposeSessionOnClose = disposeSessionOnClose;
            _gracefulCloseOnDispose = gracefulCloseOnDispose;
            SentInitialPayloadBytes = sentInitialPayloadBytes;
        }

        public int SentInitialPayloadBytes { get; }

        public override bool CanRead => Volatile.Read(ref _disposed) == 0;

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

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _session.ReadAsync(_state, buffer, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            return _session.WriteAsync(_state, buffer, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            if (_disposeSessionOnClose)
            {
                await _session.DisposeAsync().ConfigureAwait(false);
                return;
            }

            if (_gracefulCloseOnDispose)
            {
                if (_session.IsRemoteCompleted(_state))
                {
                    await _session.CloseStreamAsync(_state).ConfigureAwait(false);
                    return;
                }

                await _session.CompleteRequestAsync(_state, CancellationToken.None).ConfigureAwait(false);
                return;
            }

            await _session.CloseStreamAsync(_state).ConfigureAwait(false);
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
        public const ushort EnablePush = 0x2;
        public const ushort MaxConcurrentStreams = 0x3;
        public const ushort InitialWindowSize = 0x4;
        public const ushort MaxFrameSize = 0x5;
    }

    private readonly record struct Http2StaticHeader(string Name, string Value);

    private static readonly Http2StaticHeader[] Http2StaticHeaders =
    [
        default,
        new(":authority", string.Empty),
        new(":method", "GET"),
        new(":method", "POST"),
        new(":path", "/"),
        new(":path", "/index.html"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "200"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "304"),
        new(":status", "400"),
        new(":status", "404"),
        new(":status", "500"),
        new("accept-charset", string.Empty),
        new("accept-encoding", "gzip, deflate"),
        new("accept-language", string.Empty),
        new("accept-ranges", string.Empty),
        new("accept", string.Empty),
        new("access-control-allow-origin", string.Empty),
        new("age", string.Empty),
        new("allow", string.Empty),
        new("authorization", string.Empty),
        new("cache-control", string.Empty),
        new("content-disposition", string.Empty),
        new("content-encoding", string.Empty),
        new("content-language", string.Empty),
        new("content-length", string.Empty),
        new("content-location", string.Empty),
        new("content-range", string.Empty),
        new("content-type", string.Empty),
        new("cookie", string.Empty),
        new("date", string.Empty),
        new("etag", string.Empty),
        new("expect", string.Empty),
        new("expires", string.Empty),
        new("from", string.Empty),
        new("host", string.Empty),
        new("if-match", string.Empty),
        new("if-modified-since", string.Empty),
        new("if-none-match", string.Empty),
        new("if-range", string.Empty),
        new("if-unmodified-since", string.Empty),
        new("last-modified", string.Empty),
        new("link", string.Empty),
        new("location", string.Empty),
        new("max-forwards", string.Empty),
        new("proxy-authenticate", string.Empty),
        new("proxy-authorization", string.Empty),
        new("range", string.Empty),
        new("referer", string.Empty),
        new("refresh", string.Empty),
        new("retry-after", string.Empty),
        new("server", string.Empty),
        new("set-cookie", string.Empty),
        new("strict-transport-security", string.Empty),
        new("transfer-encoding", string.Empty),
        new("user-agent", string.Empty),
        new("vary", string.Empty),
        new("via", string.Empty),
        new("www-authenticate", string.Empty)
    ];
}

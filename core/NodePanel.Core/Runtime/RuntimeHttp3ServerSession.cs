#pragma warning disable CA1416
using System.Net.Quic;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeHttp3ServerSession : IAsyncDisposable
{
    private const int DefaultIncomingBufferCount = 32;

    private readonly QuicConnection _connection;
    private readonly QuicStream _controlStream;
    private readonly QuicStream _encoderStream;
    private readonly QuicStream _decoderStream;
    private readonly RuntimeQPackDecoderState _qpack = new();
    private readonly SemaphoreSlim _decoderStreamWriteLock = new(1, 1);
    private readonly CancellationTokenSource _backgroundCts = new();
    private readonly object _stateLock = new();
    private readonly object _backgroundTasksLock = new();
    private readonly Channel<AcceptedRequest> _acceptedRequests = Channel.CreateUnbounded<AcceptedRequest>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly Dictionary<long, RequestState> _requests = [];
    private readonly List<Task> _backgroundTasks = [];
    private readonly Task _acceptLoopTask;
    private Exception? _terminalException;
    private long _highestAcceptedRequestStreamId;
    private int _disposed;

    private RuntimeHttp3ServerSession(
        QuicConnection connection,
        QuicStream controlStream,
        QuicStream encoderStream,
        QuicStream decoderStream)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _controlStream = controlStream ?? throw new ArgumentNullException(nameof(controlStream));
        _encoderStream = encoderStream ?? throw new ArgumentNullException(nameof(encoderStream));
        _decoderStream = decoderStream ?? throw new ArgumentNullException(nameof(decoderStream));
        _acceptLoopTask = AcceptInboundStreamsAsync(_backgroundCts.Token);
    }

    public static async ValueTask<RuntimeHttp3ServerSession> AcceptAsync(
        QuicConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);

        QuicStream? controlStream = null;
        QuicStream? encoderStream = null;
        QuicStream? decoderStream = null;
        try
        {
            controlStream = await connection
                .OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken)
                .ConfigureAwait(false);
            encoderStream = await connection
                .OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken)
                .ConfigureAwait(false);
            decoderStream = await connection
                .OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken)
                .ConfigureAwait(false);

            await RuntimeHttp3ProtocolPrimitives
                .WriteControlStreamPreambleAsync(controlStream, cancellationToken)
                .ConfigureAwait(false);
            await RuntimeHttp3ProtocolPrimitives
                .WriteUnidirectionalStreamTypeAsync(
                    encoderStream,
                    RuntimeHttp3ProtocolPrimitives.QPackEncoderStreamType,
                    cancellationToken)
                .ConfigureAwait(false);
            await RuntimeHttp3ProtocolPrimitives
                .WriteUnidirectionalStreamTypeAsync(
                    decoderStream,
                    RuntimeHttp3ProtocolPrimitives.QPackDecoderStreamType,
                    cancellationToken)
                .ConfigureAwait(false);

            return new RuntimeHttp3ServerSession(connection, controlStream, encoderStream, decoderStream);
        }
        catch
        {
            if (decoderStream is not null)
            {
                await DisposeQuietlyAsync(decoderStream).ConfigureAwait(false);
            }

            if (encoderStream is not null)
            {
                await DisposeQuietlyAsync(encoderStream).ConfigureAwait(false);
            }

            if (controlStream is not null)
            {
                await DisposeQuietlyAsync(controlStream).ConfigureAwait(false);
            }

            await DisposeQuietlyAsync(connection).ConfigureAwait(false);
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
            ThrowIfFaulted();
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

        var disposedException = new ObjectDisposedException(nameof(RuntimeHttp3ServerSession));
        _backgroundCts.Cancel();
        await TrySendGoAwayAsync().ConfigureAwait(false);
        _qpack.Complete(disposedException);
        _acceptedRequests.Writer.TryComplete(disposedException);

        var states = DetachAllRequests(disposedException);
        foreach (var state in states)
        {
            state.Incoming.Writer.TryComplete(disposedException);
        }

        await DisposeQuietlyAsync(_controlStream).ConfigureAwait(false);
        await DisposeQuietlyAsync(_encoderStream).ConfigureAwait(false);
        await DisposeQuietlyAsync(_decoderStream).ConfigureAwait(false);
        await DisposeQuietlyAsync(_connection).ConfigureAwait(false);

        try
        {
            await _acceptLoopTask.ConfigureAwait(false);
        }
        catch
        {
        }

        foreach (var state in states)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        Task[] backgroundTasks;
        lock (_backgroundTasksLock)
        {
            backgroundTasks = _backgroundTasks.ToArray();
            _backgroundTasks.Clear();
        }

        foreach (var backgroundTask in backgroundTasks)
        {
            try
            {
                await backgroundTask.ConfigureAwait(false);
            }
            catch
            {
            }
        }

        _decoderStreamWriteLock.Dispose();
        _backgroundCts.Dispose();
    }

    internal async ValueTask<int> ReadAsync(
        RequestState state,
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

        return read;
    }

    internal async ValueTask WriteAsync(
        RequestState state,
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
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureWritableStateCore(state, requireStartedResponse: true);
            }

            await RuntimeHttp3ProtocolPrimitives
                .WriteFrameAsync(
                    state.Stream,
                    RuntimeHttp3ProtocolPrimitives.DataFrameType,
                    buffer,
                    completeWrites: false,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            state.WriteLock.Release();
        }
    }

    internal async ValueTask WriteResponseHeadersAsync(
        RequestState state,
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        bool completeResponse,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        var payload = RuntimeHttp3ProtocolPrimitives.BuildResponseHeaderBlock(statusCode, headers);

        await state.WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureWritableStateCore(state, requireStartedResponse: false);
                state.ResponseHeadersSent = true;
                if (completeResponse)
                {
                    state.ResponseCompleted = true;
                }
            }

            await RuntimeHttp3ProtocolPrimitives
                .WriteFrameAsync(
                    state.Stream,
                    RuntimeHttp3ProtocolPrimitives.HeadersFrameType,
                    payload,
                    completeWrites: completeResponse,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            state.WriteLock.Release();
        }

        if (completeResponse)
        {
            FinalizeLocalCompletion(state);
        }
    }

    internal async ValueTask CompleteResponseAsync(
        RequestState state,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        await state.WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureWritableStateCore(state, requireStartedResponse: true);
                state.ResponseCompleted = true;
            }

            await state.Stream
                .WriteAsync(ReadOnlyMemory<byte>.Empty, completeWrites: true, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            state.WriteLock.Release();
        }

        FinalizeLocalCompletion(state);
    }

    internal async ValueTask WriteResponseTrailersAsync(
        RequestState state,
        IReadOnlyDictionary<string, string> trailers,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(trailers);

        var payload = RuntimeHttp3ProtocolPrimitives.BuildResponseHeaderBlock(trailers);

        await state.WriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_stateLock)
            {
                ThrowIfFaultedCore();
                EnsureWritableStateCore(state, requireStartedResponse: true);
                state.ResponseCompleted = true;
            }

            await RuntimeHttp3ProtocolPrimitives
                .WriteFrameAsync(
                    state.Stream,
                    RuntimeHttp3ProtocolPrimitives.HeadersFrameType,
                    payload,
                    completeWrites: true,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            state.WriteLock.Release();
        }

        FinalizeLocalCompletion(state);
    }

    internal bool IsRemoteCompleted(RequestState state)
    {
        lock (_stateLock)
        {
            return _requests.TryGetValue(state.StreamId, out var tracked) &&
                   ReferenceEquals(tracked, state) &&
                   state.RemoteCompleted;
        }
    }

    internal void MarkIgnoreRequestBody(RequestState state)
        => Interlocked.Exchange(ref state.IgnoreRequestBody, 1);

    private async Task AcceptInboundStreamsAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var inboundStream = await _connection.AcceptInboundStreamAsync(cancellationToken)
                    .ConfigureAwait(false);
                TrackBackgroundTask(ProcessInboundStreamAsync(inboundStream, cancellationToken));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (QuicException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (QuicException ex)
        {
            SetFault(ex);
        }
    }

    private void TrackBackgroundTask(Task task)
    {
        ArgumentNullException.ThrowIfNull(task);

        lock (_backgroundTasksLock)
        {
            _backgroundTasks.Add(task);
        }

        _ = task.ContinueWith(
            completedTask =>
            {
                lock (_backgroundTasksLock)
                {
                    _backgroundTasks.Remove(completedTask);
                }
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private async Task ProcessInboundStreamAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
    {
        if (stream.Type == QuicStreamType.Unidirectional)
        {
            await ProcessUnidirectionalStreamAsync(stream, cancellationToken).ConfigureAwait(false);
            return;
        }

        await ProcessRequestStreamAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    private async Task ProcessUnidirectionalStreamAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
    {
        var isCriticalStream = false;
        try
        {
            var streamType = await RuntimeHttp3ProtocolPrimitives
                .ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken)
                .ConfigureAwait(false);
            if (!streamType.HasValue)
            {
                return;
            }

            if (streamType.Value == RuntimeHttp3ProtocolPrimitives.ControlStreamType)
            {
                isCriticalStream = true;
                await RuntimeHttp3ClientSession
                    .ScanControlStreamAsync(stream, static () => { }, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            if (streamType.Value == RuntimeHttp3ProtocolPrimitives.QPackEncoderStreamType)
            {
                isCriticalStream = true;
                await _qpack
                    .ProcessEncoderStreamAsync(stream, WriteQPackDecoderInstructionAsync, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            await DrainInboundStreamAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (QuicException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (Exception ex) when (isCriticalStream || ex is QuicException)
        {
            SetFault(ex);
        }
        finally
        {
            await DisposeQuietlyAsync(stream).ConfigureAwait(false);
        }
    }

    private async Task ProcessRequestStreamAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
    {
        RequestState? state = null;
        try
        {
            while (true)
            {
                var frame = await RuntimeHttp3ProtocolPrimitives
                    .ReadFrameAsync(stream, cancellationToken)
                    .ConfigureAwait(false);
                if (frame is null)
                {
                    if (state is null)
                    {
                        throw new EndOfStreamException("Unexpected EOF during HTTP/3 request headers.");
                    }

                    FinalizeRemoteCompletion(state);
                    return;
                }

                switch (frame.Value.Type)
                {
                    case RuntimeHttp3ProtocolPrimitives.HeadersFrameType:
                        if (state is not null)
                        {
                            continue;
                        }

                        var headers = await _qpack
                            .DecodeHeadersAsync(
                                frame.Value.Payload,
                                stream.Id,
                                WriteQPackDecoderInstructionAsync,
                                cancellationToken)
                            .ConfigureAwait(false);
                        state = new RequestState(stream);
                        AddRequest(state);
                        await _acceptedRequests.Writer
                            .WriteAsync(new AcceptedRequest(this, state, headers), cancellationToken)
                            .ConfigureAwait(false);
                        break;
                    case RuntimeHttp3ProtocolPrimitives.DataFrameType:
                        if (state is null)
                        {
                            throw new InvalidDataException("HTTP/3 request stream received a DATA frame before the request HEADERS frame.");
                        }

                        if (frame.Value.Payload.Length > 0 &&
                            Volatile.Read(ref state.IgnoreRequestBody) == 0)
                        {
                            await state.Incoming.Writer
                                .WriteAsync(frame.Value.Payload, cancellationToken)
                                .ConfigureAwait(false);
                        }

                        break;
                    default:
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (QuicException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (Exception ex)
        {
            if (state is null)
            {
                SetFault(ex);
            }
            else
            {
                CompleteState(state, ex);
            }
        }
        finally
        {
            if (state is null)
            {
                await DisposeQuietlyAsync(stream).ConfigureAwait(false);
            }
        }
    }

    private void AddRequest(RequestState state)
    {
        lock (_stateLock)
        {
            ThrowIfFaultedCore();
            _requests.Add(state.StreamId, state);
        }

        UpdateHighestAcceptedRequestStreamId(state.StreamId);
    }

    private void UpdateHighestAcceptedRequestStreamId(long streamId)
    {
        while (true)
        {
            var current = Interlocked.Read(ref _highestAcceptedRequestStreamId);
            if (streamId <= current)
            {
                return;
            }

            if (Interlocked.CompareExchange(ref _highestAcceptedRequestStreamId, streamId, current) == current)
            {
                return;
            }
        }
    }

    private async ValueTask<bool> EnsureReadBufferAsync(
        RequestState state,
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

    private async ValueTask WriteQPackDecoderInstructionAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (payload.IsEmpty || Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        await _decoderStreamWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            await _decoderStream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await _decoderStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (QuicException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        finally
        {
            _decoderStreamWriteLock.Release();
        }
    }

    private void FinalizeRemoteCompletion(RequestState state)
    {
        var shouldDisposeState = false;
        lock (_stateLock)
        {
            if (!_requests.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            state.RemoteCompleted = true;
            shouldDisposeState = state.ResponseCompleted;
            if (shouldDisposeState)
            {
                _requests.Remove(state.StreamId);
                state.SessionClosed = true;
            }
        }

        state.Incoming.Writer.TryComplete();
        if (shouldDisposeState)
        {
            TrackBackgroundTask(state.DisposeAsync().AsTask());
        }
    }

    private void FinalizeLocalCompletion(RequestState state)
    {
        var shouldDisposeState = false;
        lock (_stateLock)
        {
            if (!_requests.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            shouldDisposeState = state.RemoteCompleted;
            if (shouldDisposeState)
            {
                _requests.Remove(state.StreamId);
                state.SessionClosed = true;
            }
        }

        if (shouldDisposeState)
        {
            TrackBackgroundTask(state.DisposeAsync().AsTask());
        }
    }

    private void CompleteState(RequestState state, Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        var shouldDisposeState = false;
        lock (_stateLock)
        {
            if (!_requests.TryGetValue(state.StreamId, out var tracked) ||
                !ReferenceEquals(tracked, state) ||
                state.SessionClosed)
            {
                return;
            }

            _requests.Remove(state.StreamId);
            state.SessionClosed = true;
            state.RemoteCompleted = true;
            state.ResponseCompleted = true;
            state.TerminalException ??= exception;
            shouldDisposeState = true;
        }

        state.Incoming.Writer.TryComplete(exception);
        if (shouldDisposeState)
        {
            TrackBackgroundTask(state.DisposeAsync().AsTask());
        }
    }

    private RequestState[] DetachAllRequests(Exception? exception)
    {
        lock (_stateLock)
        {
            var states = _requests.Values.ToArray();
            _requests.Clear();
            foreach (var state in states)
            {
                state.SessionClosed = true;
                state.TerminalException ??= exception;
            }

            return states;
        }
    }

    private void EnsureWritableStateCore(RequestState state, bool requireStartedResponse)
    {
        if (!_requests.TryGetValue(state.StreamId, out var tracked) ||
            !ReferenceEquals(tracked, state) ||
            state.SessionClosed)
        {
            throw new IOException("HTTP/3 request stream is already closed.");
        }

        if (state.ResponseCompleted)
        {
            throw new IOException("HTTP/3 response is already complete.");
        }

        if (requireStartedResponse)
        {
            if (!state.ResponseHeadersSent)
            {
                throw new InvalidOperationException("HTTP/3 response headers must be sent before writing the response body.");
            }

            return;
        }

        if (state.ResponseHeadersSent)
        {
            throw new InvalidOperationException("HTTP/3 response was already started.");
        }
    }

    private void SetFault(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (Interlocked.CompareExchange(ref _terminalException, exception, null) is not null)
        {
            return;
        }

        _backgroundCts.Cancel();
        _qpack.Complete(exception);
        _acceptedRequests.Writer.TryComplete(exception);

        foreach (var state in DetachAllRequests(exception))
        {
            state.Incoming.Writer.TryComplete(exception);
            TrackBackgroundTask(state.DisposeAsync().AsTask());
        }
    }

    private async ValueTask TrySendGoAwayAsync()
    {
        try
        {
            var payload = BuildGoAwayPayload(Interlocked.Read(ref _highestAcceptedRequestStreamId));
            await RuntimeHttp3ProtocolPrimitives
                .WriteFrameAsync(
                    _controlStream,
                    RuntimeHttp3ProtocolPrimitives.GoAwayFrameType,
                    payload,
                    completeWrites: false,
                    CancellationToken.None)
                .ConfigureAwait(false);
            await _controlStream.FlushAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (QuicException)
        {
        }
        catch (IOException)
        {
        }
    }

    private static byte[] BuildGoAwayPayload(long streamId)
    {
        Span<byte> buffer = stackalloc byte[8];
        var offset = 0;
        RuntimeHttp3ProtocolPrimitives.WriteVariableLengthInteger(buffer, ref offset, streamId);
        return buffer[..offset].ToArray();
    }

    private void ThrowIfFaulted(RequestState state)
    {
        if (state.TerminalException is not null)
        {
            ExceptionDispatchInfo.Capture(state.TerminalException).Throw();
        }

        ThrowIfFaulted();
    }

    private void ThrowIfFaulted()
    {
        if (_terminalException is not null)
        {
            ExceptionDispatchInfo.Capture(_terminalException).Throw();
        }
    }

    private void ThrowIfFaultedCore()
    {
        if (_terminalException is not null)
        {
            ExceptionDispatchInfo.Capture(_terminalException).Throw();
        }
    }

    private static async Task DrainInboundStreamAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }
        }
    }

    private static async ValueTask DisposeQuietlyAsync(IAsyncDisposable disposable)
    {
        try
        {
            await disposable.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }
    }

    internal sealed class AcceptedRequest : IAsyncDisposable
    {
        private readonly RuntimeHttp3ServerSession _session;
        private readonly RequestState _state;
        private readonly RequestBodyStream _requestBody;
        private ResponseBodyStream? _responseBody;
        private int _responseStarted;
        private int _disposed;

        internal AcceptedRequest(
            RuntimeHttp3ServerSession session,
            RequestState state,
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
                throw new InvalidOperationException("HTTP/3 response was already started.");
            }

            await _session
                .WriteResponseHeadersAsync(_state, statusCode, headers, completeResponse: true, cancellationToken)
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
                throw new InvalidOperationException("HTTP/3 response was already started.");
            }

            await _session
                .WriteResponseHeadersAsync(_state, statusCode, headers, completeResponse: false, cancellationToken)
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
                throw new InvalidOperationException("HTTP/3 response must be started before writing trailers.");
            }

            await _session.WriteResponseTrailersAsync(_state, trailers, cancellationToken).ConfigureAwait(false);
        }

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

    internal sealed class RequestState : IAsyncDisposable
    {
        private int _disposed;

        public RequestState(QuicStream stream)
        {
            Stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        public long StreamId => Stream.Id;

        public QuicStream Stream { get; }

        public Channel<byte[]> Incoming { get; } = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(DefaultIncomingBufferCount)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });

        public SemaphoreSlim WriteLock { get; } = new(1, 1);

        public byte[]? ReadBuffer { get; set; }

        public int ReadBufferOffset { get; set; }

        public Exception? TerminalException { get; set; }

        public int IgnoreRequestBody;

        public bool ResponseHeadersSent { get; set; }

        public bool RemoteCompleted { get; set; }

        public bool ResponseCompleted { get; set; }

        public bool SessionClosed { get; set; }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await DisposeQuietlyAsync(Stream).ConfigureAwait(false);
            WriteLock.Dispose();
        }
    }

    private sealed class RequestBodyStream : Stream
    {
        private readonly RuntimeHttp3ServerSession _session;
        private readonly RequestState _state;
        private int _disposed;

        public RequestBodyStream(RuntimeHttp3ServerSession session, RequestState state)
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
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return ValueTask.CompletedTask;
            }

            _session.MarkIgnoreRequestBody(_state);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ResponseBodyStream : Stream
    {
        private readonly RuntimeHttp3ServerSession _session;
        private readonly RequestState _state;
        private readonly bool _completeOnDispose;
        private int _disposed;

        public ResponseBodyStream(
            RuntimeHttp3ServerSession session,
            RequestState state,
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

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

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
}

#pragma warning restore CA1416

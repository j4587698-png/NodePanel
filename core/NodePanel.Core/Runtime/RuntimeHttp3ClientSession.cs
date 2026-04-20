#pragma warning disable CA1416
using System.Buffers;
using System.Globalization;
using System.Net.Quic;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeHttp3ClientSession : IAsyncDisposable
{
    private const long ControlStreamType = 0x00;
    private const long QPackEncoderStreamType = 0x02;
    private const long QPackDecoderStreamType = 0x03;
    private const long DataFrameType = 0x00;
    private const long HeadersFrameType = 0x01;
    private const long SettingsFrameType = 0x04;
    private const long GoAwayFrameType = 0x07;
    private const int DefaultIncomingBufferCount = 32;

    private readonly RuntimeQuicClientConnection _connection;
    private readonly QuicStream _controlStream;
    private readonly QuicStream _encoderStream;
    private readonly QuicStream _decoderStream;
    private readonly RuntimeQPackDecoderState _qpack = new();
    private readonly SemaphoreSlim _decoderStreamWriteLock = new(1, 1);
    private readonly CancellationTokenSource _backgroundCts = new();
    private readonly object _backgroundTasksLock = new();
    private readonly List<Task> _backgroundTasks = new();
    private readonly Task _acceptLoopTask;
    private Exception? _terminalException;
    private int _acceptNewRequests = 1;
    private int _disposed;

    private RuntimeHttp3ClientSession(
        RuntimeQuicClientConnection connection,
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

    public static async ValueTask<RuntimeHttp3ClientSession> CreateAsync(
        RuntimeQuicClientConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);

        QuicStream? controlStream = null;
        QuicStream? encoderStream = null;
        QuicStream? decoderStream = null;
        try
        {
            controlStream = await connection.OpenOutboundUnidirectionalStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            encoderStream = await connection.OpenOutboundUnidirectionalStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            decoderStream = await connection.OpenOutboundUnidirectionalStreamAsync(cancellationToken)
                .ConfigureAwait(false);

            await WriteControlStreamPreambleAsync(controlStream, cancellationToken).ConfigureAwait(false);
            await WriteUnidirectionalStreamTypeAsync(
                    encoderStream,
                    QPackEncoderStreamType,
                    cancellationToken)
                .ConfigureAwait(false);
            await WriteUnidirectionalStreamTypeAsync(
                    decoderStream,
                    QPackDecoderStreamType,
                    cancellationToken)
                .ConfigureAwait(false);

            return new RuntimeHttp3ClientSession(connection, controlStream, encoderStream, decoderStream);
        }
        catch
        {
            if (decoderStream is not null)
            {
                await decoderStream.DisposeAsync().ConfigureAwait(false);
            }

            if (encoderStream is not null)
            {
                await encoderStream.DisposeAsync().ConfigureAwait(false);
            }

            if (controlStream is not null)
            {
                await controlStream.DisposeAsync().ConfigureAwait(false);
            }

            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public bool CanOpenNewRequest
        => Volatile.Read(ref _disposed) == 0 &&
           Volatile.Read(ref _acceptNewRequests) != 0 &&
           _terminalException is null;

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
        bool endRequestOnHeaders = false,
        bool completeRequestAfterInitialPayload = false)
    {
        await using var pendingRequest = await StartHttpRequestAsync(
                method,
                authority,
                scheme,
                path,
                requestHeaders,
                initialPayload,
                cancellationToken,
                disposeSessionOnClose,
                endRequestOnHeaders,
                completeRequestAfterInitialPayload)
            .ConfigureAwait(false);

        if (waitForSuccessfulStatus)
        {
            await pendingRequest.WaitForSuccessfulStatusAsync(cancellationToken).ConfigureAwait(false);
        }

        return pendingRequest.DetachResponseStream();
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
        bool endRequestOnHeaders = false,
        bool completeRequestAfterInitialPayload = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        if (endRequestOnHeaders && completeRequestAfterInitialPayload && initialPayload.Length > 0)
        {
            throw new ArgumentException(
                "HTTP/3 request completion mode cannot end on headers and after the initial payload at the same time.",
                nameof(completeRequestAfterInitialPayload));
        }

        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ThrowIfFaulted();
        if (Volatile.Read(ref _acceptNewRequests) == 0)
        {
            throw new InvalidOperationException("HTTP/3 proxy session can no longer accept new requests after GOAWAY.");
        }

        var requestStream = await _connection.OpenOutboundBidirectionalStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var headerBlock = BuildHttpRequestHeaderBlock(
                requestHeaders,
                method.Trim(),
                authority.Trim(),
                scheme.Trim(),
                path.Trim());
            var writesCompleted = endRequestOnHeaders && initialPayload.Length == 0;
            await WriteFrameAsync(
                    requestStream,
                    HeadersFrameType,
                    headerBlock,
                    completeWrites: writesCompleted,
                    cancellationToken)
                .ConfigureAwait(false);

            if (initialPayload.Length > 0)
            {
                writesCompleted = completeRequestAfterInitialPayload;
                await WriteFrameAsync(
                        requestStream,
                        DataFrameType,
                        initialPayload,
                        completeWrites: writesCompleted,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            await requestStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            return new PendingRequest(
                new Http3RequestStream(
                    this,
                    requestStream,
                    disposeSessionOnClose,
                    initialPayload.Length,
                    writesCompleted));
        }
        catch
        {
            await requestStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _acceptNewRequests, 0);
        _backgroundCts.Cancel();
        _qpack.Complete();

        try
        {
            await _controlStream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        try
        {
            await _encoderStream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        try
        {
            await _decoderStream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        await _connection.DisposeAsync().ConfigureAwait(false);

        try
        {
            await _acceptLoopTask.ConfigureAwait(false);
        }
        catch
        {
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
        var isCriticalStream = false;
        try
        {
            if (stream.Type == QuicStreamType.Unidirectional)
            {
                var streamType = await ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken).ConfigureAwait(false);
                if (!streamType.HasValue)
                {
                    return;
                }

                if (streamType.Value == ControlStreamType)
                {
                    isCriticalStream = true;
                    await ScanControlStreamAsync(
                            stream,
                            MarkNoNewRequests,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }

                if (streamType.Value == QPackEncoderStreamType)
                {
                    isCriticalStream = true;
                    await _qpack.ProcessEncoderStreamAsync(
                            stream,
                            WriteQPackDecoderInstructionAsync,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }
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
            try
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }
    }

    internal static async ValueTask ScanControlStreamAsync(
        Stream stream,
        Action onGoAway,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(onGoAway);

        while (true)
        {
            var frameType = await ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!frameType.HasValue)
            {
                return;
            }

            var frameLength = await ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!frameLength.HasValue)
            {
                throw new EndOfStreamException("Unexpected EOF while reading an HTTP/3 control frame length.");
            }

            if (frameType.Value == GoAwayFrameType)
            {
                onGoAway();
            }

            await SkipBytesAsync(stream, frameLength.Value, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async ValueTask WriteControlStreamPreambleAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
        => await RuntimeHttp3ProtocolPrimitives
            .WriteControlStreamPreambleAsync(stream, cancellationToken)
            .ConfigureAwait(false);

    private static async ValueTask WriteUnidirectionalStreamTypeAsync(
        QuicStream stream,
        long streamType,
        CancellationToken cancellationToken)
        => await RuntimeHttp3ProtocolPrimitives
            .WriteUnidirectionalStreamTypeAsync(stream, streamType, cancellationToken)
            .ConfigureAwait(false);

    private static async ValueTask WriteFrameAsync(
        QuicStream stream,
        long frameType,
        ReadOnlyMemory<byte> payload,
        bool completeWrites,
        CancellationToken cancellationToken)
        => await RuntimeHttp3ProtocolPrimitives
            .WriteFrameAsync(stream, frameType, payload, completeWrites, cancellationToken)
            .ConfigureAwait(false);

    private static async ValueTask WriteVariableLengthIntegerAsync(
        QuicStream stream,
        long value,
        CancellationToken cancellationToken)
    {
        Span<byte> buffer = stackalloc byte[8];
        var offset = 0;
        WriteVariableLengthInteger(buffer, ref offset, value);
        await stream.WriteAsync(buffer[..offset].ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private static void WriteVariableLengthInteger(
        Span<byte> buffer,
        ref int offset,
        long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < 64)
        {
            buffer[offset++] = (byte)value;
            return;
        }

        if (value < 16_384)
        {
            buffer[offset++] = (byte)(0x40 | ((value >> 8) & 0x3F));
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        if (value < 1_073_741_824L)
        {
            buffer[offset++] = (byte)(0x80 | ((value >> 24) & 0x3F));
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        if (value < 4_611_686_018_427_387_904L)
        {
            buffer[offset++] = (byte)(0xC0 | ((value >> 56) & 0x3F));
            buffer[offset++] = (byte)((value >> 48) & 0xFF);
            buffer[offset++] = (byte)((value >> 40) & 0xFF);
            buffer[offset++] = (byte)((value >> 32) & 0xFF);
            buffer[offset++] = (byte)((value >> 24) & 0xFF);
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        throw new ArgumentOutOfRangeException(
            nameof(value),
            value,
            "HTTP/3 variable-length integers must be smaller than 2^62.");
    }

    private static async ValueTask<(bool HasValue, long Value)> ReadOptionalVariableLengthIntegerAsync(
        Stream stream,
        CancellationToken cancellationToken)
        => await RuntimeHttp3ProtocolPrimitives
            .ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken)
            .ConfigureAwait(false);

    private static async ValueTask ReadExactAsync(
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
                throw new EndOfStreamException("Unexpected EOF while reading an HTTP/3 frame.");
            }

            offset += read;
        }
    }

    private static async ValueTask SkipBytesAsync(
        Stream stream,
        long length,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (length == 0)
        {
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            var remaining = length;
            while (remaining > 0)
            {
                var currentLength = (int)Math.Min(buffer.Length, remaining);
                var read = await stream.ReadAsync(buffer.AsMemory(0, currentLength), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("Unexpected EOF while skipping an HTTP/3 frame payload.");
                }

                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task DrainInboundStreamAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static byte[] BuildHttpRequestHeaderBlock(
        IReadOnlyDictionary<string, string> requestHeaders,
        string method,
        string authority,
        string scheme,
        string path)
        => RuntimeHttp3ProtocolPrimitives.BuildRequestHeaderBlock(
            requestHeaders,
            method,
            authority,
            scheme,
            path);

    private static void WriteQPackHeaderBlockPrefix(MemoryStream buffer)
    {
        buffer.WriteByte(0x00);
        buffer.WriteByte(0x00);
    }

    private void MarkNoNewRequests()
        => Interlocked.Exchange(ref _acceptNewRequests, 0);

    private void SetFault(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (Interlocked.CompareExchange(ref _terminalException, exception, null) is null)
        {
            Interlocked.Exchange(ref _acceptNewRequests, 0);
            _qpack.Complete(exception);
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

    private void ThrowIfFaulted()
    {
        if (_terminalException is not null)
        {
            ExceptionDispatchInfo.Capture(_terminalException).Throw();
        }
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

    private static void WriteLiteralFieldLineWithLiteralName(
        MemoryStream buffer,
        string name,
        string value)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        WritePrefixedInteger(buffer, nameBytes.Length, prefixBits: 3, prefixMask: 0x20);
        buffer.Write(nameBytes, 0, nameBytes.Length);
        WriteStringLiteral(buffer, value);
    }

    private static void WriteStringLiteral(MemoryStream buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WritePrefixedInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }

    private static void WritePrefixedInteger(
        MemoryStream buffer,
        int value,
        int prefixBits,
        byte prefixMask)
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

    internal sealed class PendingRequest : IAsyncDisposable
    {
        private Http3RequestStream? _requestStream;
        private Http3RequestStream? _responseStream;

        internal PendingRequest(Http3RequestStream responseStream)
        {
            _requestStream = responseStream ?? throw new ArgumentNullException(nameof(responseStream));
            _responseStream = responseStream ?? throw new ArgumentNullException(nameof(responseStream));
        }

        public async ValueTask WaitForSuccessfulStatusAsync(CancellationToken cancellationToken)
        {
            if (_responseStream is null)
            {
                throw new ObjectDisposedException(nameof(PendingRequest));
            }

            await _responseStream.WaitForSuccessfulStatusAsync(cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask<IReadOnlyDictionary<string, string>> WaitForResponseTrailersAsync(
            CancellationToken cancellationToken)
        {
            if (_requestStream is null)
            {
                throw new ObjectDisposedException(nameof(PendingRequest));
            }

            return await _requestStream.WaitForResponseTrailersAsync(cancellationToken).ConfigureAwait(false);
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
            if (_requestStream is null)
            {
                return;
            }

            var responseStream = _responseStream;
            _requestStream = null;
            _responseStream = null;
            if (responseStream is not null)
            {
                await responseStream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    internal sealed class Http3RequestStream : Stream, IInitialPayloadSentMetadata
    {
        private static readonly IReadOnlyDictionary<string, string> EmptyResponseTrailers =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private readonly RuntimeHttp3ClientSession _session;
        private readonly QuicStream _stream;
        private readonly bool _disposeSessionOnClose;
        private readonly Channel<byte[]> _incoming = Channel.CreateBounded<byte[]>(
            new BoundedChannelOptions(DefaultIncomingBufferCount)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait
            });
        private readonly CancellationTokenSource _responseAbortCts = new();
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly TaskCompletionSource<int> _statusCodeTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<IReadOnlyDictionary<string, string>> _responseTrailersTcs =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Task _responseLoopTask;
        private byte[]? _readBuffer;
        private int _readBufferOffset;
        private Exception? _terminalException;
        private bool _responseStarted;
        private bool _responseTrailersReceived;
        private bool _writesCompleted;
        private int _disposed;

        public Http3RequestStream(
            RuntimeHttp3ClientSession session,
            QuicStream stream,
            bool disposeSessionOnClose,
            int sentInitialPayloadBytes,
            bool writesCompleted)
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _disposeSessionOnClose = disposeSessionOnClose;
            SentInitialPayloadBytes = sentInitialPayloadBytes;
            _writesCompleted = writesCompleted;
            _responseLoopTask = ProcessResponseAsync();
        }

        public int SentInitialPayloadBytes { get; }

        public override bool CanRead => Volatile.Read(ref _disposed) == 0 && _stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0 && _stream.CanWrite && !_writesCompleted;

        public override bool CanTimeout => _stream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int ReadTimeout
        {
            get => _stream.ReadTimeout;
            set => _stream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _stream.WriteTimeout;
            set => _stream.WriteTimeout = value;
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfFaulted();
            return _stream.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (buffer.Length == 0)
            {
                return 0;
            }

            if (!await EnsureReadBufferAsync(cancellationToken).ConfigureAwait(false))
            {
                ThrowIfFaulted();
                return 0;
            }

            var available = _readBuffer!.Length - _readBufferOffset;
            var read = Math.Min(buffer.Length, available);
            _readBuffer.AsMemory(_readBufferOffset, read).CopyTo(buffer);
            _readBufferOffset += read;
            if (_readBufferOffset >= _readBuffer.Length)
            {
                _readBuffer = null;
                _readBufferOffset = 0;
            }

            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfFaulted();
            if (buffer.Length == 0)
            {
                return;
            }

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfFaulted();
                if (_writesCompleted)
                {
                    throw new IOException("HTTP/3 request body is already closed.");
                }

                await WriteFrameAsync(
                        _stream,
                        DataFrameType,
                        buffer,
                        completeWrites: false,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public async ValueTask WaitForSuccessfulStatusAsync(CancellationToken cancellationToken)
            => _ = await _statusCodeTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

        public async ValueTask<IReadOnlyDictionary<string, string>> WaitForResponseTrailersAsync(
            CancellationToken cancellationToken)
            => await _responseTrailersTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);

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

            _responseAbortCts.Cancel();

            try
            {
                await CompleteWritesAsync().ConfigureAwait(false);
            }
            catch
            {
            }

            try
            {
                if (_disposeSessionOnClose)
                {
                    await _session.DisposeAsync().ConfigureAwait(false);
                }
                else
                {
                    await _stream.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                _incoming.Writer.TryComplete();
                _writeLock.Dispose();
                _responseAbortCts.Dispose();
            }
        }

        private async ValueTask<bool> EnsureReadBufferAsync(CancellationToken cancellationToken)
        {
            if (_readBuffer is not null && _readBufferOffset < _readBuffer.Length)
            {
                return true;
            }

            try
            {
                _readBuffer = await _incoming.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                _readBufferOffset = 0;
                return true;
            }
            catch (ChannelClosedException)
            {
                _readBuffer = null;
                _readBufferOffset = 0;
                return false;
            }
        }

        private async ValueTask CompleteWritesAsync()
        {
            await _writeLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                if (_writesCompleted)
                {
                    return;
                }

                _writesCompleted = true;
                await _stream.WriteAsync(ReadOnlyMemory<byte>.Empty, completeWrites: true, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        private void ThrowIfFaulted()
        {
            if (_terminalException is not null)
            {
                ExceptionDispatchInfo.Capture(_terminalException).Throw();
            }
        }

        private async Task ProcessResponseAsync()
        {
            try
            {
                while (true)
                {
                    var frame = await ReadFrameAsync(_stream, _responseAbortCts.Token).ConfigureAwait(false);
                    if (frame is null)
                    {
                        if (!_responseStarted)
                        {
                            throw new EndOfStreamException("Unexpected EOF during SplitHTTP HTTP/3 response headers.");
                        }

                        TryCompleteResponseTrailers();
                        _incoming.Writer.TryComplete();
                        return;
                    }

                    switch (frame.Value.Type)
                    {
                        case HeadersFrameType:
                            if (_responseStarted)
                            {
                                if (_responseTrailersReceived)
                                {
                                    throw new InvalidDataException("SplitHTTP HTTP/3 received multiple trailing HEADERS blocks.");
                                }

                                var trailers = await _session._qpack
                                    .DecodeHeadersAsync(
                                        frame.Value.Payload,
                                        _stream.Id,
                                        _session.WriteQPackDecoderInstructionAsync,
                                        _responseAbortCts.Token)
                                    .ConfigureAwait(false);
                                _responseTrailersReceived = true;
                                TryCompleteResponseTrailers(trailers);
                                break;
                            }

                            var statusCode = await ReadStatusCodeAsync(
                                    frame.Value.Payload,
                                    _responseAbortCts.Token)
                                .ConfigureAwait(false);
                            if (statusCode is >= 100 and < 200)
                            {
                                continue;
                            }

                            if (statusCode != 200)
                            {
                                throw new IOException(
                                    $"SplitHTTP HTTP/3 responded with non-200 status: {statusCode.ToString(CultureInfo.InvariantCulture)}.");
                            }

                            _responseStarted = true;
                            _statusCodeTcs.TrySetResult(statusCode);
                            break;
                        case DataFrameType:
                            if (!_responseStarted)
                            {
                                throw new InvalidDataException("SplitHTTP HTTP/3 received a DATA frame before the response HEADERS frame.");
                            }

                            if (_responseTrailersReceived)
                            {
                                throw new InvalidDataException("SplitHTTP HTTP/3 received a DATA frame after response trailers.");
                            }

                            if (frame.Value.Payload.Length > 0)
                            {
                                await _incoming.Writer.WriteAsync(frame.Value.Payload, _responseAbortCts.Token)
                                    .ConfigureAwait(false);
                            }

                            break;
                        default:
                            break;
                    }
                }
            }
            catch (OperationCanceledException) when (Volatile.Read(ref _disposed) != 0)
            {
                _responseTrailersTcs.TrySetCanceled();
                _incoming.Writer.TryComplete();
                _statusCodeTcs.TrySetCanceled();
            }
            catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
            {
                _responseTrailersTcs.TrySetCanceled();
                _incoming.Writer.TryComplete();
                _statusCodeTcs.TrySetCanceled();
            }
            catch (QuicException) when (Volatile.Read(ref _disposed) != 0)
            {
                _responseTrailersTcs.TrySetCanceled();
                _incoming.Writer.TryComplete();
                _statusCodeTcs.TrySetCanceled();
            }
            catch (Exception ex)
            {
                _terminalException = ex;
                _responseTrailersTcs.TrySetException(ex);
                _incoming.Writer.TryComplete(ex);
                _statusCodeTcs.TrySetException(ex);
            }
        }

        private void TryCompleteResponseTrailers(IReadOnlyDictionary<string, string>? trailers = null)
            => _responseTrailersTcs.TrySetResult(trailers ?? EmptyResponseTrailers);

        private static async ValueTask<Http3Frame?> ReadFrameAsync(
            Stream stream,
            CancellationToken cancellationToken)
        {
            var frame = await RuntimeHttp3ProtocolPrimitives
                .ReadFrameAsync(stream, cancellationToken)
                .ConfigureAwait(false);
            return frame is null
                ? null
                : new Http3Frame(frame.Value.Type, frame.Value.Payload);
        }

        private ValueTask<int> ReadStatusCodeAsync(
            ReadOnlyMemory<byte> headerBlock,
            CancellationToken cancellationToken)
            => _session._qpack.DecodeStatusCodeAsync(
                headerBlock,
                _stream.Id,
                _session.WriteQPackDecoderInstructionAsync,
                cancellationToken);

        internal static int DecodeStatusCodeForHeaderBlock(ReadOnlyMemory<byte> headerBlock)
            => RuntimeQPackDecoderState.DecodeStatusCode(headerBlock);

        private readonly record struct Http3Frame(long Type, byte[] Payload);
    }
}

#pragma warning restore CA1416

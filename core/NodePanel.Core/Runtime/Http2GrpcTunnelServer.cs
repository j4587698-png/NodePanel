using System.Buffers.Binary;
using System.Globalization;
using System.Runtime.ExceptionServices;

namespace NodePanel.Core.Runtime;

internal static class Http2GrpcTunnelServer
{
    private const string GrpcContentTypePrefix = "application/grpc";
    private static readonly IReadOnlyDictionary<string, string> GrpcResponseHeaders
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["content-type"] = "application/grpc"
        };

    public static async ValueTask<AcceptedGrpcTunnelConnection> AcceptAsync(
        Stream transportStream,
        RuntimeGrpcTransportOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentNullException.ThrowIfNull(options);

        var session = await RuntimeHttp2ServerSession
            .AcceptAsync(
                transportStream,
                cancellationToken,
                CreateSessionOptions(options))
            .ConfigureAwait(false);
        try
        {
            var accepted = await AcceptRequestAsync(
                    session,
                    options,
                    cancellationToken,
                    disposeSessionOnClose: true)
                .ConfigureAwait(false);
            return accepted ?? throw new EndOfStreamException("HTTP/2 gRPC transport closed before the first request stream was accepted.");
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public static async Task ServeAsync(
        Stream transportStream,
        RuntimeGrpcTransportOptions options,
        Func<Stream, CancellationToken, Task> handler,
        Action<Exception>? onHandlerError,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(handler);

        await using var session = await RuntimeHttp2ServerSession
            .AcceptAsync(
                transportStream,
                cancellationToken,
                CreateSessionOptions(options))
            .ConfigureAwait(false);

        var activeTasks = new List<Task>();
        var activeTasksLock = new object();

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                AcceptedGrpcTunnelConnection? acceptedConnection;
                try
                {
                    acceptedConnection = await AcceptRequestAsync(
                            session,
                            options,
                            cancellationToken,
                            disposeSessionOnClose: false)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    InboundServerRuntimeSupport.InvokeSafely(onHandlerError, ex);
                    throw;
                }

                if (acceptedConnection is null)
                {
                    break;
                }

                var task = HandleAcceptedConnectionAsync(
                    acceptedConnection,
                    handler,
                    onHandlerError,
                    cancellationToken);
                lock (activeTasksLock)
                {
                    activeTasks.Add(task);
                }

                _ = task.ContinueWith(
                    static (completedTask, state) =>
                    {
                        var tuple = ((List<Task> Tasks, object SyncRoot))state!;
                        lock (tuple.SyncRoot)
                        {
                            tuple.Tasks.Remove(completedTask);
                        }
                    },
                    (activeTasks, activeTasksLock),
                    CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }
        }
        finally
        {
            Task[] pendingTasks;
            lock (activeTasksLock)
            {
                pendingTasks = activeTasks.ToArray();
            }

            if (pendingTasks.Length > 0)
            {
                await Task.WhenAll(pendingTasks).ConfigureAwait(false);
            }
        }
    }

    private static async ValueTask<AcceptedGrpcTunnelConnection?> AcceptRequestAsync(
        RuntimeHttp2ServerSession session,
        RuntimeGrpcTransportOptions options,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose)
    {
        var request = await session.AcceptRequestAsync(cancellationToken).ConfigureAwait(false);
        if (request is null)
        {
            return null;
        }

        try
        {
            var requestPath = ValidateRequestHeaders(request.Headers, options);
            var responseBody = await request.OpenResponseBodyAsync(
                    200,
                    GrpcResponseHeaders,
                    cancellationToken,
                    completeOnDispose: false)
                .ConfigureAwait(false);

            return new AcceptedGrpcTunnelConnection
            {
                Stream = new GrpcTunnelStream(
                    new GrpcTransportStream(request, responseBody),
                    requestPath.MultiMode),
                RequestHeaders = request.Headers,
                MethodPath = requestPath.MethodPath,
                MultiMode = requestPath.MultiMode,
                SessionLease = disposeSessionOnClose ? session : null
            };
        }
        catch
        {
            await request.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task HandleAcceptedConnectionAsync(
        AcceptedGrpcTunnelConnection acceptedConnection,
        Func<Stream, CancellationToken, Task> handler,
        Action<Exception>? onHandlerError,
        CancellationToken cancellationToken)
    {
        await using var connection = acceptedConnection;
        try
        {
            await handler(connection.Stream, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            if (acceptedConnection.Stream is GrpcTunnelStream grpcTunnelStream)
            {
                grpcTunnelStream.MarkFailed(ex);
            }

            InboundServerRuntimeSupport.InvokeSafely(onHandlerError, ex);
        }
    }

    private static RuntimeHttp2ServerSessionOptions CreateSessionOptions(RuntimeGrpcTransportOptions options)
    {
        var initialReceiveWindowSize = Math.Max(0, options.InitialWindowSize);
        var keepAliveInterval = options.IdleTimeoutSeconds > 0
            ? TimeSpan.FromSeconds(options.IdleTimeoutSeconds)
            : TimeSpan.Zero;
        var keepAliveTimeout = options.HealthCheckTimeoutSeconds > 0
            ? TimeSpan.FromSeconds(options.HealthCheckTimeoutSeconds)
            : TimeSpan.Zero;

        if (initialReceiveWindowSize == 0 &&
            keepAliveInterval == TimeSpan.Zero &&
            keepAliveTimeout == TimeSpan.Zero &&
            !options.PermitWithoutStream)
        {
            return RuntimeHttp2ServerSessionOptions.Default;
        }

        return new RuntimeHttp2ServerSessionOptions
        {
            InitialReceiveWindowSize = initialReceiveWindowSize,
            KeepAliveInterval = keepAliveInterval,
            KeepAliveTimeout = keepAliveTimeout,
            PermitKeepAliveWithoutStreams = options.PermitWithoutStream
        };
    }

    private static IReadOnlyDictionary<string, string> CreateGrpcTrailers(int grpcStatus)
        => new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["grpc-status"] = grpcStatus.ToString(CultureInfo.InvariantCulture)
        };

    internal sealed record AcceptedGrpcTunnelConnection : IAsyncDisposable
    {
        public required Stream Stream { get; init; }

        public IReadOnlyDictionary<string, string> RequestHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string MethodPath { get; init; } = string.Empty;

        public bool MultiMode { get; init; }

        public IAsyncDisposable? SessionLease { get; init; }

        public async ValueTask DisposeAsync()
        {
            Exception? streamException = null;
            try
            {
                await Stream.DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                streamException = ex;
            }

            if (SessionLease is not null)
            {
                try
                {
                    await SessionLease.DisposeAsync().ConfigureAwait(false);
                }
                catch when (streamException is not null)
                {
                }
            }

            if (streamException is not null)
            {
                ExceptionDispatchInfo.Capture(streamException).Throw();
            }
        }
    }

    private sealed class GrpcTransportStream : Stream
    {
        private readonly RuntimeHttp2ServerSession.AcceptedRequest _request;
        private readonly Stream _requestBody;
        private readonly Stream _responseBody;
        private int _responseGrpcStatus = GrpcStatusCodes.Ok;
        private int _disposed;

        public GrpcTransportStream(
            RuntimeHttp2ServerSession.AcceptedRequest request,
            Stream responseBody)
        {
            _request = request ?? throw new ArgumentNullException(nameof(request));
            _requestBody = request.Body;
            _responseBody = responseBody ?? throw new ArgumentNullException(nameof(responseBody));
        }

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
            return _requestBody.ReadAsync(buffer, cancellationToken);
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
            return _responseBody.WriteAsync(buffer, cancellationToken);
        }

        internal void MarkFailed(Exception exception)
        {
            ArgumentNullException.ThrowIfNull(exception);
            if (Volatile.Read(ref _disposed) != 0)
            {
                return;
            }

            Interlocked.CompareExchange(ref _responseGrpcStatus, GrpcStatusCodes.Internal, GrpcStatusCodes.Ok);
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

            try
            {
                try
                {
                    await _request.WriteTrailersAsync(
                            CreateGrpcTrailers(Volatile.Read(ref _responseGrpcStatus)),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                }
            }
            finally
            {
                await _request.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private sealed class GrpcTunnelStream : Stream
    {
        private readonly GrpcTransportStream _innerStream;
        private readonly bool _multiMode;
        private byte[]? _readBuffer;
        private int _readBufferOffset;
        private int _disposed;

        public GrpcTunnelStream(GrpcTransportStream innerStream, bool multiMode)
        {
            _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
            _multiMode = multiMode;
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
            => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (buffer.Length == 0)
            {
                return 0;
            }

            while (true)
            {
                if (_readBuffer is not null && _readBufferOffset < _readBuffer.Length)
                {
                    var available = _readBuffer.Length - _readBufferOffset;
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

                if (!await TryReadNextMessageAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0;
                }
            }
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (buffer.Length == 0)
            {
                return;
            }

            var messagePayload = _multiMode
                ? EncodeMultiHunk(buffer.Span)
                : EncodeHunk(buffer.Span);
            var frameHeader = new byte[5];
            BinaryPrimitives.WriteUInt32BigEndian(frameHeader.AsSpan(1, 4), (uint)messagePayload.Length);

            await _innerStream.WriteAsync(frameHeader.AsMemory(0, frameHeader.Length), cancellationToken).ConfigureAwait(false);
            await _innerStream.WriteAsync(messagePayload.AsMemory(0, messagePayload.Length), cancellationToken).ConfigureAwait(false);
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

            await _innerStream.DisposeAsync().ConfigureAwait(false);
        }

        internal void MarkFailed(Exception exception)
            => _innerStream.MarkFailed(exception);

        private async ValueTask<bool> TryReadNextMessageAsync(CancellationToken cancellationToken)
        {
            var messageHeader = new byte[5];
            if (!await TryReadExactAsync(_innerStream, messageHeader, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            if (messageHeader[0] != 0)
            {
                throw new NotSupportedException("Compressed gRPC tunnel messages are not supported.");
            }

            var messageLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(messageHeader.AsSpan(1, 4)));
            var messagePayload = new byte[messageLength];
            if (messageLength > 0 &&
                !await TryReadExactAsync(_innerStream, messagePayload, cancellationToken).ConfigureAwait(false))
            {
                throw new EndOfStreamException("Unexpected EOF while reading a gRPC tunnel message.");
            }

            _readBuffer = _multiMode
                ? DecodeMultiHunk(messagePayload)
                : DecodeHunk(messagePayload);
            _readBufferOffset = 0;
            return _readBuffer.Length > 0 || await TryReadNextMessageAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private readonly record struct AcceptedRequestPath(
        string MethodPath,
        bool MultiMode);

    private static AcceptedRequestPath ValidateRequestHeaders(
        IReadOnlyDictionary<string, string> headers,
        RuntimeGrpcTransportOptions options)
    {
        if (!headers.TryGetValue(":method", out var method) ||
            !string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("HTTP/2 gRPC request is missing a valid POST method.");
        }

        if (!headers.TryGetValue(":path", out var methodPath) ||
            !options.TryResolveRequestPath(methodPath, out var normalizedMethodPath, out var multiMode))
        {
            throw new InvalidDataException(
                $"HTTP/2 gRPC request path '{methodPath ?? string.Empty}' does not match '{options.TunMethodPath}' or '{options.TunMultiMethodPath}'.");
        }

        if (!headers.TryGetValue("content-type", out var contentType) ||
            !IsGrpcContentType(contentType))
        {
            throw new InvalidDataException("HTTP/2 gRPC request is missing a valid 'content-type: application/grpc' header.");
        }

        return new AcceptedRequestPath(normalizedMethodPath, multiMode);
    }

    private static bool IsGrpcContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return false;
        }

        var value = contentType.Trim();
        if (!value.StartsWith(GrpcContentTypePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (value.Length == GrpcContentTypePrefix.Length)
        {
            return true;
        }

        var next = value[GrpcContentTypePrefix.Length];
        return next is '+' or ';';
    }

    private static byte[] EncodeHunk(ReadOnlySpan<byte> payload)
    {
        using var buffer = new MemoryStream(payload.Length + 8);
        WriteVarint(buffer, 0x0A);
        WriteVarint(buffer, payload.Length);
        if (payload.Length > 0)
        {
            buffer.Write(payload);
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeMultiHunk(ReadOnlySpan<byte> payload)
    {
        using var buffer = new MemoryStream(payload.Length + 8);
        WriteVarint(buffer, 0x0A);
        WriteVarint(buffer, payload.Length);
        if (payload.Length > 0)
        {
            buffer.Write(payload);
        }

        return buffer.ToArray();
    }

    private static byte[] DecodeHunk(ReadOnlySpan<byte> payload)
    {
        var offset = 0;
        while (offset < payload.Length)
        {
            var fieldKey = ReadVarint(payload, ref offset);
            var fieldNumber = fieldKey >> 3;
            var wireType = (int)(fieldKey & 0x07);
            if (fieldNumber == 1 && wireType == 2)
            {
                var length = checked((int)ReadVarint(payload, ref offset));
                EnsureAvailable(payload, offset, length);
                return payload.Slice(offset, length).ToArray();
            }

            SkipField(payload, ref offset, wireType);
        }

        return Array.Empty<byte>();
    }

    private static byte[] DecodeMultiHunk(ReadOnlySpan<byte> payload)
    {
        using var buffer = new MemoryStream(payload.Length);
        var offset = 0;
        while (offset < payload.Length)
        {
            var fieldKey = ReadVarint(payload, ref offset);
            var fieldNumber = fieldKey >> 3;
            var wireType = (int)(fieldKey & 0x07);
            if (fieldNumber == 1 && wireType == 2)
            {
                var length = checked((int)ReadVarint(payload, ref offset));
                EnsureAvailable(payload, offset, length);
                buffer.Write(payload.Slice(offset, length));
                offset += length;
                continue;
            }

            SkipField(payload, ref offset, wireType);
        }

        return buffer.ToArray();
    }

    private static void SkipField(ReadOnlySpan<byte> payload, ref int offset, int wireType)
    {
        switch (wireType)
        {
            case 0:
                _ = ReadVarint(payload, ref offset);
                return;
            case 1:
                EnsureAvailable(payload, offset, 8);
                offset += 8;
                return;
            case 2:
                var length = checked((int)ReadVarint(payload, ref offset));
                EnsureAvailable(payload, offset, length);
                offset += length;
                return;
            case 5:
                EnsureAvailable(payload, offset, 4);
                offset += 4;
                return;
            default:
                throw new InvalidDataException($"Unsupported gRPC tunnel protobuf wire type: {wireType}.");
        }
    }

    private static void EnsureAvailable(ReadOnlySpan<byte> payload, int offset, int length)
    {
        if (length < 0 || offset < 0 || offset + length > payload.Length)
        {
            throw new InvalidDataException("gRPC tunnel protobuf payload exceeded the available bytes.");
        }
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> payload, ref int offset)
    {
        ulong value = 0;
        var shift = 0;
        while (offset < payload.Length)
        {
            var next = payload[offset++];
            value |= ((ulong)(next & 0x7F)) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
            if (shift > 63)
            {
                break;
            }
        }

        throw new InvalidDataException("gRPC tunnel protobuf varint exceeded the available bytes.");
    }

    private static void WriteVarint(Stream stream, int value)
    {
        uint remaining = checked((uint)value);
        while (remaining >= 0x80)
        {
            stream.WriteByte((byte)((remaining & 0x7F) | 0x80));
            remaining >>= 7;
        }

        stream.WriteByte((byte)remaining);
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

                throw new EndOfStreamException("Unexpected EOF while reading a gRPC tunnel message.");
            }

            offset += read;
        }

        return true;
    }

    private static class GrpcStatusCodes
    {
        public const int Ok = 0;
        public const int Internal = 13;
    }
}

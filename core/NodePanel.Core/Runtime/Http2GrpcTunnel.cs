using System.Buffers.Binary;

namespace NodePanel.Core.Runtime;

internal static class Http2GrpcTunnel
{
    public static async ValueTask<Stream> OpenAsync(
        Stream transportStream,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentNullException.ThrowIfNull(options);

        var session = await Http2TunnelSession
            .CreateAsync(
                transportStream,
                cancellationToken,
                CreateSessionOptions(options))
            .ConfigureAwait(false);
        try
        {
            return await OpenAsync(
                    session,
                    stack,
                    options,
                    cancellationToken,
                    disposeSessionOnClose: true)
                .ConfigureAwait(false);
        }
        catch
        {
            await session.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal static async ValueTask<Stream> OpenAsync(
        Http2TunnelSession session,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken,
        bool disposeSessionOnClose)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(options);

        var stream = await session.OpenGrpcStreamAsync(
                ResolveAuthority(stack, options),
                ResolveScheme(stack),
                RuntimeGrpcUtilities.ResolveMethodPath(options.GrpcServiceName, options.GrpcMultiMode),
                CreateRequestHeaders(options),
                Array.Empty<byte>(),
                cancellationToken,
                disposeSessionOnClose)
            .ConfigureAwait(false);
        return new GrpcTunnelStream(stream, options.GrpcMultiMode);
    }

    internal static IReadOnlyDictionary<string, string> CreateRequestHeaders(IRuntimeInternetOptions options)
        => new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["content-type"] = "application/grpc",
            ["te"] = "trailers",
            ["user-agent"] = RuntimeInternetHttpUtilities.BuildGrpcUserAgentHeader(options)
        };

    internal static Http2TunnelSessionOptions CreateSessionOptions(IRuntimeInternetOptions options)
    {
        var initialReceiveWindowSize = Math.Max(0, options.GrpcInitialWindowSize);
        var keepAliveInterval = options.GrpcIdleTimeoutSeconds > 0
            ? TimeSpan.FromSeconds(options.GrpcIdleTimeoutSeconds)
            : TimeSpan.Zero;
        var keepAliveTimeout = options.GrpcHealthCheckTimeoutSeconds > 0
            ? TimeSpan.FromSeconds(options.GrpcHealthCheckTimeoutSeconds)
            : TimeSpan.Zero;

        if (initialReceiveWindowSize == 0 &&
            keepAliveInterval == TimeSpan.Zero &&
            keepAliveTimeout == TimeSpan.Zero &&
            !options.GrpcPermitWithoutStream)
        {
            return Http2TunnelSessionOptions.Default;
        }

        return new Http2TunnelSessionOptions
        {
            InitialReceiveWindowSize = initialReceiveWindowSize,
            KeepAliveInterval = keepAliveInterval,
            KeepAliveTimeout = keepAliveTimeout,
            PermitKeepAliveWithoutStreams = options.GrpcPermitWithoutStream
        };
    }

    internal static string ResolveAuthority(RuntimeInternetStack stack, IRuntimeInternetOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.GrpcAuthority))
        {
            return options.GrpcAuthority.Trim();
        }

        var normalizedSecurity = RuntimeInternetSecurityTypes.Normalize(stack.SecurityType);
        if (string.Equals(normalizedSecurity, RuntimeInternetSecurityTypes.Tls, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(options.ServerName))
        {
            return options.ServerName.Trim();
        }

        return options.ServerHost.Trim();
    }

    internal static string ResolveScheme(RuntimeInternetStack stack)
        => RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(stack.SecurityType)
            ? "https"
            : "http";

    private sealed class GrpcTunnelStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly bool _multiMode;
        private byte[]? _readBuffer;
        private int _readBufferOffset;
        private int _disposed;

        public GrpcTunnelStream(Stream innerStream, bool multiMode)
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

                    throw new EndOfStreamException("Unexpected EOF while reading a gRPC tunnel frame.");
                }

                offset += read;
            }

            return true;
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
    }
}

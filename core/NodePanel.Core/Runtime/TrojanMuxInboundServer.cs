using System.Net.Sockets;
using System.Threading.Channels;
using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public sealed class TrojanMuxInboundServer
{
    private readonly IDispatcher _dispatcher;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly TrafficRegistry _trafficRegistry;

    public TrojanMuxInboundServer(
        IDispatcher dispatcher,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
    }

    public async Task HandleAsync(
        Stream muxStream,
        TrojanUser user,
        ITrojanInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(muxStream);
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(options);

        await HandleAsync(
            muxStream,
            user,
            TrojanDispatchContextFactory.Create(user, options),
            options.ConnectionIdleSeconds,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task HandleAsync(
        Stream muxStream,
        IRuntimeUserDefinition user,
        DispatchContext dispatchContext,
        int connectionIdleSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(muxStream);
        ArgumentNullException.ThrowIfNull(user);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(connectionIdleSeconds));
        await using var trackedStream = new TrojanMuxTrackedStream(
            muxStream,
            user.UserId,
            _rateLimiterRegistry.GetUserGate(user),
            _rateLimiterRegistry.GlobalGate,
            _trafficRegistry,
            activityTimer);

        var worker = new TrojanMuxInboundWorker(
            _dispatcher,
            trackedStream,
            dispatchContext);
        await worker.RunAsync(linkedCts.Token).ConfigureAwait(false);
    }

    private interface ITrojanMuxInboundSession : IAsyncDisposable
    {
        Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken);

        Task CompleteInputAsync(CancellationToken cancellationToken);
    }

    private sealed class TrojanMuxInboundWorker
    {
        private readonly IDispatcher _dispatcher;
        private readonly Stream _stream;
        private readonly DispatchContext _dispatchContext;
        private readonly ConcurrentDictionary<ushort, ITrojanMuxInboundSession> _sessions = new();
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        public TrojanMuxInboundWorker(
            IDispatcher dispatcher,
            Stream stream,
            DispatchContext dispatchContext)
        {
            _dispatcher = dispatcher;
            _stream = stream;
            _dispatchContext = dispatchContext;
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    var frame = await TrojanMuxFrameCodec.ReadAsync(_stream, cancellationToken).ConfigureAwait(false);
                    if (frame is null)
                    {
                        return;
                    }

                    switch (frame.Status)
                    {
                        case TrojanMuxSessionStatus.New:
                            await HandleNewAsync(frame, cancellationToken).ConfigureAwait(false);
                            break;
                        case TrojanMuxSessionStatus.Keep:
                            await HandleKeepAsync(frame, cancellationToken).ConfigureAwait(false);
                            break;
                        case TrojanMuxSessionStatus.End:
                            await HandleEndAsync(frame.SessionId, cancellationToken).ConfigureAwait(false);
                            break;
                        case TrojanMuxSessionStatus.KeepAlive:
                            break;
                        default:
                            throw new InvalidDataException($"Unsupported trojan mux session status: {frame.Status}.");
                    }
                }
            }
            finally
            {
                foreach (var sessionId in _sessions.Keys.ToArray())
                {
                    if (_sessions.TryRemove(sessionId, out var session))
                    {
                        await session.DisposeAsync().ConfigureAwait(false);
                    }
                }

                _writeLock.Dispose();
            }
        }

        private async Task HandleNewAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(frame.Target);

            ITrojanMuxInboundSession session;
            if (frame.Target.Network == DispatchNetwork.Tcp)
            {
                var remoteStream = await _dispatcher.DispatchTcpAsync(
                    CreateDispatchContext(frame.Target),
                    frame.Target.ToDispatchDestination(),
                    cancellationToken).ConfigureAwait(false);
                session = new TrojanMuxInboundTcpSession(
                    frame.SessionId,
                    remoteStream,
                    this);
            }
            else
            {
                var transport = await _dispatcher.DispatchUdpAsync(
                    CreateDispatchContext(frame.Target),
                    cancellationToken).ConfigureAwait(false);
                session = new TrojanMuxInboundUdpSession(
                    frame.SessionId,
                    transport,
                    this);
            }

            if (!_sessions.TryAdd(frame.SessionId, session))
            {
                await session.DisposeAsync().ConfigureAwait(false);
                throw new InvalidDataException($"Duplicate trojan mux session id: {frame.SessionId}.");
            }

            if (frame.HasData)
            {
                await session.WriteRequestAsync(frame, cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task HandleKeepAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            if (!_sessions.TryGetValue(frame.SessionId, out var session))
            {
                await WriteFrameAsync(
                    new TrojanMuxFrame
                    {
                        SessionId = frame.SessionId,
                        Status = TrojanMuxSessionStatus.End
                    },
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (frame.HasData)
            {
                await session.WriteRequestAsync(frame, cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task HandleEndAsync(ushort sessionId, CancellationToken cancellationToken)
        {
            if (!_sessions.TryRemove(sessionId, out var session))
            {
                return;
            }

            await session.CompleteInputAsync(cancellationToken).ConfigureAwait(false);
            await session.DisposeAsync().ConfigureAwait(false);
        }

        private DispatchContext CreateDispatchContext(TrojanMuxFrameTarget target)
            => _dispatchContext with
            {
                OriginalDestinationHost = target.Host,
                OriginalDestinationPort = target.Port
            };

        public ValueTask WriteFrameAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
            => WriteFrameCoreAsync(frame, cancellationToken);

        public async Task CompleteSessionAsync(
            ushort sessionId,
            ITrojanMuxInboundSession session,
            Exception? error,
            CancellationToken cancellationToken)
        {
            if (_sessions.TryRemove(sessionId, out var existing) &&
                !ReferenceEquals(existing, session))
            {
                await existing.DisposeAsync().ConfigureAwait(false);
            }

            await WriteFrameAsync(
                new TrojanMuxFrame
                {
                    SessionId = sessionId,
                    Status = TrojanMuxSessionStatus.End,
                    Option = error is null ? TrojanMuxFrameOption.None : TrojanMuxFrameOption.Error
                },
                cancellationToken).ConfigureAwait(false);
        }

        private async ValueTask WriteFrameCoreAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await TrojanMuxFrameCodec.WriteAsync(_stream, frame, cancellationToken).ConfigureAwait(false);
                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }
    }

    private sealed class TrojanMuxInboundTcpSession : ITrojanMuxInboundSession
    {
        private readonly ushort _sessionId;
        private readonly Stream _remoteStream;
        private readonly TrojanMuxInboundWorker _owner;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Task _responseLoop;

        private int _disposed;

        public TrojanMuxInboundTcpSession(
            ushort sessionId,
            Stream remoteStream,
            TrojanMuxInboundWorker owner)
        {
            _sessionId = sessionId;
            _remoteStream = remoteStream;
            _owner = owner;
            _responseLoop = RunResponseLoopAsync();
        }

        public async Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            if (frame.Payload.Length == 0)
            {
                return;
            }

            await _remoteStream.WriteAsync(frame.Payload.AsMemory(0, frame.Payload.Length), cancellationToken).ConfigureAwait(false);
            await _remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public Task CompleteInputAsync(CancellationToken cancellationToken)
        {
            TryShutdownWrite(_remoteStream);
            return Task.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            await _remoteStream.DisposeAsync().ConfigureAwait(false);

            try
            {
                await _responseLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            _disposeCts.Dispose();
        }

        private async Task RunResponseLoopAsync()
        {
            Exception? terminalError = null;
            var buffer = new byte[TrojanMuxProtocol.MaxStreamChunkLength];

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var read = await _remoteStream.ReadAsync(buffer.AsMemory(0, buffer.Length), _disposeCts.Token).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    await _owner.WriteFrameAsync(
                        new TrojanMuxFrame
                        {
                            SessionId = _sessionId,
                            Status = TrojanMuxSessionStatus.Keep,
                            Option = TrojanMuxFrameOption.Data,
                            Payload = buffer.AsSpan(0, read).ToArray()
                        },
                        _disposeCts.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                terminalError = ex;
            }
            finally
            {
                await _owner.CompleteSessionAsync(_sessionId, this, terminalError, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private sealed class TrojanMuxInboundUdpSession : ITrojanMuxInboundSession
    {
        private readonly ushort _sessionId;
        private readonly IOutboundUdpTransport _transport;
        private readonly TrojanMuxInboundWorker _owner;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Task _responseLoop;

        private int _disposed;

        public TrojanMuxInboundUdpSession(
            ushort sessionId,
            IOutboundUdpTransport transport,
            TrojanMuxInboundWorker owner)
        {
            _sessionId = sessionId;
            _transport = transport;
            _owner = owner;
            _responseLoop = RunResponseLoopAsync();
        }

        public async Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            if (frame.Payload.Length == 0 || frame.Target is null)
            {
                return;
            }

            await _transport.SendAsync(
                frame.Target.ToDispatchDestination(),
                frame.Payload,
                cancellationToken).ConfigureAwait(false);
        }

        public Task CompleteInputAsync(CancellationToken cancellationToken)
            => _transport.DisposeAsync().AsTask();

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            await _transport.DisposeAsync().ConfigureAwait(false);

            try
            {
                await _responseLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            _disposeCts.Dispose();
        }

        private async Task RunResponseLoopAsync()
        {
            Exception? terminalError = null;

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var datagram = await _transport.ReceiveAsync(_disposeCts.Token).ConfigureAwait(false);
                    if (datagram is null)
                    {
                        break;
                    }

                    await _owner.WriteFrameAsync(
                        new TrojanMuxFrame
                        {
                            SessionId = _sessionId,
                            Status = TrojanMuxSessionStatus.Keep,
                            Option = TrojanMuxFrameOption.Data,
                            Target = new TrojanMuxFrameTarget(
                                datagram.SourceHost,
                                datagram.SourcePort,
                                DispatchNetwork.Udp),
                            Payload = datagram.Payload
                        },
                        _disposeCts.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                terminalError = ex;
            }
            finally
            {
                await _owner.CompleteSessionAsync(_sessionId, this, terminalError, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private sealed class TrojanMuxTrackedStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly string _userId;
        private readonly ByteRateGate _userGate;
        private readonly ByteRateGate _globalGate;
        private readonly TrafficRegistry _trafficRegistry;
        private readonly ActivityTimer _activityTimer;

        public TrojanMuxTrackedStream(
            Stream innerStream,
            string userId,
            ByteRateGate userGate,
            ByteRateGate globalGate,
            TrafficRegistry trafficRegistry,
            ActivityTimer activityTimer)
        {
            _innerStream = innerStream;
            _userId = userId;
            _userGate = userGate;
            _globalGate = globalGate;
            _trafficRegistry = trafficRegistry;
            _activityTimer = activityTimer;
        }

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _innerStream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return 0;
            }

            _activityTimer.Update();
            await _userGate.WaitAsync(read, cancellationToken).ConfigureAwait(false);
            await _globalGate.WaitAsync(read, cancellationToken).ConfigureAwait(false);
            _trafficRegistry.RecordUpload(_userId, read);
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var scratch = new byte[buffer.Length];
            var read = ReadAsync(scratch, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            scratch.AsSpan(0, read).CopyTo(buffer);
            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override void Write(ReadOnlySpan<byte> buffer)
            => WriteAsync(buffer.ToArray(), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.IsEmpty)
            {
                return;
            }

            _activityTimer.Update();
            await _userGate.WaitAsync(buffer.Length, cancellationToken).ConfigureAwait(false);
            await _globalGate.WaitAsync(buffer.Length, cancellationToken).ConfigureAwait(false);
            await _innerStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            _activityTimer.Update();
            _trafficRegistry.RecordDownload(_userId, buffer.Length);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override ValueTask DisposeAsync() => _innerStream.DisposeAsync();
    }

    private static void TryShutdownWrite(Stream stream)
    {
        if (stream is not NetworkStream networkStream)
        {
            return;
        }

        try
        {
            networkStream.Socket.Shutdown(SocketShutdown.Send);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException)
        {
        }
        catch (SocketException)
        {
        }
    }
}

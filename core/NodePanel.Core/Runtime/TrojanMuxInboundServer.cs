using System.Buffers.Binary;
using System.Net.Sockets;
using System.Threading.Channels;
using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public sealed class TrojanMuxInboundServer
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;
    private readonly TrojanMuxInboundXudpRegistry _xudpRegistry;

    public TrojanMuxInboundServer(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry)
        : this(dispatcher, rateLimiterRegistry, trafficRegistry, fakeDnsEngine: null)
    {
    }

    public TrojanMuxInboundServer(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IFakeDnsEngine? fakeDnsEngine)
        : this(
            dispatcher,
            rateLimiterRegistry,
            trafficRegistry,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal TrojanMuxInboundServer(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeSniffer runtimeSniffer,
        TimeSpan? xudpExpiration = null)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer ?? throw new ArgumentNullException(nameof(runtimeSniffer));
        _xudpRegistry = new TrojanMuxInboundXudpRegistry(
            xudpExpiration ?? TimeSpan.FromMinutes(1));
    }

    public async Task HandleAsync(
        Stream muxStream,
        TrojanUser user,
        IRuntimeInboundConnectionOptions options,
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
            options.Sniffing,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task HandleAsync(
        Stream muxStream,
        IRuntimeUserDefinition user,
        DispatchContext dispatchContext,
        int connectionIdleSeconds,
        CancellationToken cancellationToken,
        DispatchNetwork? allowedTargetNetwork = null)
        => await HandleAsync(
                muxStream,
                user,
                dispatchContext,
                connectionIdleSeconds,
                RuntimeSniffingOptions.Disabled,
                cancellationToken,
                allowedTargetNetwork)
            .ConfigureAwait(false);

    internal async Task HandleAsync(
        Stream muxStream,
        IRuntimeUserDefinition user,
        DispatchContext dispatchContext,
        int connectionIdleSeconds,
        IRuntimeSniffingDefinition sniffing,
        CancellationToken cancellationToken,
        DispatchNetwork? allowedTargetNetwork = null,
        bool readSourceAndLocal = false)
    {
        ArgumentNullException.ThrowIfNull(muxStream);
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(sniffing);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(connectionIdleSeconds));
        var userGate = _rateLimiterRegistry.GetUserGate(user);
        var globalGate = _rateLimiterRegistry.GlobalGate;
        await using var trackedStream = new FlowControlledStream(
            muxStream,
            readControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => _trafficRegistry.RecordUpload(user, bytes)),
            writeControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => _trafficRegistry.RecordDownload(user, bytes)),
            activityTimer: activityTimer);

        var worker = new TrojanMuxInboundWorker(
            _dispatcher,
            _runtimeSniffer,
            trackedStream,
            dispatchContext with
            {
                SkipTransportFlowControl = true
            },
            sniffing,
            allowedTargetNetwork,
            readSourceAndLocal,
            _xudpRegistry);
        await worker.RunAsync(linkedCts.Token).ConfigureAwait(false);
    }

    private static bool TryGetXudpGlobalIdKey(ReadOnlySpan<byte> globalId, out ulong key)
    {
        if (globalId.Length != 8)
        {
            key = 0;
            return false;
        }

        key = BinaryPrimitives.ReadUInt64BigEndian(globalId);
        return key != 0;
    }

    private interface ITrojanMuxInboundSession : IAsyncDisposable
    {
        Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken);

        Task CompleteInputAsync(CancellationToken cancellationToken);
    }

    private sealed class TrojanMuxInboundWorker
    {
        private readonly IDispatcher _dispatcher;
        private readonly IRuntimeSniffer _runtimeSniffer;
        private readonly IRuntimeSniffingDefinition _sniffing;
        private readonly Stream _stream;
        private readonly DispatchContext _dispatchContext;
        private readonly DispatchNetwork? _allowedTargetNetwork;
        private readonly bool _readSourceAndLocal;
        private readonly TrojanMuxInboundXudpRegistry _xudpRegistry;
        private readonly ConcurrentDictionary<ushort, ITrojanMuxInboundSession> _sessions = new();
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        public TrojanMuxInboundWorker(
            IDispatcher dispatcher,
            IRuntimeSniffer runtimeSniffer,
            Stream stream,
            DispatchContext dispatchContext,
            IRuntimeSniffingDefinition sniffing,
            DispatchNetwork? allowedTargetNetwork,
            bool readSourceAndLocal,
            TrojanMuxInboundXudpRegistry xudpRegistry)
        {
            _dispatcher = dispatcher;
            _runtimeSniffer = runtimeSniffer;
            _stream = stream;
            _dispatchContext = dispatchContext;
            _sniffing = sniffing;
            _allowedTargetNetwork = allowedTargetNetwork;
            _readSourceAndLocal = readSourceAndLocal;
            _xudpRegistry = xudpRegistry;
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    TrojanMuxFrame? frame;
                    try
                    {
                        frame = await TrojanMuxFrameCodec.ReadAsync(
                            _stream,
                            _readSourceAndLocal,
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (!cancellationToken.IsCancellationRequested && IsPeerDisconnected(ex))
                    {
                        return;
                    }

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

        private static bool IsPeerDisconnected(Exception exception)
        {
            for (Exception? current = exception; current is not null; current = current.InnerException)
            {
                if (current is EndOfStreamException)
                {
                    return true;
                }

                if (current is SocketException socketException &&
                    socketException.SocketErrorCode is SocketError.ConnectionReset or
                        SocketError.ConnectionAborted or
                        SocketError.OperationAborted or
                        SocketError.Shutdown)
                {
                    return true;
                }
            }

            return false;
        }

        private async Task HandleNewAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(frame.Target);
            EnsureTargetAllowed(frame.Target.Network);

            ITrojanMuxInboundSession session;
            TrojanMuxInboundXudpSession? xudpSession = null;
            if (frame.Target.Network == DispatchNetwork.Tcp)
            {
                session = new TrojanMuxInboundTcpSession(
                    frame.SessionId,
                    frame,
                    this);
            }
            else if (TryGetXudpGlobalIdKey(frame.GlobalId, out var globalIdKey))
            {
                xudpSession = new TrojanMuxInboundXudpSession(
                    frame.SessionId,
                    frame.Target,
                    this,
                    _xudpRegistry.Acquire(globalIdKey));
                session = xudpSession;
            }
            else
            {
                session = new TrojanMuxInboundUdpSession(
                    frame.SessionId,
                    frame.Target,
                    this);
            }

            if (!_sessions.TryAdd(frame.SessionId, session))
            {
                await session.DisposeAsync().ConfigureAwait(false);
                throw new InvalidDataException($"Duplicate trojan mux session id: {frame.SessionId}.");
            }

            try
            {
                if (xudpSession is not null)
                {
                    await xudpSession.AttachAsync(cancellationToken).ConfigureAwait(false);
                }

                if (frame.HasData)
                {
                    await session.WriteRequestAsync(frame, cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                if (_sessions.TryRemove(frame.SessionId, out var existing) &&
                    !ReferenceEquals(existing, session))
                {
                    await existing.DisposeAsync().ConfigureAwait(false);
                }

                await session.DisposeAsync().ConfigureAwait(false);
                throw;
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

        private DispatchContext CreateDispatchContext(TrojanMuxFrame frame)
        {
            ArgumentNullException.ThrowIfNull(frame.Target);

            var sourceEndPoint = frame.Source is not null
                ? TrojanMuxProtocol.CreateEndPoint(frame.Source)
                : _dispatchContext.SourceEndPoint;
            var localEndPoint = frame.Local is not null
                ? TrojanMuxProtocol.CreateEndPoint(frame.Local)
                : _dispatchContext.LocalEndPoint;

            return _dispatchContext with
            {
                OriginalDestinationHost = frame.Target.Host,
                OriginalDestinationPort = frame.Target.Port,
                InboundSourceNetwork = frame.Source is not null
                    ? NormalizeNetwork(frame.Source.Network)
                    : _dispatchContext.InboundSourceNetwork,
                SourceEndPoint = sourceEndPoint,
                LocalEndPoint = localEndPoint,
                SourceAddresses = frame.Source is not null
                    ? TrojanMuxProtocol.CreateAddressList(sourceEndPoint)
                    : _dispatchContext.SourceAddresses,
                LocalAddresses = frame.Local is not null
                    ? TrojanMuxProtocol.CreateAddressList(localEndPoint)
                    : _dispatchContext.LocalAddresses
            };
        }

        public ValueTask<RuntimeTcpDispatchResult> DispatchTcpAsync(
            TrojanMuxFrame frame,
            Stream inboundStream,
            CancellationToken cancellationToken)
            => RuntimeTcpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                _sniffing,
                inboundStream,
                CreateDispatchContext(frame),
                frame.Target!.ToDispatchDestination(),
                cancellationToken,
                cancellationToken);

        public ValueTask<RuntimeUdpDispatchResult> DispatchUdpAsync(
            TrojanMuxFrame frame,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
            => RuntimeUdpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                _sniffing,
                payload,
                CreateDispatchContext(frame),
                frame.Target!.ToDispatchDestination(),
                cancellationToken);

        public IOutboundUdpTransport WrapUdpTransport(IOutboundUdpTransport transport)
            => RuntimeSniffingUdpTransport.WrapIfNeeded(
                transport,
                _runtimeSniffer,
                _sniffing);

        private void EnsureTargetAllowed(DispatchNetwork network)
        {
            if (_allowedTargetNetwork is null || network == _allowedTargetNetwork.Value)
            {
                return;
            }

            throw new InvalidDataException(
                $"Mux target network '{network}' is not allowed on the current connection. Allowed network: '{_allowedTargetNetwork.Value}'.");
        }

        private static string NormalizeNetwork(DispatchNetwork network)
            => network switch
            {
                DispatchNetwork.Tcp => RoutingNetworks.Tcp,
                DispatchNetwork.Udp => RoutingNetworks.Udp,
                _ => string.Empty
            };

        public ValueTask WriteFrameAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
            => WriteFrameCoreAsync(frame, cancellationToken);

        public async Task ReleaseSessionAsync(
            ushort sessionId,
            ITrojanMuxInboundSession session)
        {
            if (_sessions.TryRemove(sessionId, out var existing) &&
                !ReferenceEquals(existing, session))
            {
                await existing.DisposeAsync().ConfigureAwait(false);
            }
        }

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

    private sealed class TrojanMuxInboundXudpRegistry
    {
        private readonly TimeSpan _expiration;
        private readonly ConcurrentDictionary<ulong, TrojanMuxInboundXudpState> _states = new();

        public TrojanMuxInboundXudpRegistry(TimeSpan expiration)
        {
            _expiration = expiration;
        }

        public TrojanMuxInboundXudpState Acquire(ulong globalIdKey)
        {
            while (true)
            {
                var state = _states.GetOrAdd(
                    globalIdKey,
                    key => new TrojanMuxInboundXudpState(key, this, _expiration));
                if (!state.IsTerminal)
                {
                    return state;
                }

                _states.TryRemove(new KeyValuePair<ulong, TrojanMuxInboundXudpState>(globalIdKey, state));
            }
        }

        public void Remove(ulong globalIdKey, TrojanMuxInboundXudpState state)
            => _states.TryRemove(new KeyValuePair<ulong, TrojanMuxInboundXudpState>(globalIdKey, state));
    }

    private enum TrojanMuxInboundXudpStateStatus
    {
        Initializing = 0,
        Active = 1,
        Expiring = 2,
        Closed = 3
    }

    private sealed class TrojanMuxInboundXudpState
    {
        private readonly TrojanMuxInboundXudpRegistry _registry;
        private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = true
            });
        private readonly SemaphoreSlim _attachLock = new(1, 1);
        private readonly SemaphoreSlim _transportLock = new(1, 1);
        private readonly object _sync = new();
        private readonly ulong _globalIdKey;
        private readonly TimeSpan _expiration;

        private TrojanMuxInboundXudpSession? _currentSession;
        private CancellationTokenSource? _expirationCts;
        private IOutboundUdpTransport? _transport;
        private Task? _receiveLoop;
        private long _transportVersion;
        private TrojanMuxInboundXudpStateStatus _status;
        private int _closed;
        private int _responseCompleted;

        public TrojanMuxInboundXudpState(
            ulong globalIdKey,
            TrojanMuxInboundXudpRegistry registry,
            TimeSpan expiration)
        {
            _globalIdKey = globalIdKey;
            _registry = registry;
            _expiration = expiration;
        }

        public bool IsTerminal
        {
            get
            {
                lock (_sync)
                {
                    return _status == TrojanMuxInboundXudpStateStatus.Closed ||
                           Volatile.Read(ref _closed) != 0 ||
                           Volatile.Read(ref _responseCompleted) != 0;
                }
            }
        }

        public async Task AttachAsync(
            TrojanMuxInboundXudpSession session,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(session);

            await _attachLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfClosed();

                TrojanMuxInboundXudpSession? previous;
                CancellationTokenSource? expirationCts;
                lock (_sync)
                {
                    ThrowIfClosed();
                    previous = _currentSession;
                    _currentSession = session;
                    _status = TrojanMuxInboundXudpStateStatus.Initializing;
                    expirationCts = _expirationCts;
                    _expirationCts = null;
                }

                expirationCts?.Cancel();
                expirationCts?.Dispose();

                if (previous is not null &&
                    !ReferenceEquals(previous, session))
                {
                    await previous.ForceCloseForRebindAsync().ConfigureAwait(false);
                }

                lock (_sync)
                {
                    if (ReferenceEquals(_currentSession, session) &&
                        Volatile.Read(ref _closed) == 0 &&
                        Volatile.Read(ref _responseCompleted) == 0)
                    {
                        _status = TrojanMuxInboundXudpStateStatus.Active;
                    }
                }

                session.StartResponseLoop();
            }
            finally
            {
                _attachLock.Release();
            }
        }

        public async Task SendAsync(
            TrojanMuxInboundXudpSession session,
            TrojanMuxFrame frame,
            CancellationToken cancellationToken)
        {
            EnsureAttached(session);

            await _transportLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                EnsureAttached(session);

                var transport = await EnsureTransportAsync(session, frame, cancellationToken).ConfigureAwait(false);
                try
                {
                    await transport.SendAsync(
                        frame.Target!.ToDispatchDestination(),
                        frame.Payload,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException &&
                                           Volatile.Read(ref _closed) == 0)
                {
                    transport = await ReplaceTransportAsync(session, frame, cancellationToken).ConfigureAwait(false);
                    await transport.SendAsync(
                        frame.Target!.ToDispatchDestination(),
                        frame.Payload,
                        cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                _transportLock.Release();
            }
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            try
            {
                return await _responses.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException ex) when (ex.InnerException is null)
            {
                return null;
            }
            catch (ChannelClosedException ex)
            {
                throw new IOException("XUDP transport closed unexpectedly.", ex.InnerException);
            }
        }

        public async ValueTask DetachAsync(TrojanMuxInboundXudpSession session)
        {
            CancellationTokenSource? expirationCts = null;
            var shouldFinalize = false;
            lock (_sync)
            {
                if (ReferenceEquals(_currentSession, session))
                {
                    _currentSession = null;
                }

                if (Volatile.Read(ref _closed) != 0)
                {
                    return;
                }

                if (Volatile.Read(ref _responseCompleted) != 0 ||
                    _transport is null)
                {
                    _status = TrojanMuxInboundXudpStateStatus.Closed;
                    Interlocked.Exchange(ref _closed, 1);
                    expirationCts = _expirationCts;
                    _expirationCts = null;
                    shouldFinalize = true;
                }
                else if (_currentSession is null)
                {
                    _status = TrojanMuxInboundXudpStateStatus.Expiring;
                    expirationCts = new CancellationTokenSource();
                    _expirationCts = expirationCts;
                }
            }

            if (shouldFinalize)
            {
                expirationCts?.Cancel();
                expirationCts?.Dispose();
                await FinalizeClosureAsync().ConfigureAwait(false);
                return;
            }

            if (expirationCts is not null)
            {
                _ = Task.Run(() => ExpireAsync(expirationCts));
            }
        }

        private void EnsureAttached(TrojanMuxInboundXudpSession session)
        {
            ThrowIfClosed();

            lock (_sync)
            {
                if (!ReferenceEquals(_currentSession, session))
                {
                    throw new InvalidOperationException("XUDP session is not attached to the current mux connection.");
                }
            }
        }

        private bool IsAttached(TrojanMuxInboundXudpSession session)
        {
            if (Volatile.Read(ref _closed) != 0 ||
                Volatile.Read(ref _responseCompleted) != 0)
            {
                return false;
            }

            lock (_sync)
            {
                return ReferenceEquals(_currentSession, session);
            }
        }

        private async Task<IOutboundUdpTransport> EnsureTransportAsync(
            TrojanMuxInboundXudpSession session,
            TrojanMuxFrame frame,
            CancellationToken cancellationToken)
        {
            if (_transport is not null)
            {
                return _transport;
            }

            return await CreateTransportAsync(
                session,
                frame,
                replaceExisting: false,
                cancellationToken).ConfigureAwait(false);
        }

        private Task<IOutboundUdpTransport> ReplaceTransportAsync(
            TrojanMuxInboundXudpSession session,
            TrojanMuxFrame frame,
            CancellationToken cancellationToken)
            => CreateTransportAsync(
                session,
                frame,
                replaceExisting: true,
                cancellationToken);

        private async Task<IOutboundUdpTransport> CreateTransportAsync(
            TrojanMuxInboundXudpSession session,
            TrojanMuxFrame frame,
            bool replaceExisting,
            CancellationToken cancellationToken)
        {
            var dispatchResult = await session.DispatchUdpAsync(frame, cancellationToken).ConfigureAwait(false);
            var transport = session.WrapUdpTransport(dispatchResult.Transport);
            if (!IsAttached(session))
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                throw new OperationCanceledException(
                    "XUDP session detached during transport initialization.",
                    cancellationToken);
            }

            IOutboundUdpTransport? previousTransport = null;
            if (replaceExisting)
            {
                previousTransport = _transport;
            }

            var version = Interlocked.Increment(ref _transportVersion);
            _transport = transport;
            _receiveLoop = RunReceiveLoopAsync(transport, version);

            if (previousTransport is not null)
            {
                try
                {
                    await previousTransport.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }
            }

            lock (_sync)
            {
                if (ReferenceEquals(_currentSession, session) &&
                    Volatile.Read(ref _closed) == 0 &&
                    Volatile.Read(ref _responseCompleted) == 0)
                {
                    _status = TrojanMuxInboundXudpStateStatus.Active;
                }
            }

            return transport;
        }

        private async Task RunReceiveLoopAsync(
            IOutboundUdpTransport transport,
            long version)
        {
            Exception? terminalError = null;

            try
            {
                while (Volatile.Read(ref _closed) == 0)
                {
                    var datagram = await transport.ReceiveAsync(CancellationToken.None).ConfigureAwait(false);
                    if (datagram is null)
                    {
                        break;
                    }

                    await _responses.Writer.WriteAsync(datagram, CancellationToken.None).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (Volatile.Read(ref _closed) != 0)
            {
            }
            catch (ObjectDisposedException) when (Volatile.Read(ref _closed) != 0)
            {
            }
            catch (Exception ex)
            {
                terminalError = ex;
            }
            finally
            {
                await OnReceiveLoopCompletedAsync(version, terminalError).ConfigureAwait(false);
            }
        }

        private async Task OnReceiveLoopCompletedAsync(long version, Exception? terminalError)
        {
            var shouldRemove = false;
            CancellationTokenSource? expirationCts = null;

            lock (_sync)
            {
                if (version != Interlocked.Read(ref _transportVersion) ||
                    Volatile.Read(ref _closed) != 0)
                {
                    return;
                }

                _transport = null;
                _receiveLoop = null;
                if (_currentSession is null)
                {
                    _status = TrojanMuxInboundXudpStateStatus.Closed;
                    Interlocked.Exchange(ref _closed, 1);
                    expirationCts = _expirationCts;
                    _expirationCts = null;
                    shouldRemove = true;
                }
                else
                {
                    _status = TrojanMuxInboundXudpStateStatus.Closed;
                    Interlocked.Exchange(ref _responseCompleted, 1);
                }
            }

            expirationCts?.Cancel();
            expirationCts?.Dispose();

            if (shouldRemove)
            {
                _registry.Remove(_globalIdKey, this);
            }

            _responses.Writer.TryComplete(terminalError);

            await Task.CompletedTask.ConfigureAwait(false);
        }

        private async Task ExpireAsync(CancellationTokenSource expirationCts)
        {
            try
            {
                await Task.Delay(_expiration, expirationCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            var shouldFinalize = false;
            lock (_sync)
            {
                if (Volatile.Read(ref _closed) != 0 ||
                    !ReferenceEquals(_expirationCts, expirationCts) ||
                    _currentSession is not null)
                {
                    return;
                }

                _status = TrojanMuxInboundXudpStateStatus.Closed;
                _expirationCts = null;
                Interlocked.Exchange(ref _closed, 1);
                shouldFinalize = true;
            }

            expirationCts.Dispose();
            if (shouldFinalize)
            {
                await FinalizeClosureAsync().ConfigureAwait(false);
            }
        }

        private async Task FinalizeClosureAsync()
        {
            _registry.Remove(_globalIdKey, this);

            IOutboundUdpTransport? transport;
            await _transportLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                transport = _transport;
                _transport = null;
                _receiveLoop = null;
                Interlocked.Increment(ref _transportVersion);
            }
            finally
            {
                _transportLock.Release();
            }

            if (transport is not null)
            {
                try
                {
                    await transport.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }
            }

            _responses.Writer.TryComplete();
        }

        private void ThrowIfClosed()
        {
            lock (_sync)
            {
                if (_status == TrojanMuxInboundXudpStateStatus.Closed ||
                    Volatile.Read(ref _closed) != 0 ||
                    Volatile.Read(ref _responseCompleted) != 0)
                {
                    throw new ObjectDisposedException(nameof(TrojanMuxInboundXudpState));
                }
            }
        }
    }

    private sealed class TrojanMuxInboundTcpSession : ITrojanMuxInboundSession
    {
        private readonly ushort _sessionId;
        private readonly TrojanMuxFrame _openFrame;
        private readonly TrojanMuxInputStream _inputStream = new();
        private readonly TrojanMuxInboundWorker _owner;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Task _runLoop;

        private int _disposed;

        public TrojanMuxInboundTcpSession(
            ushort sessionId,
            TrojanMuxFrame openFrame,
            TrojanMuxInboundWorker owner)
        {
            _sessionId = sessionId;
            _openFrame = openFrame;
            _owner = owner;
            _runLoop = RunAsync();
        }

        public async Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            if (frame.Payload.Length == 0)
            {
                return;
            }

            await _inputStream.EnqueueAsync(frame.Payload, cancellationToken).ConfigureAwait(false);
        }

        public Task CompleteInputAsync(CancellationToken cancellationToken)
        {
            _inputStream.Complete();
            return Task.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            _inputStream.Complete();

            try
            {
                await _runLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                await _inputStream.DisposeAsync().ConfigureAwait(false);
            }

            _disposeCts.Dispose();
        }

        private async Task RunAsync()
        {
            Exception? terminalError = null;
            Stream? remoteStream = null;

            try
            {
                var dispatchResult = await _owner
                    .DispatchTcpAsync(_openFrame, _inputStream, _disposeCts.Token)
                    .ConfigureAwait(false);
                remoteStream = dispatchResult.OutboundStream;

                var requestLoop = PumpRequestsAsync(
                    dispatchResult.InboundStream,
                    remoteStream,
                    _disposeCts.Token);
                var responseLoop = PumpResponsesAsync(remoteStream, _disposeCts.Token);
                var completed = await Task.WhenAny(requestLoop, responseLoop).ConfigureAwait(false);

                if (ReferenceEquals(completed, requestLoop))
                {
                    await requestLoop.ConfigureAwait(false);
                    TryShutdownWrite(remoteStream);
                    await responseLoop.ConfigureAwait(false);
                }
                else
                {
                    await responseLoop.ConfigureAwait(false);
                    _disposeCts.Cancel();

                    try
                    {
                        await requestLoop.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
                    {
                    }
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
                if (remoteStream is not null)
                {
                    await remoteStream.DisposeAsync().ConfigureAwait(false);
                }

                await _owner.CompleteSessionAsync(_sessionId, this, terminalError, CancellationToken.None).ConfigureAwait(false);
            }
        }

        private async Task PumpRequestsAsync(
            Stream inboundStream,
            Stream remoteStream,
            CancellationToken cancellationToken)
        {
            var buffer = new byte[TrojanMuxProtocol.MaxStreamChunkLength];
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await inboundStream
                    .ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }

                await remoteStream
                    .WriteAsync(buffer.AsMemory(0, read), cancellationToken)
                    .ConfigureAwait(false);
                await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        private async Task PumpResponsesAsync(Stream remoteStream, CancellationToken cancellationToken)
        {
            var buffer = new byte[TrojanMuxProtocol.MaxStreamChunkLength];
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await remoteStream
                    .ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }

                await _owner.WriteFrameAsync(
                        new TrojanMuxFrame
                        {
                            SessionId = _sessionId,
                            Status = TrojanMuxSessionStatus.Keep,
                            Option = TrojanMuxFrameOption.Data,
                            Payload = buffer.AsSpan(0, read).ToArray()
                        },
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private sealed class TrojanMuxInboundXudpSession : ITrojanMuxInboundSession
    {
        private readonly ushort _sessionId;
        private readonly TrojanMuxFrameTarget _target;
        private readonly TrojanMuxInboundWorker _owner;
        private readonly TrojanMuxInboundXudpState _state;
        private readonly CancellationTokenSource _disposeCts = new();

        private Task? _responseLoop;
        private int _cleanupStarted;

        public TrojanMuxInboundXudpSession(
            ushort sessionId,
            TrojanMuxFrameTarget target,
            TrojanMuxInboundWorker owner,
            TrojanMuxInboundXudpState state)
        {
            _sessionId = sessionId;
            _target = target;
            _owner = owner;
            _state = state;
        }

        public Task AttachAsync(CancellationToken cancellationToken)
            => _state.AttachAsync(this, cancellationToken);

        public void StartResponseLoop()
            => _responseLoop ??= RunResponseLoopAsync();

        public async Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            if (frame.Payload.Length == 0 || frame.Target is null)
            {
                return;
            }

            await _state.SendAsync(this, frame, cancellationToken).ConfigureAwait(false);
        }

        public Task CompleteInputAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public async Task ForceCloseForRebindAsync()
        {
            if (!TryBeginCleanup())
            {
                await WaitForResponseLoopCompletionAsync().ConfigureAwait(false);
                return;
            }

            _disposeCts.Cancel();
            try
            {
                await _owner.CompleteSessionAsync(
                    _sessionId,
                    this,
                    error: null,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }

            try
            {
                await WaitForResponseLoopCompletionAsync().ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
            finally
            {
                _disposeCts.Dispose();
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (!TryBeginCleanup())
            {
                await WaitForResponseLoopCompletionAsync().ConfigureAwait(false);
                return;
            }

            _disposeCts.Cancel();
            await _owner.CompleteSessionAsync(
                _sessionId,
                this,
                error: null,
                CancellationToken.None).ConfigureAwait(false);

            try
            {
                await WaitForResponseLoopCompletionAsync().ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
            finally
            {
                await _state.DetachAsync(this).ConfigureAwait(false);
                _disposeCts.Dispose();
            }
        }

        public ValueTask<RuntimeUdpDispatchResult> DispatchUdpAsync(
            TrojanMuxFrame frame,
            CancellationToken cancellationToken)
        {
            var effectiveFrame = frame.Target is null
                ? frame with { Target = _target }
                : frame;
            return _owner.DispatchUdpAsync(
                effectiveFrame,
                frame.Payload,
                cancellationToken);
        }

        public IOutboundUdpTransport WrapUdpTransport(IOutboundUdpTransport transport)
            => _owner.WrapUdpTransport(transport);

        private async Task RunResponseLoopAsync()
        {
            Exception? terminalError = null;

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var datagram = await _state.ReceiveAsync(_disposeCts.Token).ConfigureAwait(false);
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
                return;
            }
            catch (Exception ex)
            {
                terminalError = ex;
            }

            if (!TryBeginCleanup())
            {
                return;
            }

            try
            {
                await _owner.CompleteSessionAsync(
                    _sessionId,
                    this,
                    terminalError,
                    CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                await _state.DetachAsync(this).ConfigureAwait(false);
                _disposeCts.Dispose();
            }
        }

        private bool TryBeginCleanup()
            => Interlocked.Exchange(ref _cleanupStarted, 1) == 0;

        private async Task WaitForResponseLoopCompletionAsync()
        {
            if (_responseLoop is null)
            {
                return;
            }

            await _responseLoop.ConfigureAwait(false);
        }
    }

    private sealed class TrojanMuxInboundUdpSession : ITrojanMuxInboundSession
    {
        private readonly ushort _sessionId;
        private readonly TrojanMuxFrameTarget _target;
        private readonly TrojanMuxInboundWorker _owner;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly SemaphoreSlim _initializeLock = new(1, 1);

        private Task? _responseLoop;
        private IOutboundUdpTransport? _transport;
        private int _disposed;

        public TrojanMuxInboundUdpSession(
            ushort sessionId,
            TrojanMuxFrameTarget target,
            TrojanMuxInboundWorker owner)
        {
            _sessionId = sessionId;
            _target = target;
            _owner = owner;
        }

        public async Task WriteRequestAsync(TrojanMuxFrame frame, CancellationToken cancellationToken)
        {
            if (frame.Payload.Length == 0 || frame.Target is null)
            {
                return;
            }

            var transport = await EnsureTransportAsync(frame, cancellationToken).ConfigureAwait(false);
            await transport.SendAsync(
                frame.Target.ToDispatchDestination(),
                frame.Payload,
                cancellationToken).ConfigureAwait(false);
        }

        public Task CompleteInputAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            if (_transport is not null)
            {
                await _transport.DisposeAsync().ConfigureAwait(false);
            }

            try
            {
                if (_responseLoop is not null)
                {
                    await _responseLoop.ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                _initializeLock.Dispose();
            }

            _disposeCts.Dispose();
        }

        private async Task<IOutboundUdpTransport> EnsureTransportAsync(
            TrojanMuxFrame frame,
            CancellationToken cancellationToken)
        {
            if (_transport is not null)
            {
                return _transport;
            }

            await _initializeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_transport is not null)
                {
                    return _transport;
                }

                var dispatchResult = await _owner
                    .DispatchUdpAsync(
                        frame.Target is null ? frame with { Target = _target } : frame,
                        frame.Payload,
                        _disposeCts.Token)
                    .ConfigureAwait(false);
                var transport = _owner.WrapUdpTransport(dispatchResult.Transport);
                if (_disposeCts.IsCancellationRequested)
                {
                    await transport.DisposeAsync().ConfigureAwait(false);
                    throw new OperationCanceledException(_disposeCts.Token);
                }

                _transport = transport;
                _responseLoop = RunResponseLoopAsync(transport);
                return transport;
            }
            finally
            {
                _initializeLock.Release();
            }
        }

        private async Task RunResponseLoopAsync(IOutboundUdpTransport transport)
        {
            Exception? terminalError = null;

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var datagram = await transport.ReceiveAsync(_disposeCts.Token).ConfigureAwait(false);
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

    private sealed class TrojanMuxInputStream : Stream
    {
        private readonly Channel<byte[]> _chunks = Channel.CreateUnbounded<byte[]>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });

        private byte[]? _currentChunk;
        private int _currentOffset;
        private int _completed;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public ValueTask EnqueueAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
        {
            if (payload.Length == 0)
            {
                return ValueTask.CompletedTask;
            }

            if (Volatile.Read(ref _completed) != 0)
            {
                throw new InvalidOperationException("Mux input stream is already completed.");
            }

            return _chunks.Writer.WriteAsync(payload.ToArray(), cancellationToken);
        }

        public void Complete()
        {
            if (Interlocked.Exchange(ref _completed, 1) == 0)
            {
                _chunks.Writer.TryComplete();
            }
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            while (true)
            {
                if (_currentChunk is not null && _currentOffset < _currentChunk.Length)
                {
                    var copied = Math.Min(buffer.Length, _currentChunk.Length - _currentOffset);
                    _currentChunk.AsMemory(_currentOffset, copied).CopyTo(buffer);
                    _currentOffset += copied;
                    if (_currentOffset >= _currentChunk.Length)
                    {
                        _currentChunk = null;
                        _currentOffset = 0;
                    }

                    return copied;
                }

                if (!await _chunks.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
                {
                    return 0;
                }

                if (_chunks.Reader.TryRead(out var nextChunk))
                {
                    _currentChunk = nextChunk;
                    _currentOffset = 0;
                }
            }
        }

        public override Task<int> ReadAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public override ValueTask DisposeAsync()
        {
            Complete();
            return ValueTask.CompletedTask;
        }
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

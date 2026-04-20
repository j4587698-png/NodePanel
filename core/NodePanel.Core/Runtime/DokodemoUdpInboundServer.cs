using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public sealed class DokodemoUdpInboundServer
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IDokodemoUdpRedirectSupport _redirectSupport;

    public DokodemoUdpInboundServer(
        IDispatcher dispatcher,
        IFakeDnsEngine? fakeDnsEngine = null,
        IDokodemoUdpRedirectSupport? redirectSupport = null)
        : this(
            dispatcher,
            new DefaultRuntimeSniffer(fakeDnsEngine),
            redirectSupport)
    {
    }

    internal DokodemoUdpInboundServer(
        IDispatcher dispatcher,
        IRuntimeSniffer runtimeSniffer,
        IDokodemoUdpRedirectSupport? redirectSupport = null)
    {
        _dispatcher = dispatcher;
        _runtimeSniffer = runtimeSniffer;
        _redirectSupport = redirectSupport ?? new DefaultDokodemoUdpRedirectSupport();
    }

    internal async Task RunAsync(
        DokodemoInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var listeners = options.Plan.Inbounds
            .Where(static inbound => inbound.HasUdp)
            .ToArray();
        if (listeners.Length == 0)
        {
            return;
        }

        var activeListeners = new List<ListenerState>(listeners.Length);
        try
        {
            foreach (var inbound in listeners)
            {
                var socket = CreateSocket(inbound.Binding);
                _redirectSupport.ConfigureListener(socket);
                var localEndPoint = GetRequiredLocalEndPoint(socket);
                DispatchDestination? destination = null;
                if (!inbound.FollowRedirect)
                {
                    var sessionOptions = CreateSessionOptions(
                        inbound,
                        options,
                        remoteEndPoint: null,
                        localEndPoint: localEndPoint,
                        originalDestinationEndPoint: null);
                    destination = DokodemoInboundDestinationResolver.Resolve(sessionOptions);
                }

                var listener = new ListenerState(inbound, socket, localEndPoint, destination, options.Limits);
                activeListeners.Add(listener);

                InboundServerRuntimeSupport.InvokeSafely(
                    options.Callbacks.ListenerStarted,
                    new DokodemoInboundListenerContext
                    {
                        Tag = inbound.Tag,
                        Binding = inbound.Binding,
                        Network = RoutingNetworks.Udp
                    });
            }

            var receiveTasks = activeListeners
                .Select(listener => RunReceiveLoopAsync(listener, options, cancellationToken))
                .ToArray();
            var receiveGroup = Task.WhenAll(receiveTasks);
            var firstLoopCompletion = Task.WhenAny(receiveTasks);
            var stopSignal = InboundServerRuntimeSupport.WaitForCancellationAsync(cancellationToken);
            var completed = await Task.WhenAny(firstLoopCompletion, stopSignal).ConfigureAwait(false);

            foreach (var listener in activeListeners)
            {
                listener.Socket.Dispose();
            }

            try
            {
                await receiveGroup.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }

            if (completed == stopSignal || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (receiveGroup.Exception is not null)
            {
                var exception = receiveGroup.Exception.InnerExceptions.Count == 1
                    ? receiveGroup.Exception.InnerExceptions[0]
                    : receiveGroup.Exception;
                throw exception;
            }

            throw new InvalidOperationException("Dokodemo-door UDP inbound receive loop ended unexpectedly.");
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                listener.Socket.Dispose();
                listener.SendLock.Dispose();
            }
        }
    }

    private async Task RunReceiveLoopAsync(
        ListenerState listener,
        DokodemoInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[65535];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                DokodemoUdpReceiveResult received;
                try
                {
                    received = await _redirectSupport.ReceiveAsync(
                        listener.Socket,
                        buffer.AsMemory(0, buffer.Length),
                        cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var remoteEndPoint = received.RemoteEndPoint;
                if (received.ReceivedBytes == 0)
                {
                    continue;
                }

                SessionState? session = null;
                try
                {
                    session = await ResolveOrCreateSessionAsync(
                        listener,
                        remoteEndPoint,
                        received.LocalEndPoint,
                        received.OriginalDestinationEndPoint,
                        options.SessionPolicies).ConfigureAwait(false);
                    if (session is null || session.LifetimeCts.IsCancellationRequested)
                    {
                        continue;
                    }

                    var transport = await EnsureTransportAsync(
                        listener,
                        session,
                        buffer.AsMemory(0, received.ReceivedBytes),
                        options).ConfigureAwait(false);
                    var destination = session.Destination
                        ?? listener.Destination
                        ?? throw new InvalidOperationException("Dokodemo-door UDP inbound transport destination is not initialized.");
                    await transport.SendAsync(
                        destination,
                        buffer.AsMemory(0, received.ReceivedBytes),
                        session.LifetimeCts.Token).ConfigureAwait(false);

                    session.Touch();
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (OperationCanceledException)
                {
                }
                catch (Exception ex)
                {
                    if (session is not null)
                    {
                        await RemoveSessionAsync(listener, session).ConfigureAwait(false);
                    }

                    InboundServerRuntimeSupport.InvokeSafely(
                        options.Callbacks.ConnectionError,
                        new RuntimeInboundConnectionErrorContext
                        {
                            Exception = ex,
                            RemoteEndPoint = remoteEndPoint
                        });
                }
            }
        }
        finally
        {
            foreach (var session in SnapshotSessions(listener))
            {
                await RemoveSessionAsync(listener, session).ConfigureAwait(false);
            }
        }
    }

    private async ValueTask<SessionState?> ResolveOrCreateSessionAsync(
        ListenerState listener,
        IPEndPoint remoteEndPoint,
        IPEndPoint localEndPoint,
        IPEndPoint? originalDestinationEndPoint,
        RuntimeSessionPolicyCatalog sessionPolicies)
    {
        SessionState? staleSession = null;
        SessionState? resolvedSession = null;
        var resolvedLimits = RuntimeInboundSessionLimitResolver.Resolve(
            listener.Limits,
            sessionPolicies,
            listener.Inbound.UserLevel);

        lock (listener.Sync)
        {
            var key = GetSessionKey(
                remoteEndPoint,
                listener.Inbound.FollowRedirect
                    ? originalDestinationEndPoint ?? localEndPoint
                    : null);
            if (listener.SessionsByKey.TryGetValue(key, out var existing))
            {
                if (!existing.LifetimeCts.IsCancellationRequested)
                {
                    resolvedSession = existing;
                }
                else
                {
                    listener.SessionsByKey.Remove(key);
                    staleSession = existing;
                }
            }

            if (resolvedSession is null)
            {
                resolvedSession = new SessionState(
                    key,
                    remoteEndPoint,
                    localEndPoint,
                    originalDestinationEndPoint,
                    TimeSpan.FromSeconds(resolvedLimits.ConnectionIdleSeconds));
                listener.SessionsByKey[key] = resolvedSession;
            }
        }

        if (staleSession is not null)
        {
            await RemoveSessionAsync(listener, staleSession).ConfigureAwait(false);
        }

        return resolvedSession;
    }

    private async Task<IOutboundUdpTransport> EnsureTransportAsync(
        ListenerState listener,
        SessionState session,
        ReadOnlyMemory<byte> firstPayload,
        DokodemoInboundServerOptions options)
    {
        if (session.Transport is not null)
        {
            return session.Transport;
        }

        await session.InitializeLock.WaitAsync(session.LifetimeCts.Token).ConfigureAwait(false);
        try
        {
            if (session.Transport is not null)
            {
                return session.Transport;
            }

            var sessionOptions = CreateSessionOptions(
                listener.Inbound,
                options,
                session.RemoteEndPoint,
                session.LocalEndPoint,
                session.OriginalDestinationEndPoint);
            var destination = session.Destination ?? listener.Destination;
            if (destination is null)
            {
                if (listener.Inbound.FollowRedirect &&
                    sessionOptions.OriginalDestinationEndPoint is not IPEndPoint)
                {
                    throw new InvalidOperationException(
                        DokodemoInboundErrorMessages.UdpFollowRedirectOriginalDestinationUnavailable);
                }

                destination = DokodemoInboundDestinationResolver.Resolve(sessionOptions);
            }

            var dispatchContext = DokodemoDispatchContextFactory.Create(sessionOptions, destination);
            var dispatchResult = await RuntimeUdpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                sessionOptions.Sniffing,
                firstPayload,
                dispatchContext,
                destination,
                session.LifetimeCts.Token).ConfigureAwait(false);
            var transport = dispatchResult.Transport;
            IDokodemoUdpResponseWriter? responseWriter = null;

            try
            {
                if (listener.Inbound.FollowRedirect)
                {
                    if (sessionOptions.OriginalDestinationEndPoint is not IPEndPoint originalDestinationEndPoint)
                    {
                        throw new InvalidOperationException(
                            DokodemoInboundErrorMessages.UdpFollowRedirectOriginalDestinationUnavailable);
                    }

                    responseWriter = _redirectSupport.CreateResponseWriter(
                        listener.Socket,
                        listener.LocalEndPoint,
                        session.RemoteEndPoint,
                        originalDestinationEndPoint,
                        sessionOptions.Mark);
                }

                if (session.LifetimeCts.IsCancellationRequested)
                {
                    throw new OperationCanceledException(session.LifetimeCts.Token);
                }

                session.Destination = dispatchResult.Destination;
                session.Transport = transport;
                session.ResponseWriter = responseWriter;
            }
            catch
            {
                if (responseWriter is not null)
                {
                    try
                    {
                        await responseWriter.DisposeAsync().ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }

                try
                {
                    await transport.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }

                throw;
            }

            _ = Task.Run(() => RunResponseLoopAsync(listener, session), CancellationToken.None);
            return transport;
        }
        finally
        {
            session.InitializeLock.Release();
        }
    }

    private async Task RunResponseLoopAsync(ListenerState listener, SessionState session)
    {
        var transport = session.Transport;
        if (transport is null)
        {
            return;
        }

        var responseWriter = session.ResponseWriter;
        try
        {
            while (!session.LifetimeCts.IsCancellationRequested)
            {
                var datagram = await transport.ReceiveAsync(session.LifetimeCts.Token).ConfigureAwait(false);
                if (datagram is null)
                {
                    return;
                }

                if (responseWriter is not null)
                {
                    await responseWriter.SendAsync(datagram, session.LifetimeCts.Token).ConfigureAwait(false);
                }
                else
                {
                    await listener.SendLock.WaitAsync(session.LifetimeCts.Token).ConfigureAwait(false);
                    try
                    {
                        await listener.Socket.SendToAsync(
                            datagram.Payload,
                            SocketFlags.None,
                            session.RemoteEndPoint,
                            session.LifetimeCts.Token).ConfigureAwait(false);
                    }
                    finally
                    {
                        listener.SendLock.Release();
                    }
                }

                session.Touch();
            }
        }
        catch (OperationCanceledException) when (session.LifetimeCts.IsCancellationRequested)
        {
        }
        catch
        {
        }
        finally
        {
            await RemoveSessionAsync(listener, session).ConfigureAwait(false);
        }
    }

    private async ValueTask RemoveSessionAsync(ListenerState listener, SessionState session)
    {
        if (Interlocked.Exchange(ref session.Removed, 1) != 0)
        {
            return;
        }

        lock (listener.Sync)
        {
            if (listener.SessionsByKey.TryGetValue(session.Key, out var current) &&
                ReferenceEquals(current, session))
            {
                listener.SessionsByKey.Remove(session.Key);
            }
        }

        session.LifetimeCts.Cancel();

        if (session.Transport is not null)
        {
            try
            {
                await session.Transport.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }

        if (session.ResponseWriter is not null)
        {
            try
            {
                await session.ResponseWriter.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }

        try
        {
            await session.Timer.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        session.InitializeLock.Dispose();
        session.LifetimeCts.Dispose();
    }

    private static IReadOnlyList<SessionState> SnapshotSessions(ListenerState listener)
    {
        lock (listener.Sync)
        {
            return listener.SessionsByKey.Values
                .Distinct()
                .ToArray();
        }
    }

    private static DokodemoInboundSessionOptions CreateSessionOptions(
        DokodemoInboundRuntime inbound,
        DokodemoInboundServerOptions options,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint)
    {
        var limits = RuntimeInboundSessionLimitResolver.Resolve(
            options.Limits,
            options.SessionPolicies,
            inbound.UserLevel);
        return new DokodemoInboundSessionOptions
        {
            InboundTag = inbound.Tag,
            UserLevel = inbound.UserLevel,
            Network = RoutingNetworks.Udp,
            DestinationHost = inbound.DestinationHost,
            DestinationPort = inbound.DestinationPort,
            PortMap = inbound.PortMap,
            Mark = inbound.Mark,
            FollowRedirect = inbound.FollowRedirect,
            HandshakeTimeoutSeconds = limits.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds,
            UseCone = options.UseCone,
            RemoteEndPoint = remoteEndPoint,
            LocalEndPoint = localEndPoint,
            OriginalDestinationEndPoint = inbound.FollowRedirect ? originalDestinationEndPoint : null,
            Sniffing = inbound.Sniffing
        };
    }

    private static Socket CreateSocket(ListenerBinding binding)
    {
        if (binding.IsUnix)
        {
            throw new NotSupportedException("Dokodemo-door UDP inbound does not support UNIX listeners.");
        }

        var listenAddress = IPAddress.Parse(binding.ListenAddress);
        var socket = new Socket(listenAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(listenAddress, binding.Port));
        return socket;
    }

    private static IPEndPoint GetRequiredLocalEndPoint(Socket socket)
        => socket.LocalEndPoint as IPEndPoint
           ?? throw new InvalidOperationException("Dokodemo-door UDP socket is not using an IP endpoint.");

    private static string GetSessionKey(IPEndPoint remoteEndPoint, IPEndPoint? targetEndPoint)
    {
        var key = GetEndPointKey(remoteEndPoint);
        return targetEndPoint is null
            ? key
            : key + "|" + GetEndPointKey(targetEndPoint);
    }

    private static string GetEndPointKey(IPEndPoint endPoint)
    {
        var normalized = endPoint.Address.IsIPv4MappedToIPv6 ? endPoint.Address.MapToIPv4() : endPoint.Address;
        return normalized + ":" + endPoint.Port.ToString();
    }

    private sealed class ListenerState
    {
        public ListenerState(
            DokodemoInboundRuntime inbound,
            Socket socket,
            IPEndPoint localEndPoint,
            DispatchDestination? destination,
            RuntimeTransportLimits limits)
        {
            Inbound = inbound;
            Socket = socket;
            LocalEndPoint = localEndPoint;
            Destination = destination;
            Limits = limits;
        }

        public DokodemoInboundRuntime Inbound { get; }

        public Socket Socket { get; }

        public IPEndPoint LocalEndPoint { get; }

        public DispatchDestination? Destination { get; }

        public RuntimeTransportLimits Limits { get; }

        public Lock Sync { get; } = new();

        public SemaphoreSlim SendLock { get; } = new(1, 1);

        public Dictionary<string, SessionState> SessionsByKey { get; } = new(StringComparer.Ordinal);
    }

    private sealed class SessionState
    {
        public SessionState(
            string key,
            IPEndPoint remoteEndPoint,
            IPEndPoint localEndPoint,
            IPEndPoint? originalDestinationEndPoint,
            TimeSpan idleTimeout)
        {
            Key = key;
            RemoteEndPoint = remoteEndPoint;
            LocalEndPoint = localEndPoint;
            OriginalDestinationEndPoint = originalDestinationEndPoint;
            Timer = ActivityTimer.CancelAfterInactivity(() => LifetimeCts.Cancel(), idleTimeout);
            Timer.Update();
        }

        public string Key { get; }

        public IPEndPoint RemoteEndPoint { get; }

        public IPEndPoint LocalEndPoint { get; }

        public IPEndPoint? OriginalDestinationEndPoint { get; }

        public CancellationTokenSource LifetimeCts { get; } = new();

        public SemaphoreSlim InitializeLock { get; } = new(1, 1);

        public ActivityTimer Timer { get; }

        public DispatchDestination? Destination { get; set; }

        public IOutboundUdpTransport? Transport { get; set; }

        public IDokodemoUdpResponseWriter? ResponseWriter { get; set; }

        public int Removed;

        public void Touch() => Timer.Update();
    }
}

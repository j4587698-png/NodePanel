using System.Net;
using System.Net.Sockets;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class ShadowsocksUdpInboundServer
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeSessionRegistry _sessionRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;

    public ShadowsocksUdpInboundServer(
        IDispatcher dispatcher,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            sessionRegistry,
            rateLimiterRegistry,
            trafficRegistry,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal ShadowsocksUdpInboundServer(
        IDispatcher dispatcher,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _sessionRegistry = sessionRegistry;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task RunAsync(
        ShadowsocksInboundServerOptions options,
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
                var localEndPoint = GetRequiredLocalEndPoint(socket);
                var listener = new ListenerState(inbound, socket, localEndPoint);
                activeListeners.Add(listener);

                InboundServerRuntimeSupport.InvokeSafely(
                    options.Callbacks.ListenerStarted,
                    new ShadowsocksInboundListenerContext
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

            throw new InvalidOperationException("Shadowsocks UDP inbound receive loop ended unexpectedly.");
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
        ShadowsocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[65535];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await listener.Socket.ReceiveFromAsync(
                        buffer.AsMemory(0, buffer.Length),
                        SocketFlags.None,
                        CreateReceivePlaceholder(listener.Socket.AddressFamily),
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

                if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint)
                {
                    continue;
                }

                SessionState? session = null;
                try
                {
                    if (!listener.Inbound.RuntimeState.TryDecodeUdpPacket(
                            buffer.AsSpan(0, received.ReceivedBytes),
                            out var user,
                            out var account,
                            out var packet) ||
                        user is null ||
                        account is null ||
                        packet is null ||
                        packet.Payload.Length == 0)
                    {
                        continue;
                    }

                    session = await ResolveOrCreateSessionAsync(
                        listener,
                        remoteEndPoint,
                        user,
                        account,
                        packet,
                        RuntimeInboundSessionLimitResolver.Resolve(
                            options.Limits,
                            options.SessionPolicies,
                            user.Level).ConnectionIdleSeconds,
                        options.UseCone).ConfigureAwait(false);
                    if (session is null || session.LifetimeCts.IsCancellationRequested)
                    {
                        continue;
                    }

                    var transport = await EnsureTransportAsync(
                        listener,
                        session,
                        packet,
                        options).ConfigureAwait(false);

                    var destination = new DispatchDestination
                    {
                        Host = packet.Host,
                        Port = packet.Port,
                        Network = DispatchNetwork.Udp
                    };

                    var userGate = _rateLimiterRegistry.GetUserGate(user);
                    var globalGate = _rateLimiterRegistry.GlobalGate;
                    var handleFlowLocally = !RuntimeUdpTransportClassifier.IsFlowControlled(transport);
                    if (handleFlowLocally)
                    {
                        await userGate.WaitAsync(packet.Payload.Length, session.LifetimeCts.Token).ConfigureAwait(false);
                        await globalGate.WaitAsync(packet.Payload.Length, session.LifetimeCts.Token).ConfigureAwait(false);
                    }

                    await transport.SendAsync(destination, packet.Payload, session.LifetimeCts.Token).ConfigureAwait(false);

                    session.Touch();
                    if (handleFlowLocally)
                    {
                        _trafficRegistry.RecordUpload(user, packet.Payload.Length);
                    }
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
        ShadowsocksUser user,
        ShadowsocksAccount account,
        ShadowsocksUdpPacket packet,
        int connectionIdleSeconds,
        bool useCone)
    {
        SessionState? staleSession = null;
        SessionState? resolvedSession = null;

        lock (listener.Sync)
        {
            var key = CreateSessionKey(remoteEndPoint, packet, useCone);
            if (listener.SessionsByKey.TryGetValue(key, out var existing))
            {
                if (!existing.LifetimeCts.IsCancellationRequested &&
                    string.Equals(RuntimeUserKeys.Get(existing.User), RuntimeUserKeys.Get(user), StringComparison.Ordinal) &&
                    string.Equals(existing.Account.Cipher, account.Cipher, StringComparison.Ordinal))
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
                var remoteIp = ExtractRemoteIp(remoteEndPoint);
                if (_sessionRegistry.TryOpenSession(RuntimeUserKeys.Get(user), remoteIp, user.DeviceLimit, out var lease) && lease is not null)
                {
                    resolvedSession = new SessionState(
                        key,
                        remoteEndPoint,
                        listener.LocalEndPoint,
                        user,
                        account,
                        lease,
                        TimeSpan.FromSeconds(Math.Max(1, connectionIdleSeconds)));
                    listener.SessionsByKey[key] = resolvedSession;
                }
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
        ShadowsocksUdpPacket packet,
        ShadowsocksInboundServerOptions options)
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

            var sessionOptions = CreateSessionOptions(listener.Inbound, options, session)
                .WithUserLevel(session.User.Level);
            var dispatchDestination = new DispatchDestination
            {
                Host = packet.Host,
                Port = packet.Port,
                Network = DispatchNetwork.Udp
            };
            var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
                ShadowsocksDispatchContextFactory.Create(session.User, sessionOptions),
                dispatchDestination);

            var dispatchResult = await RuntimeUdpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                sessionOptions.Sniffing,
                packet.Payload,
                dispatchContext,
                dispatchDestination,
                session.LifetimeCts.Token).ConfigureAwait(false);
            var transport = RuntimeSniffingUdpTransport.WrapIfNeeded(
                dispatchResult.Transport,
                _runtimeSniffer,
                sessionOptions.Sniffing);

            if (session.LifetimeCts.IsCancellationRequested)
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                throw new OperationCanceledException(session.LifetimeCts.Token);
            }

            session.Transport = transport;
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

        var userGate = _rateLimiterRegistry.GetUserGate(session.User);
        var globalGate = _rateLimiterRegistry.GlobalGate;
        var handleFlowLocally = !RuntimeUdpTransportClassifier.IsFlowControlled(transport);

        try
        {
            while (!session.LifetimeCts.IsCancellationRequested)
            {
                var datagram = await transport.ReceiveAsync(session.LifetimeCts.Token).ConfigureAwait(false);
                if (datagram is null)
                {
                    return;
                }

                if (handleFlowLocally)
                {
                    await userGate.WaitAsync(datagram.Payload.Length, session.LifetimeCts.Token).ConfigureAwait(false);
                    await globalGate.WaitAsync(datagram.Payload.Length, session.LifetimeCts.Token).ConfigureAwait(false);
                }

                var packet = ShadowsocksProtocolCodec.EncodeUdpPacket(
                    session.Account,
                    datagram.SourceHost,
                    datagram.SourcePort,
                    datagram.Payload);

                await listener.SendLock.WaitAsync(session.LifetimeCts.Token).ConfigureAwait(false);
                try
                {
                    await listener.Socket.SendToAsync(
                        packet,
                        SocketFlags.None,
                        session.RemoteEndPoint,
                        session.LifetimeCts.Token).ConfigureAwait(false);
                }
                finally
                {
                    listener.SendLock.Release();
                }

                session.Touch();
                if (handleFlowLocally)
                {
                    _trafficRegistry.RecordDownload(session.User, datagram.Payload.Length);
                }
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

        try
        {
            session.SessionLease.Dispose();
        }
        catch
        {
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

    private static ShadowsocksInboundSessionOptions CreateSessionOptions(
        ShadowsocksInboundRuntime inbound,
        ShadowsocksInboundServerOptions options,
        SessionState session)
        => new()
        {
            RuntimeState = inbound.RuntimeState,
            SessionPolicies = options.SessionPolicies,
            InboundTag = inbound.Tag,
            HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = options.Limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = options.Limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = options.Limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = options.Limits.DownlinkOnlySeconds,
            UseCone = options.UseCone,
            Network = RoutingNetworks.Udp,
            RemoteEndPoint = session.RemoteEndPoint,
            LocalEndPoint = session.LocalEndPoint,
            Sniffing = inbound.Sniffing
        };

    private static Socket CreateSocket(ListenerBinding binding)
    {
        if (binding.IsUnix)
        {
            throw new NotSupportedException("Shadowsocks UDP inbound does not support UNIX listeners.");
        }

        var listenAddress = IPAddress.Parse(binding.ListenAddress);
        var socket = new Socket(listenAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(listenAddress, binding.Port));
        return socket;
    }

    private static IPEndPoint GetRequiredLocalEndPoint(Socket socket)
        => socket.LocalEndPoint as IPEndPoint
           ?? throw new InvalidOperationException("Shadowsocks UDP socket is not using an IP endpoint.");

    private static string CreateSessionKey(
        IPEndPoint remoteEndPoint,
        ShadowsocksUdpPacket packet,
        bool useCone)
    {
        var remoteKey = NormalizeAddress(remoteEndPoint.Address) + ":" + remoteEndPoint.Port.ToString();
        if (useCone)
        {
            return remoteKey;
        }

        return remoteKey + "|" + NormalizeHost(packet.Host) + ":" + packet.Port.ToString();
    }

    private static string NormalizeHost(string host)
        => string.IsNullOrWhiteSpace(host)
            ? string.Empty
            : host.Trim().ToLowerInvariant();

    private static string NormalizeAddress(IPAddress address)
        => (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();

    private static string? ExtractRemoteIp(IPEndPoint remoteEndPoint)
        => NormalizeAddress(remoteEndPoint.Address);

    private static EndPoint CreateReceivePlaceholder(AddressFamily addressFamily)
        => addressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

    private sealed class ListenerState
    {
        public ListenerState(
            ShadowsocksInboundRuntime inbound,
            Socket socket,
            IPEndPoint localEndPoint)
        {
            Inbound = inbound;
            Socket = socket;
            LocalEndPoint = localEndPoint;
        }

        public ShadowsocksInboundRuntime Inbound { get; }

        public Socket Socket { get; }

        public IPEndPoint LocalEndPoint { get; }

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
            ShadowsocksUser user,
            ShadowsocksAccount account,
            IDisposable sessionLease,
            TimeSpan idleTimeout)
        {
            Key = key;
            RemoteEndPoint = remoteEndPoint;
            LocalEndPoint = localEndPoint;
            User = user;
            Account = account;
            SessionLease = sessionLease;
            Timer = ActivityTimer.CancelAfterInactivity(() => LifetimeCts.Cancel(), idleTimeout);
            Timer.Update();
        }

        public string Key { get; }

        public IPEndPoint RemoteEndPoint { get; }

        public IPEndPoint LocalEndPoint { get; }

        public ShadowsocksUser User { get; }

        public ShadowsocksAccount Account { get; }

        public IDisposable SessionLease { get; }

        public CancellationTokenSource LifetimeCts { get; } = new();

        public SemaphoreSlim InitializeLock { get; } = new(1, 1);

        public ActivityTimer Timer { get; }

        public IOutboundUdpTransport? Transport { get; set; }

        public int Removed;

        public void Touch() => Timer.Update();
    }
}

using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

internal sealed class Socks5UdpAssociateRelay : IAsyncDisposable
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly Socket _udpSocket;
    private readonly ProxyInboundConnectionOptions _sessionTemplate;
    private readonly bool _requireAuthorization;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly object _sync = new();
    private readonly HashSet<string> _authorizedIps = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IPEndPoint> _replyEndpointsByIp = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SessionState> _sessionsByRemote = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly Task _receiveLoop;

    private int _disposed;

    public Socks5UdpAssociateRelay(
        IDispatcher dispatcher,
        IRuntimeSniffer runtimeSniffer,
        ListenerBinding binding,
        ProxyInboundConnectionOptions sessionTemplate,
        bool requireAuthorization)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(runtimeSniffer);
        ArgumentNullException.ThrowIfNull(sessionTemplate);

        if (binding.IsUnix)
        {
            throw new NotSupportedException("SOCKS5 UDP associate does not support UNIX listeners.");
        }

        _dispatcher = dispatcher;
        _runtimeSniffer = runtimeSniffer;
        _sessionTemplate = sessionTemplate;
        _requireAuthorization = requireAuthorization;

        var listenAddress = IPAddress.Parse(binding.ListenAddress);
        _udpSocket = new Socket(listenAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _udpSocket.Bind(new IPEndPoint(listenAddress, binding.Port));
        _receiveLoop = RunReceiveLoopAsync();
    }

    public EndPoint LocalEndPoint
        => _udpSocket.LocalEndPoint ?? throw new InvalidOperationException("SOCKS5 UDP socket is not bound.");

    public async Task RelayAsync(
        Stream controlStream,
        ProxyInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(controlStream);
        ArgumentNullException.ThrowIfNull(options);

        ThrowIfDisposed();

        var replyEndPoint = CreateReplyEndPoint(options.LocalEndPoint as IPEndPoint);
        RememberReplyEndPoint(options.RemoteEndPoint as IPEndPoint, replyEndPoint);
        if (_requireAuthorization)
        {
            Authorize(options.RemoteEndPoint as IPEndPoint);
        }

        await Socks5ReplyWriter.WriteAsync(
            controlStream,
            Socks5ProtocolConstants.ReplySucceeded,
            replyEndPoint,
            cancellationToken).ConfigureAwait(false);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        try
        {
            await WaitForControlClosureAsync(controlStream, linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();

        try
        {
            _udpSocket.Dispose();
        }
        catch
        {
        }

        try
        {
            await _receiveLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        finally
        {
            foreach (var session in SnapshotSessions())
            {
                await RemoveSessionAsync(session).ConfigureAwait(false);
            }

            _sendLock.Dispose();
            _disposeCts.Dispose();
        }
    }

    private async Task RunReceiveLoopAsync()
    {
        var buffer = new byte[65535];

        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                SocketReceiveFromResult received;
                try
                {
                    received = await _udpSocket.ReceiveFromAsync(
                        buffer.AsMemory(0, buffer.Length),
                        SocketFlags.None,
                        CreateReceivePlaceholder(_udpSocket.AddressFamily),
                        _disposeCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (SocketException) when (_disposeCts.IsCancellationRequested)
                {
                    break;
                }

                if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint)
                {
                    continue;
                }

                if (_requireAuthorization && !IsAuthorized(remoteEndPoint))
                {
                    continue;
                }

                Socks5UdpPacket packet;
                try
                {
                    packet = Socks5UdpPacketCodec.Decode(buffer.AsSpan(0, received.ReceivedBytes));
                }
                catch (InvalidDataException)
                {
                    continue;
                }

                if (packet.Payload.Length == 0)
                {
                    continue;
                }

                var session = ResolveOrCreateSession(remoteEndPoint);
                if (session is null || session.LifetimeCts.IsCancellationRequested)
                {
                    continue;
                }

                try
                {
                    var transport = await EnsureTransportAsync(session, packet).ConfigureAwait(false);
                    await transport.SendAsync(
                        new DispatchDestination
                        {
                            Host = packet.Host,
                            Port = packet.Port,
                            Network = DispatchNetwork.Udp
                        },
                        packet.Payload,
                        session.LifetimeCts.Token).ConfigureAwait(false);
                    session.Touch();
                }
                catch (OperationCanceledException) when (session.LifetimeCts.IsCancellationRequested || _disposeCts.IsCancellationRequested)
                {
                }
                catch
                {
                    await RemoveSessionAsync(session).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            foreach (var session in SnapshotSessions())
            {
                await RemoveSessionAsync(session).ConfigureAwait(false);
            }
        }
    }

    private async Task<IOutboundUdpTransport> EnsureTransportAsync(
        SessionState session,
        Socks5UdpPacket packet)
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

            var dispatchResult = await RuntimeUdpDispatchPipeline.DispatchAsync(
                    _dispatcher,
                    _runtimeSniffer,
                    _sessionTemplate.Sniffing,
                    packet.Payload,
                    CreateDispatchContext(session, packet),
                    new DispatchDestination
                    {
                        Host = packet.Host,
                        Port = packet.Port,
                        Network = DispatchNetwork.Udp
                    },
                    session.LifetimeCts.Token)
                .ConfigureAwait(false);
            var transport = RuntimeSniffingUdpTransport.WrapIfNeeded(
                dispatchResult.Transport,
                _runtimeSniffer,
                _sessionTemplate.Sniffing);

            if (session.LifetimeCts.IsCancellationRequested || _disposeCts.IsCancellationRequested)
            {
                await transport.DisposeAsync().ConfigureAwait(false);
                throw new OperationCanceledException(session.LifetimeCts.Token);
            }

            session.Transport = transport;
            _ = Task.Run(() => RunResponseLoopAsync(session), CancellationToken.None);
            return transport;
        }
        finally
        {
            session.InitializeLock.Release();
        }
    }

    private async Task RunResponseLoopAsync(SessionState session)
    {
        var transport = session.Transport;
        if (transport is null)
        {
            return;
        }

        try
        {
            while (!session.LifetimeCts.IsCancellationRequested && !_disposeCts.IsCancellationRequested)
            {
                var datagram = await transport.ReceiveAsync(session.LifetimeCts.Token).ConfigureAwait(false);
                if (datagram is null)
                {
                    return;
                }

                var payload = Socks5UdpPacketCodec.Encode(datagram.SourceHost, datagram.SourcePort, datagram.Payload);
                await _sendLock.WaitAsync(session.LifetimeCts.Token).ConfigureAwait(false);
                try
                {
                    await _udpSocket.SendToAsync(
                        payload,
                        SocketFlags.None,
                        session.RemoteEndPoint,
                        session.LifetimeCts.Token).ConfigureAwait(false);
                }
                finally
                {
                    _sendLock.Release();
                }

                session.Touch();
            }
        }
        catch (OperationCanceledException) when (session.LifetimeCts.IsCancellationRequested || _disposeCts.IsCancellationRequested)
        {
        }
        catch
        {
        }
        finally
        {
            await RemoveSessionAsync(session).ConfigureAwait(false);
        }
    }

    private void Authorize(IPEndPoint? remoteEndPoint)
    {
        if (remoteEndPoint is null)
        {
            throw new NotSupportedException("SOCKS5 UDP associate authentication requires an IP-based TCP remote endpoint.");
        }

        lock (_sync)
        {
            _authorizedIps.Add(GetAddressKey(remoteEndPoint.Address));
        }
    }

    private bool IsAuthorized(IPEndPoint remoteEndPoint)
    {
        lock (_sync)
        {
            return _authorizedIps.Contains(GetAddressKey(remoteEndPoint.Address));
        }
    }

    private void RememberReplyEndPoint(IPEndPoint? remoteEndPoint, IPEndPoint replyEndPoint)
    {
        if (remoteEndPoint is null)
        {
            return;
        }

        lock (_sync)
        {
            _replyEndpointsByIp[GetAddressKey(remoteEndPoint.Address)] = replyEndPoint;
        }
    }

    private SessionState? ResolveOrCreateSession(IPEndPoint remoteEndPoint)
    {
        lock (_sync)
        {
            var remoteKey = GetRemoteEndPointKey(remoteEndPoint);
            if (_sessionsByRemote.TryGetValue(remoteKey, out var existingSession))
            {
                if (!existingSession.LifetimeCts.IsCancellationRequested)
                {
                    return existingSession;
                }

                _sessionsByRemote.Remove(remoteKey);
            }

            if (_disposeCts.IsCancellationRequested)
            {
                return null;
            }

            var replyEndPoint = ResolveReplyEndPoint(remoteEndPoint.Address);
            var session = new SessionState(
                remoteEndPoint,
                replyEndPoint,
                TimeSpan.FromSeconds(_sessionTemplate.ConnectionIdleSeconds));
            _sessionsByRemote[remoteKey] = session;
            return session;
        }
    }

    private async ValueTask RemoveSessionAsync(SessionState session)
    {
        if (Interlocked.Exchange(ref session.Removed, 1) != 0)
        {
            return;
        }

        lock (_sync)
        {
            var remoteKey = GetRemoteEndPointKey(session.RemoteEndPoint);
            if (_sessionsByRemote.TryGetValue(remoteKey, out var current) &&
                ReferenceEquals(current, session))
            {
                _sessionsByRemote.Remove(remoteKey);
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
            await session.Timer.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        session.LifetimeCts.Dispose();
    }

    private IReadOnlyList<SessionState> SnapshotSessions()
    {
        lock (_sync)
        {
            return _sessionsByRemote.Values
                .Distinct()
                .ToArray();
        }
    }

    private DispatchContext CreateDispatchContext(
        SessionState session,
        Socks5UdpPacket packet)
        => RuntimeInboundDispatchContextFactory.Create(
            ProxyInboundProtocols.Socks,
            _sessionTemplate,
            RoutingNetworks.Udp,
            userId: _sessionTemplate.UserId,
            scopedUserId: _sessionTemplate.ScopedUserId,
            network: RoutingNetworks.Udp,
            originalDestinationHost: packet.Host,
            originalDestinationPort: packet.Port,
            sourceEndPoint: session.RemoteEndPoint,
            localEndPoint: session.ReplyEndPoint);

    private IPEndPoint ResolveReplyEndPoint(IPAddress sourceAddress)
    {
        var key = GetAddressKey(sourceAddress);
        if (_replyEndpointsByIp.TryGetValue(key, out var replyEndPoint))
        {
            return replyEndPoint;
        }

        return CreateReplyEndPoint(tcpLocalEndPoint: null);
    }

    private IPEndPoint CreateReplyEndPoint(IPEndPoint? tcpLocalEndPoint)
    {
        if (LocalEndPoint is not IPEndPoint udpLocalEndPoint)
        {
            throw new InvalidOperationException("SOCKS5 UDP socket is not using an IP endpoint.");
        }

        if (tcpLocalEndPoint is not null)
        {
            return new IPEndPoint(tcpLocalEndPoint.Address, udpLocalEndPoint.Port);
        }

        return udpLocalEndPoint;
    }

    private static string GetAddressKey(IPAddress address)
    {
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return normalized.ToString();
    }

    private static string GetRemoteEndPointKey(IPEndPoint endPoint)
    {
        var normalized = endPoint.Address.IsIPv4MappedToIPv6 ? endPoint.Address.MapToIPv4() : endPoint.Address;
        return normalized + ":" + endPoint.Port.ToString();
    }

    private static EndPoint CreateReceivePlaceholder(AddressFamily addressFamily)
        => addressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

    private static async Task WaitForControlClosureAsync(Stream controlStream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        while (!cancellationToken.IsCancellationRequested)
        {
            var read = await controlStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return;
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(Socks5UdpAssociateRelay));
        }
    }

    private sealed class SessionState
    {
        public SessionState(
            IPEndPoint remoteEndPoint,
            IPEndPoint replyEndPoint,
            TimeSpan idleTimeout)
        {
            RemoteEndPoint = remoteEndPoint;
            ReplyEndPoint = replyEndPoint;
            Timer = ActivityTimer.CancelAfterInactivity(() => LifetimeCts.Cancel(), idleTimeout);
            Timer.Update();
        }

        public IPEndPoint RemoteEndPoint { get; }

        public IPEndPoint ReplyEndPoint { get; }

        public CancellationTokenSource LifetimeCts { get; } = new();

        public SemaphoreSlim InitializeLock { get; } = new(1, 1);

        public ActivityTimer Timer { get; }

        public IOutboundUdpTransport? Transport { get; set; }

        public int Removed;

        public void Touch() => Timer.Update();
    }
}

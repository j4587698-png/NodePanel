using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

internal static class RuntimeKcpInboundServer
{
    public static async Task RunAsync<TListener>(
        IReadOnlyList<TListener> listeners,
        Action<TListener>? onListenerStarted,
        Func<TListener, ListenerBinding> bindingSelector,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, AcceptedConnection, CancellationToken, Task> connectionHandler,
        string unexpectedStopMessage,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(bindingSelector);
        ArgumentNullException.ThrowIfNull(connectionHandler);
        ArgumentException.ThrowIfNullOrWhiteSpace(unexpectedStopMessage);

        var activeListeners = new List<ListenerState<TListener>>(listeners.Count);
        try
        {
            foreach (var listener in listeners)
            {
                var socket = CreateSocket(bindingSelector(listener));
                var localEndPoint = GetRequiredLocalEndPoint(socket);
                activeListeners.Add(new ListenerState<TListener>(listener, socket, localEndPoint));
                InboundServerRuntimeSupport.InvokeSafely(onListenerStarted, listener);
            }

            var receiveTasks = activeListeners
                .Select(listener => RunReceiveLoopAsync(
                    listener,
                    onConnectionError,
                    connectionHandler,
                    cancellationToken))
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

            throw new InvalidOperationException(unexpectedStopMessage);
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                listener.Socket.Dispose();
            }
        }
    }

    private static async Task RunReceiveLoopAsync<TListener>(
        ListenerState<TListener> listener,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, AcceptedConnection, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];

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

                if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint ||
                    received.ReceivedBytes <= 0)
                {
                    continue;
                }

                if (!RuntimeKcpPacketReader.TryReadAny(
                        buffer.AsSpan(0, received.ReceivedBytes),
                        out var segments,
                        out var wireFormat))
                {
                    continue;
                }

                var sessionKey = CreateSessionKey(remoteEndPoint, segments[0].Conversation);
                var created = false;
                if (!listener.Sessions.TryGetValue(sessionKey, out var session))
                {
                    var candidate = CreateSession(listener, remoteEndPoint, segments[0].Conversation, wireFormat);
                    if (listener.Sessions.TryAdd(sessionKey, candidate))
                    {
                        session = candidate;
                        created = true;
                    }
                    else
                    {
                        await candidate.Connection.DisposeAsync().ConfigureAwait(false);
                        if (!listener.Sessions.TryGetValue(sessionKey, out session))
                        {
                            continue;
                        }
                    }
                }

                if (!session.Connection.AcceptsWireFormat(wireFormat))
                {
                    continue;
                }

                try
                {
                    session.Connection.InputSegments(segments, wireFormat);
                }
                catch (Exception ex)
                {
                    if (listener.Sessions.TryRemove(sessionKey, out var stale))
                    {
                        await stale.Connection.DisposeAsync().ConfigureAwait(false);
                    }

                    InboundServerRuntimeSupport.InvokeSafely(
                        onConnectionError,
                        new RuntimeInboundConnectionErrorContext
                        {
                            Exception = ex,
                            RemoteEndPoint = remoteEndPoint
                        });
                    continue;
                }

                if (created)
                {
                    _ = Task.Run(
                        () => HandleAcceptedConnectionAsync(
                            listener,
                            sessionKey,
                            session,
                            onConnectionError,
                            connectionHandler,
                            cancellationToken),
                        CancellationToken.None);
                }
            }
        }
        finally
        {
            foreach (var session in listener.Sessions.Values)
            {
                await session.Connection.DisposeAsync().ConfigureAwait(false);
            }

            listener.Sessions.Clear();
        }
    }

    private static async Task HandleAcceptedConnectionAsync<TListener>(
        ListenerState<TListener> listener,
        string sessionKey,
        SessionState session,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, AcceptedConnection, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        var acceptedConnection = AcceptedConnection.FromStream(
            session.Connection,
            session.RemoteEndPoint,
            listener.LocalEndPoint);

        try
        {
            await connectionHandler(listener.Definition, acceptedConnection, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            InboundServerRuntimeSupport.InvokeSafely(
                onConnectionError,
                new RuntimeInboundConnectionErrorContext
                {
                    Exception = ex,
                    RemoteEndPoint = session.RemoteEndPoint
                });
        }
        finally
        {
            listener.Sessions.TryRemove(sessionKey, out _);
            await acceptedConnection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static SessionState CreateSession<TListener>(
        ListenerState<TListener> listener,
        IPEndPoint remoteEndPoint,
        ushort conversation,
        RuntimeKcpWireFormat wireFormat)
        => new(
            remoteEndPoint,
            new RuntimeKcpConnection(
                conversation,
                payload =>
                {
                    lock (listener.SendSync)
                    {
                        listener.Socket.SendTo(payload, remoteEndPoint);
                    }
                },
                wireFormat));

    private static Socket CreateSocket(ListenerBinding binding)
    {
        if (binding.IsUnix)
        {
            throw new NotSupportedException("mKCP inbound does not support UNIX listeners.");
        }

        var listenAddress = IPAddress.Parse(binding.ListenAddress);
        var socket = new Socket(listenAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(listenAddress, binding.Port));
        return socket;
    }

    private static IPEndPoint GetRequiredLocalEndPoint(Socket socket)
        => socket.LocalEndPoint as IPEndPoint
           ?? throw new InvalidOperationException("mKCP inbound socket is not using an IP endpoint.");

    private static EndPoint CreateReceivePlaceholder(AddressFamily addressFamily)
        => addressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

    private static string CreateSessionKey(IPEndPoint remoteEndPoint, ushort conversation)
        => NormalizeAddress(remoteEndPoint.Address) +
           "|" +
           remoteEndPoint.Port.ToString() +
           "|" +
           conversation.ToString();

    private static string NormalizeAddress(IPAddress address)
        => (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();

    private sealed record ListenerState<TListener>(
        TListener Definition,
        Socket Socket,
        IPEndPoint LocalEndPoint)
    {
        public object SendSync { get; } = new();

        public ConcurrentDictionary<string, SessionState> Sessions { get; } = new(StringComparer.Ordinal);
    }

    private sealed record SessionState(
        IPEndPoint RemoteEndPoint,
        RuntimeKcpConnection Connection);
}

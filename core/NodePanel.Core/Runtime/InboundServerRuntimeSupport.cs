#pragma warning disable CA1416
using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Runtime;

internal static class InboundServerRuntimeSupport
{
    private static readonly ConditionalWeakTable<RuntimeSplitHttpInboundOptions, RuntimeSplitHttpInboundBridge> SplitHttpInboundBridgeCache = new();

    public static Task RunTlsServerAsync<TListener>(
        IReadOnlyList<TListener> listeners,
        RuntimeTlsOptions tlsOptions,
        Action<TListener>? onListenerStarted,
        Func<TListener, ListenerBinding> bindingSelector,
        Func<TListener, bool> acceptProxyProtocolSelector,
        Func<TListener, bool> receiveOriginalDestinationSelector,
        Func<TListener, IReadOnlyList<string>> applicationProtocolsSelector,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, TlsAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        string unexpectedStopMessage,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(tlsOptions);
        ArgumentNullException.ThrowIfNull(bindingSelector);
        ArgumentNullException.ThrowIfNull(acceptProxyProtocolSelector);
        ArgumentNullException.ThrowIfNull(receiveOriginalDestinationSelector);
        ArgumentNullException.ThrowIfNull(applicationProtocolsSelector);
        ArgumentNullException.ThrowIfNull(connectionHandler);
        ArgumentException.ThrowIfNullOrWhiteSpace(unexpectedStopMessage);

        return RunAsync(
            listeners,
            bindingSelector,
            onListenerStarted,
            (listener, handle, token) => AcceptLoopAsync(
                listener,
                handle,
                (connection, definition, innerToken) => HandleAcceptedTlsConnectionAsync(
                    connection,
                    definition,
                    tlsOptions,
                    acceptProxyProtocolSelector,
                    receiveOriginalDestinationSelector,
                    applicationProtocolsSelector,
                    onClientHelloRejected,
                    onUnknownServerNameRejected,
                    onConnectionError,
                    connectionHandler,
                    innerToken),
                token),
            unexpectedStopMessage,
            cancellationToken);
    }

    public static Task RunRealityServerAsync<TListener>(
        IReadOnlyList<TListener> listeners,
        RuntimeRealityServerOptions realityOptions,
        Action<TListener>? onListenerStarted,
        Func<TListener, ListenerBinding> bindingSelector,
        Func<TListener, bool> acceptProxyProtocolSelector,
        Func<TListener, bool> receiveOriginalDestinationSelector,
        Func<TListener, IReadOnlyList<string>> applicationProtocolsSelector,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, TlsAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        string unexpectedStopMessage,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(realityOptions);
        ArgumentNullException.ThrowIfNull(bindingSelector);
        ArgumentNullException.ThrowIfNull(acceptProxyProtocolSelector);
        ArgumentNullException.ThrowIfNull(receiveOriginalDestinationSelector);
        ArgumentNullException.ThrowIfNull(applicationProtocolsSelector);
        ArgumentNullException.ThrowIfNull(connectionHandler);
        ArgumentException.ThrowIfNullOrWhiteSpace(unexpectedStopMessage);

        return RunAsync(
            listeners,
            bindingSelector,
            onListenerStarted,
            (listener, handle, token) => AcceptLoopAsync(
                listener,
                handle,
                (connection, definition, innerToken) => HandleAcceptedRealityConnectionAsync(
                    connection,
                    definition,
                    realityOptions,
                    acceptProxyProtocolSelector,
                    receiveOriginalDestinationSelector,
                    applicationProtocolsSelector,
                    onClientHelloRejected,
                    onUnknownServerNameRejected,
                    onConnectionError,
                    connectionHandler,
                    innerToken),
                token),
            unexpectedStopMessage,
            cancellationToken);
    }

    public static async Task RunQuicTlsServerAsync<TListener>(
        IReadOnlyList<TListener> listeners,
        RuntimeTlsOptions tlsOptions,
        Action<TListener>? onListenerStarted,
        Func<TListener, ListenerBinding> bindingSelector,
        Func<TListener, IReadOnlyList<string>> applicationProtocolsSelector,
        Func<TListener, RuntimeQuicOptions> quicOptionsSelector,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, QuicAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        string unexpectedStopMessage,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(tlsOptions);
        ArgumentNullException.ThrowIfNull(bindingSelector);
        ArgumentNullException.ThrowIfNull(applicationProtocolsSelector);
        ArgumentNullException.ThrowIfNull(quicOptionsSelector);
        ArgumentNullException.ThrowIfNull(connectionHandler);
        ArgumentException.ThrowIfNullOrWhiteSpace(unexpectedStopMessage);

        if (tlsOptions.ClientHelloPolicy.Enabled)
        {
            throw new NotSupportedException("QUIC inbound currently does not support TLS client hello policy filtering.");
        }

        var activeListeners = new List<QuicListenerRuntime<TListener>>(listeners.Count);
        try
        {
            foreach (var listener in listeners)
            {
                var handle = await CreateQuicListenerAsync(
                        bindingSelector(listener),
                        applicationProtocolsSelector(listener),
                        tlsOptions,
                        quicOptionsSelector(listener),
                        onUnknownServerNameRejected,
                        cancellationToken)
                    .ConfigureAwait(false);
                activeListeners.Add(new QuicListenerRuntime<TListener>(listener, handle));
                InvokeSafely(onListenerStarted, listener);
            }

            var acceptTasks = activeListeners
                .Select(listener => AcceptQuicLoopAsync(
                    listener.Definition,
                    listener.Handle,
                    onConnectionError,
                    connectionHandler,
                    cancellationToken))
                .ToArray();
            var acceptGroup = Task.WhenAll(acceptTasks);
            var firstLoopCompletion = Task.WhenAny(acceptTasks);
            var stopSignal = WaitForCancellationAsync(cancellationToken);
            var completed = await Task.WhenAny(firstLoopCompletion, stopSignal).ConfigureAwait(false);

            foreach (var listener in activeListeners)
            {
                await listener.Handle.DisposeAsync().ConfigureAwait(false);
            }

            try
            {
                await acceptGroup.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }

            if (completed == stopSignal || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (acceptGroup.Exception is not null)
            {
                var exception = acceptGroup.Exception.InnerExceptions.Count == 1
                    ? acceptGroup.Exception.InnerExceptions[0]
                    : acceptGroup.Exception;
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new InvalidOperationException(unexpectedStopMessage);
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                await listener.Handle.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    public static async Task RunAsync<TListener>(
        IReadOnlyList<TListener> listeners,
        Func<TListener, ListenerBinding> bindingSelector,
        Action<TListener>? onListenerStarted,
        Func<TListener, ListenerHandle, CancellationToken, Task> acceptLoopFactory,
        string unexpectedStopMessage,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        ArgumentNullException.ThrowIfNull(bindingSelector);
        ArgumentNullException.ThrowIfNull(acceptLoopFactory);

        var activeListeners = new List<ListenerRuntime<TListener>>(listeners.Count);
        try
        {
            foreach (var listener in listeners)
            {
                var handle = ListenerHandle.Create(bindingSelector(listener));
                activeListeners.Add(new ListenerRuntime<TListener>(listener, handle));
                InvokeSafely(onListenerStarted, listener);
            }

            var acceptTasks = activeListeners
                .Select(listener => acceptLoopFactory(listener.Definition, listener.Handle, cancellationToken))
                .ToArray();
            var acceptGroup = Task.WhenAll(acceptTasks);
            var firstLoopCompletion = Task.WhenAny(acceptTasks);
            var stopSignal = WaitForCancellationAsync(cancellationToken);
            var completed = await Task.WhenAny(firstLoopCompletion, stopSignal).ConfigureAwait(false);

            foreach (var listener in activeListeners)
            {
                listener.Handle.Stop();
            }

            try
            {
                await acceptGroup.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }

            if (completed == stopSignal || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (acceptGroup.Exception is not null)
            {
                var exception = acceptGroup.Exception.InnerExceptions.Count == 1
                    ? acceptGroup.Exception.InnerExceptions[0]
                    : acceptGroup.Exception;
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new InvalidOperationException(unexpectedStopMessage);
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                listener.Handle.Dispose();
            }
        }
    }

    public static async Task AcceptLoopAsync<TListener>(
        TListener listener,
        ListenerHandle handle,
        Func<AcceptedConnection, TListener, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(connectionHandler);

        while (!cancellationToken.IsCancellationRequested)
        {
            AcceptedConnection connection;
            try
            {
                connection = await handle.AcceptAsync(cancellationToken).ConfigureAwait(false);
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

            _ = Task.Run(
                () => connectionHandler(connection, listener, cancellationToken),
                CancellationToken.None);
        }
    }

    public static async Task<(Stream Stream, TInbound Inbound)> ResolveTlsInboundAsync<TListener, TInbound>(
        Stream stream,
        TListener listener,
        Func<TListener, IReadOnlyList<TInbound>> inboundsSelector,
        Func<TListener, byte[], TInbound?> sharedInboundSelector,
        string missingInboundMessage,
        string sharedSelectionErrorMessage,
        CancellationToken cancellationToken)
        where TInbound : class
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(inboundsSelector);
        ArgumentNullException.ThrowIfNull(sharedInboundSelector);
        ArgumentException.ThrowIfNullOrWhiteSpace(missingInboundMessage);
        ArgumentException.ThrowIfNullOrWhiteSpace(sharedSelectionErrorMessage);

        var inbounds = inboundsSelector(listener);
        if (inbounds.Count == 0)
        {
            throw new InvalidOperationException(missingInboundMessage);
        }

        if (inbounds.Count == 1)
        {
            return (stream, inbounds[0]);
        }

        var initialPayload = await ReadInitialPayloadAsync(stream, cancellationToken).ConfigureAwait(false);
        var prefixedStream = new PrefixedReadStream(stream, initialPayload);
        var selectedInbound = sharedInboundSelector(listener, initialPayload)
            ?? throw new InvalidOperationException(sharedSelectionErrorMessage);
        return (prefixedStream, selectedInbound);
    }

    public static async Task HandleTransportAsync<TInbound>(
        Stream stream,
        TInbound inbound,
        Func<TInbound, InboundInternetStack> internetStackSelector,
        Func<TInbound, string> hostSelector,
        Func<TInbound, string> pathSelector,
        Func<TInbound, int> earlyDataBytesSelector,
        Func<TInbound, int> heartbeatPeriodSecondsSelector,
        Func<TInbound, RuntimeGrpcTransportOptions> grpcOptionsSelector,
        Func<TInbound, RuntimeSplitHttpInboundOptions> splitHttpOptionsSelector,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken,
        Action<Exception>? onGrpcHandlerError = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(inbound);
        ArgumentNullException.ThrowIfNull(internetStackSelector);
        ArgumentNullException.ThrowIfNull(hostSelector);
        ArgumentNullException.ThrowIfNull(pathSelector);
        ArgumentNullException.ThrowIfNull(earlyDataBytesSelector);
        ArgumentNullException.ThrowIfNull(heartbeatPeriodSecondsSelector);
        ArgumentNullException.ThrowIfNull(grpcOptionsSelector);
        ArgumentNullException.ThrowIfNull(splitHttpOptionsSelector);
        ArgumentNullException.ThrowIfNull(handler);

        var internetStack = internetStackSelector(inbound);
        if (string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.Grpc, StringComparison.Ordinal))
        {
            await Http2GrpcTunnelServer
                .ServeAsync(
                    stream,
                    grpcOptionsSelector(inbound),
                    handler,
                    onGrpcHandlerError,
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        if (string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal))
        {
            await using var webSocketStream = await WebSocketServerHandshake.AcceptAsync(
                stream,
                new WebSocketServerHandshakeOptions
                {
                    Host = hostSelector(inbound),
                    Path = pathSelector(inbound),
                    EarlyDataBytes = earlyDataBytesSelector(inbound),
                    HeartbeatPeriodSeconds = heartbeatPeriodSecondsSelector(inbound)
                },
                cancellationToken).ConfigureAwait(false);

            await handler(webSocketStream, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.HttpUpgrade, StringComparison.Ordinal))
        {
            await using var upgradedStream = await HttpUpgradeServerHandshake.AcceptAsync(
                stream,
                new HttpUpgradeServerHandshakeOptions
                {
                    Host = hostSelector(inbound),
                    Path = pathSelector(inbound)
                },
                cancellationToken).ConfigureAwait(false);

            await handler(upgradedStream, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.SplitHttp, StringComparison.Ordinal))
        {
            var bridge = SplitHttpInboundBridgeCache.GetValue(
                splitHttpOptionsSelector(inbound),
                static options => new RuntimeSplitHttpInboundBridge(options));
            await bridge.ServeAsync(stream, handler, cancellationToken).ConfigureAwait(false);
            return;
        }

        await handler(stream, cancellationToken).ConfigureAwait(false);
    }

    public static async Task HandleQuicTransportAsync<TInbound>(
        QuicConnection connection,
        TInbound inbound,
        Func<TInbound, InboundInternetStack> internetStackSelector,
        Func<TInbound, IReadOnlyList<string>> applicationProtocolsSelector,
        Func<TInbound, RuntimeSplitHttpInboundOptions> splitHttpOptionsSelector,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(inbound);
        ArgumentNullException.ThrowIfNull(internetStackSelector);
        ArgumentNullException.ThrowIfNull(applicationProtocolsSelector);
        ArgumentNullException.ThrowIfNull(splitHttpOptionsSelector);
        ArgumentNullException.ThrowIfNull(handler);

        var internetStack = internetStackSelector(inbound);
        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.SplitHttp, StringComparison.Ordinal) ||
            !RuntimeSplitHttpInboundPlanning.IsHttp3Only(applicationProtocolsSelector(inbound)))
        {
            throw new NotSupportedException(
                $"QUIC inbound transport currently only supports SplitHTTP h3-only, but '{internetStack.TransportProtocol}' was configured.");
        }

        var bridge = SplitHttpInboundBridgeCache.GetValue(
            splitHttpOptionsSelector(inbound),
            static options => new RuntimeSplitHttpInboundBridge(options));
        await bridge.ServeHttp3Async(connection, handler, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReadInitialPayloadAsync(
        Stream stream,
        CancellationToken cancellationToken,
        int minimumBytes = 64)
    {
        var normalizedMinimumBytes = Math.Max(1, minimumBytes);
        var buffer = new byte[4096];
        var read = 0;

        while (read < normalizedMinimumBytes)
        {
            var current = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                break;
            }

            read += current;
            if (read == buffer.Length)
            {
                break;
            }
        }

        return read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
    }

    public static Task WaitForCancellationAsync(CancellationToken cancellationToken)
        => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    public static async Task ObserveCancellationAsync(Task task, CancellationToken cancellationToken)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    public static void InvokeSafely<TContext>(Action<TContext>? callback, TContext context)
    {
        if (callback is null)
        {
            return;
        }

        try
        {
            callback(context);
        }
        catch
        {
        }
    }

    private static async Task AcceptQuicLoopAsync<TListener>(
        TListener listener,
        QuicListenerHandle handle,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, QuicAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            QuicConnection connection;
            try
            {
                connection = await handle.Listener.AcceptConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (AuthenticationException)
            {
                continue;
            }
            catch (QuicException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (QuicException ex)
            {
                InvokeSafely(
                    onConnectionError,
                    new RuntimeInboundConnectionErrorContext
                    {
                        Exception = ex,
                        RemoteEndPoint = null
                    });
                continue;
            }

            var serverName = handle.ServerNames.TryRemove(connection, out var resolvedServerName)
                ? resolvedServerName
                : string.Empty;
            _ = Task.Run(
                () => HandleAcceptedQuicConnectionAsync(
                    connection,
                    serverName,
                    listener,
                    onConnectionError,
                    connectionHandler,
                    cancellationToken),
                CancellationToken.None);
        }
    }

    private static async Task HandleAcceptedQuicConnectionAsync<TListener>(
        QuicConnection connection,
        string serverName,
        TListener listener,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, QuicAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        var errorRemoteEndPoint = connection.RemoteEndPoint;

        try
        {
            await connectionHandler(
                    listener,
                    new QuicAcceptedConnectionContext
                    {
                        Connection = connection,
                        RemoteEndPoint = connection.RemoteEndPoint,
                        LocalEndPoint = connection.LocalEndPoint,
                        ServerName = serverName,
                        NegotiatedAlpn = connection.NegotiatedApplicationProtocol.ToString(),
                        NegotiatedSslProtocol = connection.SslProtocol
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            InvokeSafely(
                onConnectionError,
                new RuntimeInboundConnectionErrorContext
                {
                    Exception = ex,
                    RemoteEndPoint = errorRemoteEndPoint
                });
        }
    }

    private static async Task<QuicListenerHandle> CreateQuicListenerAsync(
        ListenerBinding binding,
        IReadOnlyList<string> applicationProtocols,
        RuntimeTlsOptions tlsOptions,
        RuntimeQuicOptions quicOptions,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(applicationProtocols);
        ArgumentNullException.ThrowIfNull(tlsOptions);
        ArgumentNullException.ThrowIfNull(quicOptions);

        if (binding.IsUnix)
        {
            throw new NotSupportedException("QUIC inbound does not support UNIX domain socket bindings.");
        }

        var listenEndPoint = new IPEndPoint(IPAddress.Parse(binding.ListenAddress), binding.Port);
        var serverNames = new ConcurrentDictionary<QuicConnection, string>();
        var sslApplicationProtocols = applicationProtocols
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => new SslApplicationProtocol(value))
            .ToList();
        if (sslApplicationProtocols.Count == 0)
        {
            throw new InvalidOperationException("QUIC inbound requires at least one ALPN value.");
        }

        var listener = await QuicListener.ListenAsync(
                new QuicListenerOptions
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = sslApplicationProtocols,
                    ConnectionOptionsCallback = (connection, clientHello, _) =>
                    {
                        var requestedServerName = clientHello.ServerName ?? string.Empty;
                        if (RuntimeTlsServerNamePolicy.ShouldReject(
                                tlsOptions.ServerNamePolicy,
                                tlsOptions.Certificate,
                                requestedServerName))
                        {
                            InvokeSafely(
                                onUnknownServerNameRejected,
                                new RuntimeTlsServerNameRejectionContext
                                {
                                    RemoteEndPoint = connection.RemoteEndPoint,
                                    RequestedServerName = requestedServerName
                                });
                            return ValueTask.FromException<QuicServerConnectionOptions>(
                                new AuthenticationException("QUIC client requested an unknown server name."));
                        }

                        serverNames[connection] = requestedServerName;
                        return ValueTask.FromResult(
                            RuntimeQuicServerConnectionOptionsFactory.Create(
                                applicationProtocols,
                                tlsOptions,
                                quicOptions));
                    }
                },
                cancellationToken)
            .ConfigureAwait(false);

        return new QuicListenerHandle(listener, serverNames);
    }

    private static async Task HandleAcceptedTlsConnectionAsync<TListener>(
        AcceptedConnection connection,
        TListener listener,
        RuntimeTlsOptions tlsOptions,
        Func<TListener, bool> acceptProxyProtocolSelector,
        Func<TListener, bool> receiveOriginalDestinationSelector,
        Func<TListener, IReadOnlyList<string>> applicationProtocolsSelector,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, TlsAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(tlsOptions);
        ArgumentNullException.ThrowIfNull(acceptProxyProtocolSelector);
        ArgumentNullException.ThrowIfNull(receiveOriginalDestinationSelector);
        ArgumentNullException.ThrowIfNull(applicationProtocolsSelector);
        ArgumentNullException.ThrowIfNull(connectionHandler);

        await using var connectionLease = connection;
        var errorRemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint;

        try
        {
            var tlsConnection = await TlsInboundConnectionAcceptor.AcceptAsync(
                connection,
                tlsOptions,
                acceptProxyProtocolSelector(listener),
                receiveOriginalDestinationSelector(listener),
                applicationProtocolsSelector(listener),
                onClientHelloRejected,
                onUnknownServerNameRejected,
                remoteEndPoint => errorRemoteEndPoint = connection.LogRemoteEndPoint ?? remoteEndPoint,
                cancellationToken).ConfigureAwait(false);
            if (tlsConnection is null)
            {
                return;
            }

            await using var authenticatedConnection = tlsConnection;
            await connectionHandler(listener, authenticatedConnection, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            InvokeSafely(
                onConnectionError,
                new RuntimeInboundConnectionErrorContext
                {
                    Exception = ex,
                    RemoteEndPoint = errorRemoteEndPoint
                });
        }
    }

    private static async Task HandleAcceptedRealityConnectionAsync<TListener>(
        AcceptedConnection connection,
        TListener listener,
        RuntimeRealityServerOptions realityOptions,
        Func<TListener, bool> acceptProxyProtocolSelector,
        Func<TListener, bool> receiveOriginalDestinationSelector,
        Func<TListener, IReadOnlyList<string>> applicationProtocolsSelector,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<RuntimeInboundConnectionErrorContext>? onConnectionError,
        Func<TListener, TlsAcceptedConnectionContext, CancellationToken, Task> connectionHandler,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(realityOptions);
        ArgumentNullException.ThrowIfNull(acceptProxyProtocolSelector);
        ArgumentNullException.ThrowIfNull(receiveOriginalDestinationSelector);
        ArgumentNullException.ThrowIfNull(applicationProtocolsSelector);
        ArgumentNullException.ThrowIfNull(connectionHandler);

        await using var connectionLease = connection;
        var errorRemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint;

        try
        {
            var realityConnection = await RealityInboundConnectionAcceptor.AcceptAsync(
                connection,
                realityOptions,
                acceptProxyProtocolSelector(listener),
                receiveOriginalDestinationSelector(listener),
                applicationProtocolsSelector(listener),
                onClientHelloRejected,
                onUnknownServerNameRejected,
                remoteEndPoint => errorRemoteEndPoint = connection.LogRemoteEndPoint ?? remoteEndPoint,
                cancellationToken).ConfigureAwait(false);
            if (realityConnection is null)
            {
                return;
            }

            await using var authenticatedConnection = realityConnection;
            await connectionHandler(listener, authenticatedConnection, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            InvokeSafely(
                onConnectionError,
                new RuntimeInboundConnectionErrorContext
                {
                    Exception = ex,
                    RemoteEndPoint = errorRemoteEndPoint
                });
        }
    }

    private sealed record ListenerRuntime<TListener>(TListener Definition, ListenerHandle Handle);

    private sealed record QuicListenerRuntime<TListener>(TListener Definition, QuicListenerHandle Handle);

    private sealed class QuicListenerHandle : IAsyncDisposable
    {
        private int _disposed;

        public QuicListenerHandle(
            QuicListener listener,
            ConcurrentDictionary<QuicConnection, string> serverNames)
        {
            Listener = listener ?? throw new ArgumentNullException(nameof(listener));
            ServerNames = serverNames ?? throw new ArgumentNullException(nameof(serverNames));
        }

        public QuicListener Listener { get; }

        public ConcurrentDictionary<QuicConnection, string> ServerNames { get; }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await Listener.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }

            ServerNames.Clear();
        }
    }
}

#pragma warning restore CA1416

internal sealed class TlsAcceptedConnectionContext : IAsyncDisposable
{
    public required Stream Stream { get; init; }

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public IPEndPoint? OriginalDestinationEndPoint { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public string NegotiatedAlpn { get; init; } = string.Empty;

    public SslProtocols NegotiatedSslProtocol { get; init; } = SslProtocols.None;

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}

internal sealed class QuicAcceptedConnectionContext
{
    public required QuicConnection Connection { get; init; }

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public string NegotiatedAlpn { get; init; } = string.Empty;

    public SslProtocols NegotiatedSslProtocol { get; init; } = SslProtocols.None;
}

internal sealed record PreparedAcceptedConnectionContext
{
    public required Stream Stream { get; init; }

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public IPEndPoint? OriginalDestinationEndPoint { get; init; }
}

internal static class PlainInboundConnectionAcceptor
{
    public static async Task<TlsAcceptedConnectionContext> AcceptAsync(
        AcceptedConnection connection,
        bool acceptProxyProtocol,
        bool receiveOriginalDestination,
        Action<EndPoint?>? onEffectiveRemoteEndPointChanged,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var preparedConnection = await AcceptedInboundConnectionPreprocessor
            .PrepareAsync(
                connection,
                acceptProxyProtocol,
                receiveOriginalDestination,
                onEffectiveRemoteEndPointChanged,
                cancellationToken)
            .ConfigureAwait(false);

        return new TlsAcceptedConnectionContext
        {
            Stream = preparedConnection.Stream,
            RemoteEndPoint = preparedConnection.RemoteEndPoint,
            LocalEndPoint = preparedConnection.LocalEndPoint,
            OriginalDestinationEndPoint = preparedConnection.OriginalDestinationEndPoint,
            ServerName = string.Empty,
            NegotiatedAlpn = string.Empty,
            NegotiatedSslProtocol = SslProtocols.None
        };
    }
}

internal static class AcceptedInboundConnectionPreprocessor
{
    public static async Task<PreparedAcceptedConnectionContext> PrepareAsync(
        AcceptedConnection connection,
        bool acceptProxyProtocol,
        bool receiveOriginalDestination,
        Action<EndPoint?>? onEffectiveRemoteEndPointChanged,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var networkStream = connection.Stream;
        var effectiveRemoteEndPoint = connection.RemoteEndPoint;
        var effectiveLocalEndPoint = connection.LocalEndPoint;
        IPEndPoint? originalDestinationEndPoint = null;

        if (receiveOriginalDestination &&
            OriginalTcpDestinationResolver.TryResolve(connection.Socket, out var resolvedOriginalDestination))
        {
            originalDestinationEndPoint = resolvedOriginalDestination;
        }

        if (acceptProxyProtocol)
        {
            var proxyHeader = await ProxyProtocolReader.ReadAsync(networkStream, cancellationToken).ConfigureAwait(false);
            effectiveRemoteEndPoint = proxyHeader.RemoteEndPoint;
            effectiveLocalEndPoint = proxyHeader.LocalEndPoint;
            onEffectiveRemoteEndPointChanged?.Invoke(effectiveRemoteEndPoint);
        }

        return new PreparedAcceptedConnectionContext
        {
            Stream = networkStream,
            RemoteEndPoint = effectiveRemoteEndPoint,
            LocalEndPoint = effectiveLocalEndPoint,
            OriginalDestinationEndPoint = originalDestinationEndPoint
        };
    }
}

internal static class TlsInboundConnectionAcceptor
{

    public static async Task<TlsAcceptedConnectionContext?> AcceptAsync(
        AcceptedConnection connection,
        RuntimeTlsOptions tlsOptions,
        bool acceptProxyProtocol,
        bool receiveOriginalDestination,
        IReadOnlyList<string> applicationProtocols,
        Action<RuntimeTlsClientHelloRejectionContext>? onClientHelloRejected,
        Action<RuntimeTlsServerNameRejectionContext>? onUnknownServerNameRejected,
        Action<EndPoint?>? onEffectiveRemoteEndPointChanged,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(tlsOptions);
        ArgumentNullException.ThrowIfNull(applicationProtocols);

        var preparedConnection = await AcceptedInboundConnectionPreprocessor
            .PrepareAsync(
                connection,
                acceptProxyProtocol,
                receiveOriginalDestination,
                onEffectiveRemoteEndPointChanged,
                cancellationToken)
            .ConfigureAwait(false);

        Stream tlsTransportStream = preparedConnection.Stream;
        if (tlsOptions.ClientHelloPolicy.Enabled)
        {
            var handshakePayload = await RuntimeTlsClientHelloReader.ReadAsync(tlsTransportStream, cancellationToken).ConfigureAwait(false);
            if (handshakePayload.Length == 0)
            {
                return null;
            }

            RuntimeTlsClientHelloMetadata? clientHelloMetadata = null;
            if (RuntimeTlsClientHelloParser.TryParse(handshakePayload, out var parsedMetadata))
            {
                clientHelloMetadata = parsedMetadata;
            }

            if (RuntimeTlsClientHelloPolicyEvaluator.ShouldReject(
                    tlsOptions.ClientHelloPolicy,
                    clientHelloMetadata,
                    out var decision))
            {
                InboundServerRuntimeSupport.InvokeSafely(
                    onClientHelloRejected,
                    new RuntimeTlsClientHelloRejectionContext
                    {
                        RemoteEndPoint = connection.LogRemoteEndPoint ?? preparedConnection.RemoteEndPoint,
                        Metadata = clientHelloMetadata,
                        Reason = decision.Reason
                    });
                return null;
            }

            tlsTransportStream = new PrefixedReadStream(tlsTransportStream, handshakePayload);
        }

        var sslStream = new SslStream(tlsTransportStream, leaveInnerStreamOpen: false);
        try
        {
            await sslStream.AuthenticateAsServerAsync(
                BuildAuthenticationOptions(applicationProtocols, tlsOptions),
                cancellationToken).ConfigureAwait(false);

            var serverName = sslStream.TargetHostName ?? string.Empty;
            if (RuntimeTlsServerNamePolicy.ShouldReject(
                    tlsOptions.ServerNamePolicy,
                    tlsOptions.Certificate,
                    serverName))
            {
                InboundServerRuntimeSupport.InvokeSafely(
                    onUnknownServerNameRejected,
                    new RuntimeTlsServerNameRejectionContext
                    {
                        RemoteEndPoint = connection.LogRemoteEndPoint ?? preparedConnection.RemoteEndPoint,
                        RequestedServerName = serverName
                    });

                await sslStream.DisposeAsync().ConfigureAwait(false);
                return null;
            }

            return new TlsAcceptedConnectionContext
            {
                Stream = sslStream,
                RemoteEndPoint = preparedConnection.RemoteEndPoint,
                LocalEndPoint = preparedConnection.LocalEndPoint,
                OriginalDestinationEndPoint = preparedConnection.OriginalDestinationEndPoint,
                ServerName = serverName,
                NegotiatedAlpn = Encoding.ASCII.GetString(sslStream.NegotiatedApplicationProtocol.Protocol.Span),
                NegotiatedSslProtocol = sslStream.SslProtocol
            };
        }
        catch
        {
            await sslStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal static SslServerAuthenticationOptions BuildAuthenticationOptions(
        IReadOnlyList<string> applicationProtocols,
        RuntimeTlsOptions tlsOptions)
    {
        var serverCertificate = RuntimeTlsServerCertificateSelector.GetServerCertificate(tlsOptions.Certificate);
        var options = new SslServerAuthenticationOptions
        {
            ServerCertificate = serverCertificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            AllowTlsResume = tlsOptions.EnableTlsSessionResumption,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ClientCertificateRequired = false
        };

        TryAttachServerCertificateContext(options, serverCertificate);

        if (applicationProtocols.Count > 0)
        {
            options.ApplicationProtocols = applicationProtocols
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => new SslApplicationProtocol(value))
                .ToList();
        }

        return options;
    }

    private static void TryAttachServerCertificateContext(
        SslServerAuthenticationOptions authenticationOptions,
        X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(authenticationOptions);
        ArgumentNullException.ThrowIfNull(certificate);

        try
        {
            authenticationOptions.ServerCertificateContext = SslStreamCertificateContext.Create(
                certificate,
                additionalCertificates: [],
                offline: true);
        }
        catch (CryptographicException)
        {
        }
        catch (NotSupportedException)
        {
        }
    }
}

using System.Net;
using System.Security.Authentication;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Runtime;

public sealed class VlessInboundServer
{
    private readonly VlessInboundConnectionHandler _vlessInboundConnectionHandler;

    public VlessInboundServer(VlessInboundConnectionHandler vlessInboundConnectionHandler)
    {
        _vlessInboundConnectionHandler = vlessInboundConnectionHandler;
    }

    public async Task RunAsync(VlessInboundServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var quicTlsListeners = options.Plan.TlsListeners
            .Where(static listener => RuntimeSplitHttpInboundPlanning.IsHttp3Only(listener.ApplicationProtocols))
            .ToArray();
        var tlsListeners = options.Plan.TlsListeners
            .Where(static listener => !RuntimeSplitHttpInboundPlanning.IsHttp3Only(listener.ApplicationProtocols))
            .ToArray();
        var realityListeners = options.Plan.RealityListeners;
        var plainListeners = options.Plan.PlainListeners.ToArray();
        var mkcpListeners = plainListeners
            .Where(static listener => listener.MkcpInbound is not null)
            .ToArray();
        plainListeners = plainListeners
            .Where(static listener => listener.MkcpInbound is null)
            .ToArray();
        if (realityListeners.Any(static listener => RuntimeSplitHttpInboundPlanning.IsHttp3Only(listener.ApplicationProtocols)))
        {
            throw new NotSupportedException("VLESS SplitHTTP h3-only inbound currently only supports TLS security and cannot run on REALITY listeners.");
        }

        if (tlsListeners.Length == 0 &&
            quicTlsListeners.Length == 0 &&
            realityListeners.Count == 0 &&
            plainListeners.Length == 0 &&
            mkcpListeners.Length == 0)
        {
            return;
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = new List<Task>(capacity: 4);
        if (plainListeners.Length > 0)
        {
            tasks.Add(RunPlainAsync(options, plainListeners, linkedCts.Token));
        }

        if (mkcpListeners.Length > 0)
        {
            tasks.Add(RunMkcpAsync(options, mkcpListeners, linkedCts.Token));
        }

        if (tlsListeners.Length > 0)
        {
            var tlsOptions = options.Tls ?? throw new InvalidOperationException("VLESS inbound server requires TLS options when TLS listeners are configured.");
            tasks.Add(RunTlsAsync(options, tlsListeners, tlsOptions, linkedCts.Token));
        }

        if (quicTlsListeners.Length > 0)
        {
            var tlsOptions = options.Tls ?? throw new InvalidOperationException("VLESS inbound server requires TLS options when QUIC TLS listeners are configured.");
            tasks.Add(RunQuicTlsAsync(options, quicTlsListeners, tlsOptions, linkedCts.Token));
        }

        if (realityListeners.Count > 0)
        {
            var realityOptions = options.Reality ?? throw new InvalidOperationException("VLESS inbound server requires REALITY options when REALITY listeners are configured.");
            tasks.Add(RunRealityAsync(options, realityOptions, linkedCts.Token));
        }

        var taskArray = tasks.ToArray();
        try
        {
            await Task.WhenAny(taskArray).ConfigureAwait(false);
            linkedCts.Cancel();
            await Task.WhenAll(taskArray.Select(task => InboundServerRuntimeSupport.ObserveCancellationAsync(task, linkedCts.Token))).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private Task RunTlsAsync(
        VlessInboundServerOptions options,
        IReadOnlyList<VlessTlsListenerRuntime> listeners,
        RuntimeTlsOptions tlsOptions,
        CancellationToken cancellationToken)
        => InboundServerRuntimeSupport.RunTlsServerAsync(
            listeners,
            tlsOptions,
            options.Callbacks.ListenerStarted,
            static listener => listener.Binding,
            static listener => listener.AcceptProxyProtocol,
            static listener => listener.Inbounds.Any(static inbound => inbound.ReceiveOriginalDestination),
            static listener => listener.ApplicationProtocols,
            options.Callbacks.ClientHelloRejected,
            options.Callbacks.UnknownServerNameRejected,
            options.Callbacks.ConnectionError,
            (listener, acceptedConnection, token) => HandleAcceptedConnectionAsync(
                options,
                listener,
                acceptedConnection,
                token),
            "VLESS inbound accept loop ended unexpectedly.",
            cancellationToken);

    private Task RunQuicTlsAsync(
        VlessInboundServerOptions options,
        IReadOnlyList<VlessTlsListenerRuntime> listeners,
        RuntimeTlsOptions tlsOptions,
        CancellationToken cancellationToken)
    {
        ValidateQuicListeners(listeners);
        return InboundServerRuntimeSupport.RunQuicTlsServerAsync(
            listeners,
            tlsOptions,
            options.Callbacks.ListenerStarted,
            static listener => listener.Binding,
            static listener => listener.ApplicationProtocols,
            static listener => listener.SplitHttpInbound!.QuicOptions,
            options.Callbacks.UnknownServerNameRejected,
            options.Callbacks.ConnectionError,
            (listener, acceptedConnection, token) => HandleQuicConnectionAsync(
                options,
                listener,
                acceptedConnection,
                token),
            "VLESS QUIC inbound accept loop ended unexpectedly.",
            cancellationToken);
    }

    private Task RunPlainAsync(
        VlessInboundServerOptions options,
        IReadOnlyList<VlessTlsListenerRuntime> listeners,
        CancellationToken cancellationToken)
        => InboundServerRuntimeSupport.RunAsync(
            listeners,
            static listener => listener.Binding,
            options.Callbacks.ListenerStarted,
            (listener, handle, token) => InboundServerRuntimeSupport.AcceptLoopAsync(
                listener,
                handle,
                (connection, definition, innerToken) => HandleAcceptedPlainConnectionAsync(connection, definition, options, innerToken),
                token),
            "VLESS inbound accept loop ended unexpectedly.",
            cancellationToken);

    private Task RunMkcpAsync(
        VlessInboundServerOptions options,
        IReadOnlyList<VlessTlsListenerRuntime> listeners,
        CancellationToken cancellationToken)
        => RuntimeKcpInboundServer.RunAsync(
            listeners,
            options.Callbacks.ListenerStarted,
            static listener => listener.Binding,
            options.Callbacks.ConnectionError,
            (listener, connection, token) => HandleAcceptedMkcpConnectionAsync(
                options,
                listener,
                connection,
                token),
            "VLESS mKCP inbound receive loop ended unexpectedly.",
            cancellationToken);

    private Task RunRealityAsync(
        VlessInboundServerOptions options,
        RuntimeRealityServerOptions realityOptions,
        CancellationToken cancellationToken)
        => InboundServerRuntimeSupport.RunRealityServerAsync(
            options.Plan.RealityListeners,
            realityOptions,
            options.Callbacks.ListenerStarted,
            static listener => listener.Binding,
            static listener => listener.AcceptProxyProtocol,
            static listener => listener.Inbounds.Any(static inbound => inbound.ReceiveOriginalDestination),
            static listener => listener.ApplicationProtocols,
            options.Callbacks.ClientHelloRejected,
            options.Callbacks.UnknownServerNameRejected,
            options.Callbacks.ConnectionError,
            (listener, acceptedConnection, token) => HandleAcceptedConnectionAsync(
                options,
                listener,
                acceptedConnection,
                token),
            "VLESS inbound accept loop ended unexpectedly.",
            cancellationToken);

    private async Task HandleAcceptedPlainConnectionAsync(
        AcceptedConnection connection,
        VlessTlsListenerRuntime listener,
        VlessInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        var errorRemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint;

        try
        {
            var acceptedConnection = await PlainInboundConnectionAcceptor.AcceptAsync(
                    connection,
                    listener.AcceptProxyProtocol,
                    listener.Inbounds.Any(static inbound => inbound.ReceiveOriginalDestination),
                    remoteEndPoint => errorRemoteEndPoint = connection.LogRemoteEndPoint ?? remoteEndPoint,
                    cancellationToken)
                .ConfigureAwait(false);
            await using var acceptedConnectionLease = acceptedConnection;
            errorRemoteEndPoint = acceptedConnection.RemoteEndPoint;

            await HandleAcceptedConnectionAsync(
                options,
                listener,
                acceptedConnection,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            InboundServerRuntimeSupport.InvokeSafely(
                options.Callbacks.ConnectionError,
                new RuntimeInboundConnectionErrorContext
                {
                    Exception = ex,
                    RemoteEndPoint = errorRemoteEndPoint
                });
        }
    }

    private async Task HandleAcceptedConnectionAsync(
        VlessInboundServerOptions options,
        VlessTlsListenerRuntime listener,
        TlsAcceptedConnectionContext acceptedConnection,
        CancellationToken cancellationToken)
    {
        var (stream, inboundSelection) = await InboundServerRuntimeSupport.ResolveTlsInboundAsync(
                acceptedConnection.Stream,
                listener,
                static current => current.Inbounds,
                static (current, payload) => VlessInboundRuntimePlanner.SelectInbound(current, payload),
                "VLESS listener has no inbound definition.",
                "VLESS shared listener could not resolve an inbound transport.",
                cancellationToken)
            .ConfigureAwait(false);

        await HandleResolvedInboundAsync(
            stream,
            options,
            inboundSelection,
            acceptedConnection.ServerName,
            acceptedConnection.NegotiatedAlpn,
            acceptedConnection.NegotiatedSslProtocol,
            acceptedConnection.RemoteEndPoint,
            acceptedConnection.LocalEndPoint,
            acceptedConnection.OriginalDestinationEndPoint,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleAcceptedMkcpConnectionAsync(
        VlessInboundServerOptions options,
        VlessTlsListenerRuntime listener,
        AcceptedConnection connection,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        var inbound = listener.MkcpInbound
                      ?? throw new InvalidOperationException("VLESS mKCP listener is missing its mKCP inbound definition.");

        await HandleResolvedInboundAsync(
            connection.Stream,
            options,
            inbound,
            serverName: string.Empty,
            alpn: string.Empty,
            outerTlsProtocol: SslProtocols.None,
            connection.RemoteEndPoint,
            connection.LocalEndPoint,
            originalDestinationEndPoint: null,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleResolvedInboundAsync(
        Stream stream,
        VlessInboundServerOptions options,
        VlessTlsInboundRuntime inbound,
        string serverName,
        string alpn,
        SslProtocols outerTlsProtocol,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint,
        CancellationToken cancellationToken)
    {
        var sessionOptions = RuntimeTlsInboundSessionOptionsFactory.Create(
            options,
            inbound,
            serverName,
            alpn,
            outerTlsProtocol,
            remoteEndPoint,
            localEndPoint,
            originalDestinationEndPoint);
        await InboundServerRuntimeSupport.HandleTransportAsync(
            stream,
            inbound,
            static current => current.InternetStack,
            static current => current.Host,
            static current => current.Path,
            static current => current.EarlyDataBytes,
            static current => current.HeartbeatPeriodSeconds,
            static current => current.Grpc,
            static current => current.SplitHttp,
            (transportStream, token) => _vlessInboundConnectionHandler.HandleAsync(
                transportStream,
                sessionOptions,
                token),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleQuicConnectionAsync(
        VlessInboundServerOptions options,
        VlessTlsListenerRuntime listener,
        QuicAcceptedConnectionContext acceptedConnection,
        CancellationToken cancellationToken)
    {
        var inbound = listener.SplitHttpInbound
            ?? throw new InvalidOperationException("VLESS QUIC listener requires a SplitHTTP inbound definition.");

        var sessionOptions = RuntimeTlsInboundSessionOptionsFactory.Create(
            options,
            inbound,
            acceptedConnection.ServerName,
            acceptedConnection.NegotiatedAlpn,
            acceptedConnection.NegotiatedSslProtocol,
            acceptedConnection.RemoteEndPoint,
            acceptedConnection.LocalEndPoint,
            originalDestinationEndPoint: null);
        await InboundServerRuntimeSupport.HandleQuicTransportAsync(
            acceptedConnection.Connection,
            inbound,
            static current => current.InternetStack,
            static current => current.ApplicationProtocols,
            static current => current.SplitHttp,
            (transportStream, token) => _vlessInboundConnectionHandler.HandleAsync(
                transportStream,
                sessionOptions,
                token),
            cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateQuicListeners(IReadOnlyList<VlessTlsListenerRuntime> listeners)
    {
        if (listeners.Any(static listener =>
                listener.AcceptProxyProtocol ||
                listener.Inbounds.Any(static inbound => inbound.ReceiveOriginalDestination)))
        {
            throw new NotSupportedException("VLESS QUIC SplitHTTP inbound does not support PROXY protocol or original destination recovery.");
        }
    }
}

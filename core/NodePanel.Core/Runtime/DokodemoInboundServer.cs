using System.Net;

namespace NodePanel.Core.Runtime;

public sealed class DokodemoInboundServer
{
    private readonly DokodemoInboundConnectionHandler _connectionHandler;
    private readonly DokodemoUdpInboundServer _udpInboundServer;

    public DokodemoInboundServer(
        DokodemoInboundConnectionHandler connectionHandler,
        DokodemoUdpInboundServer udpInboundServer)
    {
        _connectionHandler = connectionHandler;
        _udpInboundServer = udpInboundServer;
    }

    public async Task RunAsync(
        DokodemoInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Plan.Inbounds.Count == 0)
        {
            return;
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = new List<Task>(capacity: 2);
        if (options.Plan.Inbounds.Any(static inbound => inbound.HasTcp))
        {
            tasks.Add(RunTcpAsync(options, linkedCts.Token));
        }

        if (options.Plan.Inbounds.Any(static inbound => inbound.HasUdp))
        {
            tasks.Add(_udpInboundServer.RunAsync(options, linkedCts.Token));
        }

        if (tasks.Count == 0)
        {
            return;
        }

        var taskArray = tasks.ToArray();
        try
        {
            await Task.WhenAny(taskArray).ConfigureAwait(false);
            linkedCts.Cancel();
            await Task.WhenAll(taskArray.Select(task => ObserveCancellationAsync(task, linkedCts.Token))).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private Task RunTcpAsync(
        DokodemoInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        var listeners = options.Plan.Inbounds
            .Where(static inbound => inbound.HasTcp)
            .ToArray();
        if (listeners.Length == 0)
        {
            return Task.CompletedTask;
        }

        return InboundServerRuntimeSupport.RunAsync(
            listeners,
            static inbound => inbound.Binding,
            inbound => InboundServerRuntimeSupport.InvokeSafely(
                options.Callbacks.ListenerStarted,
                new DokodemoInboundListenerContext
                {
                    Tag = inbound.Tag,
                    Binding = inbound.Binding,
                    Network = RoutingNetworks.Tcp
                }),
            (listener, handle, token) => InboundServerRuntimeSupport.AcceptLoopAsync(
                listener,
                handle,
                (connection, definition, innerToken) => HandleAcceptedConnectionAsync(connection, definition, options, innerToken),
                token),
            "Dokodemo-door inbound accept loop ended unexpectedly.",
            cancellationToken);
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        DokodemoInboundRuntime inbound,
        DokodemoInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        var errorRemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint;

        try
        {
            IPEndPoint? originalDestinationEndPoint = null;
            if (inbound.FollowRedirect &&
                OriginalTcpDestinationResolver.TryResolve(connection.Socket, out var resolvedOriginalDestination))
            {
                originalDestinationEndPoint = resolvedOriginalDestination;
            }

            await _connectionHandler
                .HandleAsync(
                    connection.Stream,
                    CreateSessionOptions(
                        inbound,
                        options,
                        connection.RemoteEndPoint,
                        connection.LocalEndPoint,
                        originalDestinationEndPoint),
                    cancellationToken)
                .ConfigureAwait(false);
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
            Network = RoutingNetworks.Tcp,
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

    private static async Task ObserveCancellationAsync(Task task, CancellationToken cancellationToken)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }
}

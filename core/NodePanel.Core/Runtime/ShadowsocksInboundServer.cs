using System.Net;

namespace NodePanel.Core.Runtime;

public sealed class ShadowsocksInboundServer
{
    private readonly ShadowsocksInboundConnectionHandler _connectionHandler;
    private readonly Shadowsocks2022InboundServer _inbound2022Server;
    private readonly ShadowsocksUdpInboundServer _udpInboundServer;

    public ShadowsocksInboundServer(
        ShadowsocksInboundConnectionHandler connectionHandler,
        Shadowsocks2022InboundServer inbound2022Server,
        ShadowsocksUdpInboundServer udpInboundServer)
    {
        _connectionHandler = connectionHandler;
        _inbound2022Server = inbound2022Server;
        _udpInboundServer = udpInboundServer;
    }

    public async Task RunAsync(
        ShadowsocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = new List<Task>(capacity: 3);
        if (options.Plan.Inbounds.Any(static inbound => inbound.HasTcp))
        {
            tasks.Add(RunTcpAsync(options, linkedCts.Token));
        }

        if (options.Plan.Inbounds.Any(static inbound => inbound.HasUdp))
        {
            tasks.Add(_udpInboundServer.RunAsync(options, linkedCts.Token));
        }

        if (options.Plan.Inbounds2022.Count > 0)
        {
            tasks.Add(_inbound2022Server.RunAsync(options, linkedCts.Token));
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
        ShadowsocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        var listeners = options.Plan.Inbounds
            .Where(static inbound => inbound.HasTcp)
            .ToArray();

        return InboundServerRuntimeSupport.RunAsync(
            listeners,
            static inbound => inbound.Binding,
            inbound => InboundServerRuntimeSupport.InvokeSafely(
                options.Callbacks.ListenerStarted,
                new ShadowsocksInboundListenerContext
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
            "Shadowsocks inbound accept loop ended unexpectedly.",
            cancellationToken);
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        ShadowsocksInboundRuntime inbound,
        ShadowsocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        var errorRemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint;

        try
        {
            await _connectionHandler.HandleAsync(
                connection.Stream,
                CreateSessionOptions(inbound, options, connection.RemoteEndPoint, connection.LocalEndPoint),
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

    private static ShadowsocksInboundSessionOptions CreateSessionOptions(
        ShadowsocksInboundRuntime inbound,
        ShadowsocksInboundServerOptions options,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint)
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
            Network = RoutingNetworks.Tcp,
            RemoteEndPoint = remoteEndPoint,
            LocalEndPoint = localEndPoint,
            Sniffing = inbound.Sniffing
        };

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

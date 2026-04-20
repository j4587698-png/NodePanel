using System.Net;

namespace NodePanel.Core.Runtime;

public sealed class Shadowsocks2022InboundServer
{
    private readonly Shadowsocks2022InboundConnectionHandler _connectionHandler;
    private readonly Shadowsocks2022UdpInboundServer _udpInboundServer;

    public Shadowsocks2022InboundServer(
        Shadowsocks2022InboundConnectionHandler connectionHandler,
        Shadowsocks2022UdpInboundServer udpInboundServer)
    {
        _connectionHandler = connectionHandler;
        _udpInboundServer = udpInboundServer;
    }

    internal async Task RunAsync(
        ShadowsocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var hasTcp = options.Plan.Inbounds2022.Any(static inbound => inbound.HasTcp);
        var hasUdp = options.Plan.Inbounds2022.Any(static inbound => inbound.HasUdp);
        if (!hasTcp && !hasUdp)
        {
            return;
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var tasks = new List<Task>(capacity: 2);
        if (hasTcp)
        {
            tasks.Add(RunTcpAsync(options, linkedCts.Token));
        }

        if (hasUdp)
        {
            tasks.Add(_udpInboundServer.RunAsync(options, linkedCts.Token));
        }

        await RunGroupAsync(tasks.ToArray(), linkedCts, cancellationToken).ConfigureAwait(false);
    }

    private Task RunTcpAsync(
        ShadowsocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        var listeners = options.Plan.Inbounds2022
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
            "Shadowsocks 2022 inbound accept loop ended unexpectedly.",
            cancellationToken);
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        Shadowsocks2022InboundRuntime inbound,
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

    private static Shadowsocks2022InboundSessionOptions CreateSessionOptions(
        Shadowsocks2022InboundRuntime inbound,
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

    private static async Task RunGroupAsync(
        IReadOnlyList<Task> tasks,
        CancellationTokenSource linkedCts,
        CancellationToken cancellationToken)
    {
        if (tasks.Count == 0)
        {
            return;
        }

        try
        {
            await Task.WhenAny(tasks).ConfigureAwait(false);
            linkedCts.Cancel();
            await Task.WhenAll(tasks.Select(task => ObserveCancellationAsync(task, linkedCts.Token))).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
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

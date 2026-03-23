namespace NodePanel.Core.Runtime;

public sealed class DefaultDispatcher : IDispatcher
{
    private readonly IOutboundRouter _outboundRouter;

    public DefaultDispatcher(IOutboundRouter outboundRouter)
    {
        _outboundRouter = outboundRouter;
    }

    public ValueTask<Stream> DispatchTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var routedContext = context with
        {
            Network = RoutingNetworks.Tcp,
            OriginalDestinationHost = string.IsNullOrWhiteSpace(context.OriginalDestinationHost)
                ? destination.Host
                : context.OriginalDestinationHost,
            OriginalDestinationPort = context.OriginalDestinationPort > 0
                ? context.OriginalDestinationPort
                : destination.Port
        };

        return _outboundRouter.Resolve(routedContext, destination).OpenTcpAsync(routedContext, destination, cancellationToken);
    }

    public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var routedContext = context with
        {
            Network = RoutingNetworks.Udp
        };

        return _outboundRouter.Resolve(routedContext, destination: null).OpenUdpAsync(routedContext, cancellationToken);
    }
}

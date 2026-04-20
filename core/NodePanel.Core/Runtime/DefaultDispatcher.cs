namespace NodePanel.Core.Runtime;

public sealed class DefaultDispatcher : IDispatcher, IRuntimeInboundTcpDispatcher, IRuntimeInboundUdpDispatcher
{
    private readonly IOutboundRouter _outboundRouter;
    private readonly IRuntimeRateLimiterRegistry? _rateLimiterRegistry;
    private readonly IRuntimeSniffer? _runtimeSniffer;
    private readonly IRuntimeTrafficRegistry? _trafficRegistry;

    public DefaultDispatcher(IOutboundRouter outboundRouter)
        : this(outboundRouter, rateLimiterRegistry: null, trafficRegistry: null, runtimeSniffer: null)
    {
    }

    public DefaultDispatcher(
        IOutboundRouter outboundRouter,
        IRuntimeRateLimiterRegistry? rateLimiterRegistry,
        IRuntimeTrafficRegistry? trafficRegistry)
        : this(outboundRouter, rateLimiterRegistry, trafficRegistry, runtimeSniffer: null)
    {
    }

    internal DefaultDispatcher(
        IOutboundRouter outboundRouter,
        IRuntimeRateLimiterRegistry? rateLimiterRegistry,
        IRuntimeTrafficRegistry? trafficRegistry,
        IRuntimeSniffer? runtimeSniffer)
    {
        _outboundRouter = outboundRouter;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    public ValueTask<Stream> DispatchTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var routedContext = CreateTcpRoutedContext(context, destination);
        var resolved = _outboundRouter.Resolve(routedContext, destination);
        return DispatchTcpCoreAsync(resolved, destination, cancellationToken);
    }

    async ValueTask<RuntimeTcpDispatchResult> IRuntimeInboundTcpDispatcher.DispatchInboundTcpAsync(
        IRuntimeSniffingDefinition sniffing,
        Stream inboundStream,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken sniffCancellationToken,
        CancellationToken dispatchCancellationToken,
        bool allowDestinationOverride)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(inboundStream);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        var relayStream = inboundStream;
        if (sniffing.Enabled)
        {
            var sniffer = _runtimeSniffer ?? new DefaultRuntimeSniffer();
            var sniffResult = await sniffer
                .CreateTcpSession(
                    sniffing,
                    context,
                    destination,
                    allowDestinationOverride)
                .RunAsync(relayStream, sniffCancellationToken)
                .ConfigureAwait(false);
            relayStream = sniffResult.Stream;
            context = sniffResult.Context;
            destination = sniffResult.Destination;
        }

        var outboundStream = await DispatchTcpAsync(
            context,
            destination,
            dispatchCancellationToken).ConfigureAwait(false);

        return new RuntimeTcpDispatchResult(
            context,
            destination,
            relayStream,
            outboundStream);
    }

    async ValueTask<RuntimeUdpDispatchResult> IRuntimeInboundUdpDispatcher.DispatchInboundUdpAsync(
        IRuntimeSniffingDefinition sniffing,
        ReadOnlyMemory<byte> firstPayload,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken,
        bool allowDestinationOverride)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        if (sniffing.Enabled)
        {
            var sniffer = _runtimeSniffer ?? new DefaultRuntimeSniffer();
            var sniffResult = sniffer.SniffUdp(
                sniffing,
                firstPayload.Span,
                destination,
                context,
                allowDestinationOverride);
            destination = sniffResult.Destination;
            context = sniffResult.Context ?? context;
        }

        var transport = await DispatchUdpAsync(context, cancellationToken).ConfigureAwait(false);
        return new RuntimeUdpDispatchResult(
            context,
            destination,
            transport);
    }

    public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var routedContext = context with
        {
            Network = RoutingNetworks.Udp,
            TargetHost = string.IsNullOrWhiteSpace(context.TargetHost)
                ? context.OriginalDestinationHost
                : context.TargetHost,
            TargetPort = context.TargetPort > 0
                ? context.TargetPort
                : context.OriginalDestinationPort,
            DispatchDepth = context.DispatchDepth
        };

        var resolved = _outboundRouter.Resolve(routedContext, destination: null);
        return DispatchUdpCoreAsync(resolved, cancellationToken);
    }

    private static DispatchContext CreateTcpRoutedContext(
        DispatchContext context,
        DispatchDestination destination)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        return context with
        {
            Network = RoutingNetworks.Tcp,
            OriginalDestinationHost = string.IsNullOrWhiteSpace(context.OriginalDestinationHost)
                ? destination.Host
                : context.OriginalDestinationHost,
            OriginalDestinationPort = context.OriginalDestinationPort > 0
                ? context.OriginalDestinationPort
                : destination.Port,
            DispatchDepth = context.DispatchDepth,
            TargetHost = destination.Host,
            TargetPort = destination.Port
        };
    }

    private async ValueTask<Stream> DispatchTcpCoreAsync(
        ResolvedOutboundRoute resolved,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var openContext = resolved.Context with
        {
            DispatchDepth = resolved.Context.DispatchDepth + 1
        };
        var stream = await resolved.Handler.OpenTcpAsync(openContext, destination, cancellationToken).ConfigureAwait(false);
        return WrapTopLevelTcpStreamIfNeeded(resolved.Context, stream);
    }

    private Stream WrapTopLevelTcpStreamIfNeeded(DispatchContext context, Stream stream)
    {
        if (stream is FlowControlledStream ||
            context.DispatchDepth != 0 ||
            context.SkipTransportFlowControl ||
            _rateLimiterRegistry is null ||
            _trafficRegistry is null ||
            string.IsNullOrWhiteSpace(context.ScopedUserId))
        {
            return stream;
        }

        var scopedUserId = context.ScopedUserId.Trim();
        var userGate = _rateLimiterRegistry.GetUserGate(scopedUserId);
        var globalGate = _rateLimiterRegistry.GlobalGate;
        return new FlowControlledStream(
            stream,
            readControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => _trafficRegistry.RecordDownload(scopedUserId, bytes)),
            writeControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => _trafficRegistry.RecordUpload(scopedUserId, bytes)));
    }

    private async ValueTask<IOutboundUdpTransport> DispatchUdpCoreAsync(
        ResolvedOutboundRoute resolved,
        CancellationToken cancellationToken)
    {
        var openContext = resolved.Context with
        {
            DispatchDepth = resolved.Context.DispatchDepth + 1
        };
        var transport = await resolved.Handler.OpenUdpAsync(openContext, cancellationToken).ConfigureAwait(false);
        return WrapTopLevelUdpTransportIfNeeded(resolved.Context, transport);
    }

    private IOutboundUdpTransport WrapTopLevelUdpTransportIfNeeded(
        DispatchContext context,
        IOutboundUdpTransport transport)
    {
        if (RuntimeUdpTransportClassifier.IsFlowControlled(transport) ||
            context.DispatchDepth != 0 ||
            context.SkipTransportFlowControl ||
            _rateLimiterRegistry is null ||
            _trafficRegistry is null ||
            string.IsNullOrWhiteSpace(context.ScopedUserId))
        {
            return transport;
        }

        var scopedUserId = context.ScopedUserId.Trim();
        var userGate = _rateLimiterRegistry.GetUserGate(scopedUserId);
        var globalGate = _rateLimiterRegistry.GlobalGate;
        return new FlowControlledUdpTransport(
            transport,
            receiveControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => _trafficRegistry.RecordDownload(scopedUserId, bytes)),
            sendControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => _trafficRegistry.RecordUpload(scopedUserId, bytes)));
    }
}

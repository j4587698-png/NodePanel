namespace NodePanel.Core.Runtime;

internal interface IRuntimeInboundUdpDispatcher
{
    ValueTask<RuntimeUdpDispatchResult> DispatchInboundUdpAsync(
        IRuntimeSniffingDefinition sniffing,
        ReadOnlyMemory<byte> firstPayload,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken,
        bool allowDestinationOverride);
}

internal readonly record struct RuntimeUdpDispatchResult(
    DispatchContext Context,
    DispatchDestination Destination,
    IOutboundUdpTransport Transport);

internal static class RuntimeUdpDispatchPipeline
{
    public static ValueTask<RuntimeUdpDispatchResult> DispatchAsync(
        IDispatcher dispatcher,
        IRuntimeSniffer sniffer,
        IRuntimeSniffingDefinition sniffing,
        ReadOnlyMemory<byte> firstPayload,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken,
        bool allowDestinationOverride = true)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);

        if (dispatcher is IRuntimeInboundUdpDispatcher inboundDispatcher)
        {
            return inboundDispatcher.DispatchInboundUdpAsync(
                sniffing,
                firstPayload,
                context,
                destination,
                cancellationToken,
                allowDestinationOverride);
        }

        return DispatchFallbackAsync(
            dispatcher,
            sniffer,
            sniffing,
            firstPayload,
            context,
            destination,
            cancellationToken,
            allowDestinationOverride);
    }

    private static async ValueTask<RuntimeUdpDispatchResult> DispatchFallbackAsync(
        IDispatcher dispatcher,
        IRuntimeSniffer sniffer,
        IRuntimeSniffingDefinition sniffing,
        ReadOnlyMemory<byte> firstPayload,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken,
        bool allowDestinationOverride)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(sniffer);
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        if (sniffing.Enabled)
        {
            var sniffResult = sniffer.SniffUdp(
                sniffing,
                firstPayload.Span,
                destination,
                context,
                allowDestinationOverride);
            destination = sniffResult.Destination;
            context = sniffResult.Context ?? context;
        }

        var transport = await dispatcher
            .DispatchUdpAsync(context, cancellationToken)
            .ConfigureAwait(false);

        return new RuntimeUdpDispatchResult(
            context,
            destination,
            transport);
    }
}

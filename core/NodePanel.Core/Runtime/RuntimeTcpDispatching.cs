namespace NodePanel.Core.Runtime;

internal interface IRuntimeInboundTcpDispatcher
{
    ValueTask<RuntimeTcpDispatchResult> DispatchInboundTcpAsync(
        IRuntimeSniffingDefinition sniffing,
        Stream inboundStream,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken sniffCancellationToken,
        CancellationToken dispatchCancellationToken,
        bool allowDestinationOverride);
}

internal readonly record struct RuntimeTcpDispatchResult(
    DispatchContext Context,
    DispatchDestination Destination,
    Stream InboundStream,
    Stream OutboundStream);

internal static class RuntimeTcpDispatchPipeline
{
    public static ValueTask<RuntimeTcpDispatchResult> DispatchAsync(
        IDispatcher dispatcher,
        IRuntimeSniffer sniffer,
        IRuntimeSniffingDefinition sniffing,
        Stream inboundStream,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken sniffCancellationToken,
        CancellationToken dispatchCancellationToken,
        bool allowDestinationOverride = true)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);

        if (dispatcher is IRuntimeInboundTcpDispatcher inboundDispatcher)
        {
            return inboundDispatcher.DispatchInboundTcpAsync(
                sniffing,
                inboundStream,
                context,
                destination,
                sniffCancellationToken,
                dispatchCancellationToken,
                allowDestinationOverride);
        }

        return DispatchFallbackAsync(
            dispatcher,
            sniffer,
            sniffing,
            inboundStream,
            context,
            destination,
            sniffCancellationToken,
            dispatchCancellationToken,
            allowDestinationOverride);
    }

    private static async ValueTask<RuntimeTcpDispatchResult> DispatchFallbackAsync(
        IDispatcher dispatcher,
        IRuntimeSniffer sniffer,
        IRuntimeSniffingDefinition sniffing,
        Stream inboundStream,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken sniffCancellationToken,
        CancellationToken dispatchCancellationToken,
        bool allowDestinationOverride)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(sniffer);
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(inboundStream);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        var relayStream = inboundStream;
        if (sniffing.Enabled)
        {
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

        var outboundStream = await dispatcher
            .DispatchTcpAsync(context, destination, dispatchCancellationToken)
            .ConfigureAwait(false);

        return new RuntimeTcpDispatchResult(
            context,
            destination,
            relayStream,
            outboundStream);
    }
}

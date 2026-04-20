namespace NodePanel.Core.Runtime;

internal interface IRuntimeSniffer
{
    IRuntimeTcpSnifferSession CreateTcpSession(
        IRuntimeSniffingDefinition sniffing,
        DispatchContext context,
        DispatchDestination destination,
        bool allowDestinationOverride = true);

    ValueTask<RuntimeTcpSniffResult> SniffTcpAsync(
        IRuntimeSniffingDefinition sniffing,
        Stream stream,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken,
        bool allowDestinationOverride = true);

    RuntimeUdpSniffResult SniffUdp(
        IRuntimeSniffingDefinition sniffing,
        ReadOnlySpan<byte> payload,
        DispatchDestination destination,
        DispatchContext? context = null,
        bool allowDestinationOverride = true);
}

internal interface IRuntimeTcpSnifferSession
{
    ValueTask<RuntimeTcpSniffResult> RunAsync(
        Stream stream,
        CancellationToken cancellationToken);
}

internal sealed class DefaultRuntimeSniffer : IRuntimeSniffer
{
    private readonly IFakeDnsEngine? _fakeDnsEngine;

    public DefaultRuntimeSniffer(IFakeDnsEngine? fakeDnsEngine = null)
    {
        _fakeDnsEngine = fakeDnsEngine;
    }

    public IRuntimeTcpSnifferSession CreateTcpSession(
        IRuntimeSniffingDefinition sniffing,
        DispatchContext context,
        DispatchDestination destination,
        bool allowDestinationOverride = true)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        return new DefaultRuntimeTcpSnifferSession(
            sniffing,
            context,
            destination,
            _fakeDnsEngine,
            allowDestinationOverride);
    }

    public async ValueTask<RuntimeTcpSniffResult> SniffTcpAsync(
        IRuntimeSniffingDefinition sniffing,
        Stream stream,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken,
        bool allowDestinationOverride = true)
    {
        ArgumentNullException.ThrowIfNull(stream);

        return await CreateTcpSession(
                sniffing,
                context,
                destination,
                allowDestinationOverride)
            .RunAsync(stream, cancellationToken)
            .ConfigureAwait(false);
    }

    public RuntimeUdpSniffResult SniffUdp(
        IRuntimeSniffingDefinition sniffing,
        ReadOnlySpan<byte> payload,
        DispatchDestination destination,
        DispatchContext? context = null,
        bool allowDestinationOverride = true)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(destination);

        var decision = sniffing.Enabled
            ? RuntimeSniffingEvaluator.Compose(
                sniffing,
                destination,
                RuntimeSniffingEvaluator.DetectMetadata(destination, _fakeDnsEngine),
                sniffing.MetadataOnly
                    ? new RuntimeSniffingDecision()
                    : RuntimeSniffingEvaluator.DetectContent(payload, DispatchNetwork.Udp))
            : new RuntimeSniffingDecision();

        if (allowDestinationOverride &&
            decision.OverrideDestination is not null)
        {
            destination = decision.OverrideDestination with
            {
                Network = DispatchNetwork.Udp
            };
        }

        if (context is not null)
        {
            if (sniffing.Enabled)
            {
                context = DispatchContextTargeting.ApplySniffing(context, decision);
            }

            context = DispatchContextTargeting.SetTarget(context, destination);
        }

        return new RuntimeUdpSniffResult(decision, destination, context);
    }
}

internal sealed class DefaultRuntimeTcpSnifferSession : IRuntimeTcpSnifferSession
{
    private readonly bool _allowDestinationOverride;
    private readonly DispatchContext _context;
    private readonly DispatchDestination _destination;
    private readonly IFakeDnsEngine? _fakeDnsEngine;
    private readonly IRuntimeSniffingDefinition _sniffing;

    public DefaultRuntimeTcpSnifferSession(
        IRuntimeSniffingDefinition sniffing,
        DispatchContext context,
        DispatchDestination destination,
        IFakeDnsEngine? fakeDnsEngine,
        bool allowDestinationOverride)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        _sniffing = sniffing;
        _context = context;
        _destination = destination;
        _fakeDnsEngine = fakeDnsEngine;
        _allowDestinationOverride = allowDestinationOverride;
    }

    public async ValueTask<RuntimeTcpSniffResult> RunAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var context = _context;
        var destination = _destination;
        var relayStream = stream;

        if (_sniffing.Enabled)
        {
            var metadataMatch = RuntimeSniffingEvaluator.DetectMetadata(destination, _fakeDnsEngine);
            var sniffPayload = _sniffing.MetadataOnly
                ? Array.Empty<byte>()
                : await TcpSniffPayloadReader.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
            if (sniffPayload.Length > 0)
            {
                relayStream = new PrefixedReadStream(stream, sniffPayload);
            }

            var decision = RuntimeSniffingEvaluator.Compose(
                _sniffing,
                destination,
                metadataMatch,
                RuntimeSniffingEvaluator.DetectContent(sniffPayload, DispatchNetwork.Tcp));
            context = DispatchContextTargeting.ApplySniffing(
                context,
                decision,
                sniffPayload.Length > 0 ? sniffPayload : null);

            if (_allowDestinationOverride &&
                decision.OverrideDestination is not null)
            {
                destination = decision.OverrideDestination with
                {
                    Network = DispatchNetwork.Tcp
                };
            }
        }

        return new RuntimeTcpSniffResult(
            DispatchContextTargeting.SetTarget(context, destination),
            destination,
            relayStream);
    }
}

internal readonly record struct RuntimeTcpSniffResult(
    DispatchContext Context,
    DispatchDestination Destination,
    Stream Stream);

internal readonly record struct RuntimeUdpSniffResult(
    RuntimeSniffingDecision Decision,
    DispatchDestination Destination,
    DispatchContext? Context);

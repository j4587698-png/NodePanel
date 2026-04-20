namespace NodePanel.Core.Runtime;

public sealed class DokodemoInboundConnectionHandler
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSniffer _runtimeSniffer;

    public DokodemoInboundConnectionHandler(
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            relayService,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal DokodemoInboundConnectionHandler(
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _relayService = relayService;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task HandleAsync(
        Stream stream,
        DokodemoInboundSessionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var destination = DokodemoInboundDestinationResolver.Resolve(options);
        var dispatchContext = DokodemoDispatchContextFactory.Create(options, destination);

        var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                options.Sniffing,
                stream,
                dispatchContext,
                destination,
                cancellationToken,
                cancellationToken)
            .ConfigureAwait(false);
        await using var remoteStream = dispatchResult.OutboundStream;
        await _relayService
            .RelayAsync(dispatchResult.InboundStream, remoteStream, options, cancellationToken)
            .ConfigureAwait(false);
    }
}

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeSniffingUdpTransport : IOutboundUdpTransport, IInnerUdpTransportAccessor
{
    private readonly bool _allowDestinationOverride;
    private readonly IOutboundUdpTransport _innerTransport;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeSniffingDefinition _sniffing;

    public RuntimeSniffingUdpTransport(
        IOutboundUdpTransport innerTransport,
        IRuntimeSniffer runtimeSniffer,
        IRuntimeSniffingDefinition sniffing,
        bool allowDestinationOverride = true)
    {
        _innerTransport = innerTransport ?? throw new ArgumentNullException(nameof(innerTransport));
        _runtimeSniffer = runtimeSniffer ?? throw new ArgumentNullException(nameof(runtimeSniffer));
        _sniffing = sniffing ?? throw new ArgumentNullException(nameof(sniffing));
        _allowDestinationOverride = allowDestinationOverride;
    }

    public IOutboundUdpTransport InnerTransport => _innerTransport;

    public static IOutboundUdpTransport WrapIfNeeded(
        IOutboundUdpTransport transport,
        IRuntimeSniffer runtimeSniffer,
        IRuntimeSniffingDefinition sniffing,
        bool allowDestinationOverride = true)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(runtimeSniffer);
        ArgumentNullException.ThrowIfNull(sniffing);

        return sniffing.Enabled
            ? new RuntimeSniffingUdpTransport(
                transport,
                runtimeSniffer,
                sniffing,
                allowDestinationOverride)
            : transport;
    }

    public ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (_sniffing.Enabled)
        {
            destination = _runtimeSniffer.SniffUdp(
                _sniffing,
                payload.Span,
                destination,
                allowDestinationOverride: _allowDestinationOverride).Destination;
        }

        return _innerTransport.SendAsync(destination, payload, cancellationToken);
    }

    public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        => _innerTransport.ReceiveAsync(cancellationToken);

    public ValueTask DisposeAsync()
        => _innerTransport.DisposeAsync();
}

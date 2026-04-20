namespace NodePanel.Core.Runtime;

internal sealed class FlowControlledUdpTransport : IOutboundUdpTransport, IInnerUdpTransportAccessor
{
    private readonly IOutboundUdpTransport _innerTransport;
    private readonly StreamFlowControl _receiveControl;
    private readonly StreamFlowControl _sendControl;

    public FlowControlledUdpTransport(
        IOutboundUdpTransport innerTransport,
        StreamFlowControl receiveControl = default,
        StreamFlowControl sendControl = default)
    {
        _innerTransport = innerTransport ?? throw new ArgumentNullException(nameof(innerTransport));
        _receiveControl = receiveControl;
        _sendControl = sendControl;
    }

    public IOutboundUdpTransport InnerTransport => _innerTransport;

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        await _sendControl.ApplyAsync(payload.Length, cancellationToken).ConfigureAwait(false);
        await _innerTransport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);
        _sendControl.Record(payload.Length);
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        var datagram = await _innerTransport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        if (datagram is null)
        {
            return null;
        }

        await _receiveControl.ApplyAsync(datagram.Payload.Length, cancellationToken).ConfigureAwait(false);
        _receiveControl.Record(datagram.Payload.Length);
        return datagram;
    }

    public ValueTask DisposeAsync()
        => _innerTransport.DisposeAsync();
}

namespace NodePanel.Core.Runtime;

public sealed class BlackholeOutboundHandler : IOutboundHandler
{
    private static readonly IOutboundUdpTransport UdpTransport = new BlackholeUdpTransport();

    public string Protocol => OutboundProtocols.Blackhole;

    public ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Blackhole outbound does not support TCP open for network '{destination.Network}'.");
        }

        return ValueTask.FromResult<Stream>(Stream.Null);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
        => ValueTask.FromResult(UdpTransport);

    private sealed class BlackholeUdpTransport : IOutboundUdpTransport
    {
        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(destination);
            if (destination.Network != DispatchNetwork.Udp)
            {
                throw new NotSupportedException($"Blackhole outbound does not support UDP send for network '{destination.Network}'.");
            }

            return ValueTask.CompletedTask;
        }

        public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult<DispatchDatagram?>(null);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

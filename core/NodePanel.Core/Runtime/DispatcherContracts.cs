namespace NodePanel.Core.Runtime;

public interface IDispatcher
{
    ValueTask<Stream> DispatchTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken);

    ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken);
}

public interface IOutboundRouter
{
    IOutboundHandler Resolve(DispatchContext context, DispatchDestination? destination);
}

public interface IOutboundHandler
{
    string Protocol { get; }

    ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken);

    ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken);
}

public interface IOutboundUdpTransport : IAsyncDisposable
{
    ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);

    ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken);
}

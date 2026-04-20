namespace NodePanel.Core.Runtime;

internal sealed class GuardedUdpTransport : IOutboundUdpTransport
{
    private readonly Func<IOutboundUdpTransport> _createInnerTransport;
    private readonly string _rejectMessage;
    private readonly TaskCompletionSource<IOutboundUdpTransport> _transportTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private readonly Predicate<DispatchDestination> _isAllowed;

    private int _disposed;

    public GuardedUdpTransport(
        Func<IOutboundUdpTransport> createInnerTransport,
        Predicate<DispatchDestination> isAllowed,
        string rejectMessage)
    {
        _createInnerTransport = createInnerTransport ?? throw new ArgumentNullException(nameof(createInnerTransport));
        _isAllowed = isAllowed ?? throw new ArgumentNullException(nameof(isAllowed));
        _rejectMessage = string.IsNullOrWhiteSpace(rejectMessage)
            ? "UDP destination is not allowed."
            : rejectMessage.Trim();
    }

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        if (!_isAllowed(destination))
        {
            throw new InvalidOperationException(_rejectMessage);
        }

        var transport = await EnsureTransportAsync(cancellationToken).ConfigureAwait(false);
        await transport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        var transport = await _transportTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _transportTcs.TrySetCanceled();
        if (_transportTcs.Task.IsCompletedSuccessfully)
        {
            await _transportTcs.Task.Result.DisposeAsync().ConfigureAwait(false);
        }

        _initializeLock.Dispose();
    }

    private async ValueTask<IOutboundUdpTransport> EnsureTransportAsync(CancellationToken cancellationToken)
    {
        if (_transportTcs.Task.IsCompletedSuccessfully)
        {
            return await _transportTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        await _initializeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            if (_transportTcs.Task.IsCompletedSuccessfully)
            {
                return await _transportTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            var transport = _createInnerTransport();
            _transportTcs.TrySetResult(transport);
            return transport;
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(GuardedUdpTransport));
        }
    }
}

using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class RoutedUdpTransport : IOutboundUdpTransport
{
    private readonly Func<IOutboundUdpTransport> _createPrimaryTransport;
    private readonly Func<IOutboundUdpTransport> _createSecondaryTransport;
    private readonly SemaphoreSlim _stateLock = new(1, 1);
    private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly TaskCompletionSource<bool> _transportReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Predicate<DispatchDestination> _useSecondaryTransport;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly List<Task> _receivePumps = [];

    private IOutboundUdpTransport? _primaryTransport;
    private IOutboundUdpTransport? _secondaryTransport;
    private int _disposed;

    public RoutedUdpTransport(
        Func<IOutboundUdpTransport> createPrimaryTransport,
        Func<IOutboundUdpTransport> createSecondaryTransport,
        Predicate<DispatchDestination> useSecondaryTransport)
    {
        _createPrimaryTransport = createPrimaryTransport ?? throw new ArgumentNullException(nameof(createPrimaryTransport));
        _createSecondaryTransport = createSecondaryTransport ?? throw new ArgumentNullException(nameof(createSecondaryTransport));
        _useSecondaryTransport = useSecondaryTransport ?? throw new ArgumentNullException(nameof(useSecondaryTransport));
    }

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        var transport = await EnsureTransportAsync(
            _useSecondaryTransport(destination),
            cancellationToken).ConfigureAwait(false);
        await transport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await _transportReady.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await _responses.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();

        IOutboundUdpTransport? primaryTransport;
        IOutboundUdpTransport? secondaryTransport;
        Task[] receivePumps;
        await _stateLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            primaryTransport = _primaryTransport;
            secondaryTransport = _secondaryTransport;
            receivePumps = _receivePumps.ToArray();
            _transportReady.TrySetResult(true);
        }
        finally
        {
            _stateLock.Release();
        }

        if (secondaryTransport is not null)
        {
            await secondaryTransport.DisposeAsync().ConfigureAwait(false);
        }

        if (primaryTransport is not null &&
            !ReferenceEquals(primaryTransport, secondaryTransport))
        {
            await primaryTransport.DisposeAsync().ConfigureAwait(false);
        }

        if (receivePumps.Length > 0)
        {
            try
            {
                await Task.WhenAll(receivePumps).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
        }

        _responses.Writer.TryComplete();
        _stateLock.Dispose();
        _disposeCts.Dispose();
    }

    private async ValueTask<IOutboundUdpTransport> EnsureTransportAsync(
        bool useSecondaryTransport,
        CancellationToken cancellationToken)
    {
        var transport = useSecondaryTransport ? _secondaryTransport : _primaryTransport;
        if (transport is not null)
        {
            return transport;
        }

        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            transport = useSecondaryTransport ? _secondaryTransport : _primaryTransport;
            if (transport is not null)
            {
                return transport;
            }

            transport = useSecondaryTransport ? _createSecondaryTransport() : _createPrimaryTransport();
            if (useSecondaryTransport)
            {
                _secondaryTransport = transport;
            }
            else
            {
                _primaryTransport = transport;
            }

            _transportReady.TrySetResult(true);
            _receivePumps.Add(PumpResponsesAsync(transport));
            return transport;
        }
        finally
        {
            _stateLock.Release();
        }
    }

    private Task PumpResponsesAsync(IOutboundUdpTransport transport)
        => Task.Run(
            async () =>
            {
                try
                {
                    while (!_disposeCts.IsCancellationRequested)
                    {
                        var datagram = await transport.ReceiveAsync(_disposeCts.Token).ConfigureAwait(false);
                        if (datagram is null)
                        {
                            return;
                        }

                        await _responses.Writer.WriteAsync(datagram, _disposeCts.Token).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            });

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(RoutedUdpTransport));
        }
    }
}

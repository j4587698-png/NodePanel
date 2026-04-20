using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class TrojanXudpTransport : IOutboundUdpTransport
{
    private readonly DispatchContext _context;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly IDnsResolver _dnsResolver;
    private readonly byte[] _globalId;
    private readonly Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> _openConnectionAsync;
    private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly string _targetStrategy;

    private RuntimeClientConnection? _connection;
    private int _disposed;
    private Task? _receiveLoop;
    private bool _sentFirstFrame;

    public TrojanXudpTransport(
        DispatchContext context,
        string targetStrategy,
        Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> openConnectionAsync,
        IDnsResolver dnsResolver,
        byte[] globalId)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _targetStrategy = targetStrategy ?? throw new ArgumentNullException(nameof(targetStrategy));
        _openConnectionAsync = openConnectionAsync ?? throw new ArgumentNullException(nameof(openConnectionAsync));
        _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
        _globalId = globalId ?? throw new ArgumentNullException(nameof(globalId));
    }

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (destination.Network != DispatchNetwork.Udp)
        {
            throw new NotSupportedException($"XUDP transport does not support '{destination.Network}'.");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            _context,
            destination,
            _targetStrategy,
            _dnsResolver,
            linkedCts.Token).ConfigureAwait(false);

        await _sendLock.WaitAsync(linkedCts.Token).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            var connection = await EnsureConnectionAsync(linkedCts.Token).ConfigureAwait(false);
            await TrojanMuxFrameCodec.WriteAsync(
                connection.Stream,
                new TrojanMuxFrame
                {
                    SessionId = 0,
                    Status = _sentFirstFrame ? TrojanMuxSessionStatus.Keep : TrojanMuxSessionStatus.New,
                    Option = TrojanMuxFrameOption.Data,
                    Target = new TrojanMuxFrameTarget(
                        resolvedDestination.Host,
                        resolvedDestination.Port,
                        DispatchNetwork.Udp),
                    GlobalId = _globalId,
                    Payload = payload.ToArray()
                },
                linkedCts.Token).ConfigureAwait(false);
            await connection.Stream.FlushAsync(linkedCts.Token).ConfigureAwait(false);
            _sentFirstFrame = true;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        try
        {
            return await _responses.Reader.ReadAsync(linkedCts.Token).ConfigureAwait(false);
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

        RuntimeClientConnection? connection;
        Task? receiveLoop;
        await _sendLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            connection = _connection;
            receiveLoop = _receiveLoop;
            _connection = null;
            _receiveLoop = null;
        }
        finally
        {
            _sendLock.Release();
        }

        if (connection is not null)
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }

        if (receiveLoop is not null)
        {
            try
            {
                await receiveLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
        }

        _responses.Writer.TryComplete();
        _sendLock.Dispose();
        _disposeCts.Dispose();
    }

    private async ValueTask<RuntimeClientConnection> EnsureConnectionAsync(CancellationToken cancellationToken)
    {
        if (_connection is not null)
        {
            return _connection;
        }

        var connection = await _openConnectionAsync(_context, cancellationToken).ConfigureAwait(false);
        _connection = connection;
        _receiveLoop = RunReceiveLoopAsync(connection);
        return connection;
    }

    private async Task RunReceiveLoopAsync(RuntimeClientConnection connection)
    {
        Exception? terminalError = null;

        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                var frame = await TrojanMuxFrameCodec.ReadAsync(connection.Stream, _disposeCts.Token).ConfigureAwait(false);
                if (frame is null)
                {
                    break;
                }

                switch (frame.Status)
                {
                    case TrojanMuxSessionStatus.KeepAlive:
                        continue;
                    case TrojanMuxSessionStatus.Keep:
                        if (frame.HasData &&
                            frame.Target is not null &&
                            frame.Target.Network == DispatchNetwork.Udp)
                        {
                            await _responses.Writer.WriteAsync(
                                new DispatchDatagram
                                {
                                    SourceHost = frame.Target.Host,
                                    SourcePort = frame.Target.Port,
                                    Payload = frame.Payload
                                },
                                _disposeCts.Token).ConfigureAwait(false);
                        }
                        break;
                    case TrojanMuxSessionStatus.End:
                        if (frame.HasError)
                        {
                            terminalError = new IOException("XUDP transport terminated with a remote error.");
                        }

                        return;
                    default:
                        throw new InvalidDataException($"Unsupported XUDP frame status: {frame.Status}.");
                }
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (Exception ex)
        {
            terminalError = ex;
        }
        finally
        {
            _responses.Writer.TryComplete(terminalError);
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanXudpTransport));
        }
    }
}

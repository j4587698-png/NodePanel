using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal sealed class VlessReverseOutboundHandler : IOutboundHandler, IAsyncDisposable
{
    private readonly string _tag;
    private readonly object _sync = new();
    private readonly List<TrojanMuxWorker> _workers = [];
    private int _disposed;

    public VlessReverseOutboundHandler(string tag)
    {
        _tag = string.IsNullOrWhiteSpace(tag) ? throw new ArgumentException("Reverse tag cannot be empty.", nameof(tag)) : tag.Trim();
    }

    public string Protocol => "vless-reverse";

    public async Task AttachAsync(Stream stream, CancellationToken cancellationToken)
    {
        await using var attachment = Attach(stream);
        await attachment.WaitClosedAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"VLESS reverse outbound does not support TCP open for network '{destination.Network}'.");
        }

        for (var attempt = 0; attempt < 4; attempt++)
        {
            var worker = GetAvailableWorker();
            try
            {
                return await worker.OpenTcpAsync(destination, context, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException) when (worker.IsClosed || !worker.CanAcceptMoreSessions())
            {
            }
        }

        throw new InvalidOperationException($"No active VLESS reverse portal is available for tag '{_tag}'.");
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
        => ValueTask.FromResult<IOutboundUdpTransport>(new ReverseUdpTransport(this, context));

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        TrojanMuxWorker[] workers;
        lock (_sync)
        {
            workers = _workers.ToArray();
            _workers.Clear();
        }

        foreach (var worker in workers)
        {
            await worker.DisposeAsync().ConfigureAwait(false);
        }
    }

    private TrojanMuxWorker GetAvailableWorker()
    {
        lock (_sync)
        {
            ThrowIfDisposed();
            CleanupClosedWorkersLocked();
            return _workers.LastOrDefault(static worker => worker.CanAcceptMoreSessions())
                ?? throw new InvalidOperationException($"No active VLESS reverse portal is available for tag '{_tag}'.");
        }
    }

    private void CleanupClosedWorkersLocked()
        => _workers.RemoveAll(static worker => worker.IsClosed);

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(VlessReverseOutboundHandler));
        }
    }

    internal ReversePortalAttachment Attach(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        ThrowIfDisposed();
        var worker = new TrojanMuxWorker(
            new ReverseRuntimeClientConnection(stream),
            maxConcurrency: 0,
            isReverseMux: true);
        lock (_sync)
        {
            ThrowIfDisposed();
            CleanupClosedWorkersLocked();
            _workers.Add(worker);
        }

        return new ReversePortalAttachment(this, worker);
    }

    internal sealed class ReversePortalAttachment : IAsyncDisposable
    {
        private readonly VlessReverseOutboundHandler _owner;
        private readonly TrojanMuxWorker _worker;
        private int _disposed;

        public ReversePortalAttachment(VlessReverseOutboundHandler owner, TrojanMuxWorker worker)
        {
            _owner = owner ?? throw new ArgumentNullException(nameof(owner));
            _worker = worker ?? throw new ArgumentNullException(nameof(worker));
        }

        public Task WaitClosedAsync(CancellationToken cancellationToken = default)
            => _worker.WaitClosedAsync(cancellationToken);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            lock (_owner._sync)
            {
                _owner._workers.Remove(_worker);
            }

            await _worker.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed class ReverseRuntimeClientConnection : RuntimeClientConnection
    {
        public ReverseRuntimeClientConnection(Stream stream)
            : base(new RuntimeInternetConnectionContext(stream))
        {
        }
    }

    private sealed class ReverseUdpTransport : IOutboundUdpTransport, ITrojanMuxClientSession
    {
        private readonly VlessReverseOutboundHandler _owner;
        private readonly DispatchContext _context;
        private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly SemaphoreSlim _sendLock = new(1, 1);

        private int _disposed;
        private ushort _sessionId;
        private TrojanMuxWorker? _worker;

        public ReverseUdpTransport(VlessReverseOutboundHandler owner, DispatchContext context)
        {
            _owner = owner ?? throw new ArgumentNullException(nameof(owner));
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public async ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(ReverseUdpTransport));
            }

            if (destination.Network != DispatchNetwork.Udp)
            {
                throw new NotSupportedException($"VLESS reverse UDP session does not support '{destination.Network}'.");
            }

            await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_sessionId == 0)
                {
                    for (var attempt = 0; attempt < 4; attempt++)
                    {
                        var worker = _owner.GetAvailableWorker();
                        try
                        {
                            var sessionId = worker.RegisterSession(this);
                            await worker.WriteUdpPayloadAsync(
                                sessionId,
                                destination,
                                payload,
                                isNewSession: true,
                                Array.Empty<byte>(),
                                _context,
                                cancellationToken).ConfigureAwait(false);
                            _worker = worker;
                            _sessionId = sessionId;
                            return;
                        }
                        catch (InvalidOperationException) when (worker.IsClosed || !worker.CanAcceptMoreSessions())
                        {
                            if (ReferenceEquals(_worker, worker))
                            {
                                _worker = null;
                            }
                        }
                    }

                    throw new InvalidOperationException("No active VLESS reverse portal is available for UDP traffic.");
                }

                await _worker!.WriteUdpPayloadAsync(
                    _sessionId,
                    destination,
                    payload,
                    isNewSession: false,
                    Array.Empty<byte>(),
                    _context,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _sendLock.Release();
            }
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(ReverseUdpTransport));
            }

            try
            {
                return await _responses.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ChannelClosedException ex) when (ex.InnerException is null)
            {
                return null;
            }
            catch (ChannelClosedException ex)
            {
                throw new IOException("VLESS reverse UDP session closed unexpectedly.", ex.InnerException);
            }
        }

        public void OnFrame(TrojanMuxFrame frame)
        {
            if (frame.Payload.Length == 0 || frame.Target is null)
            {
                return;
            }

            _responses.Writer.TryWrite(
                new DispatchDatagram
                {
                    SourceHost = frame.Target.Host,
                    SourcePort = frame.Target.Port,
                    Payload = frame.Payload
                });
        }

        public void Complete(Exception? exception)
            => _responses.Writer.TryComplete(exception);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _responses.Writer.TryComplete();
            if (_sessionId != 0 && _worker is not null)
            {
                try
                {
                    await _worker.CloseLocalSessionAsync(_sessionId, CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                }
            }

            _sendLock.Dispose();
        }
    }
}

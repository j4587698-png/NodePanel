using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed class Shadowsocks2022UdpOverTcpTransport : IOutboundUdpTransport
{
    private readonly SemaphoreSlim _associationLock = new(1, 1);
    private readonly DispatchContext _context;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly IDnsResolver _dnsResolver;
    private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly Dictionary<string, UdpOverTcpAssociation> _associations = new(StringComparer.Ordinal);
    private readonly Shadowsocks2022Account _account;
    private readonly Shadowsocks2022OutboundClient _client;
    private readonly Shadowsocks2022OutboundSettings _settings;

    private int _disposed;

    public Shadowsocks2022UdpOverTcpTransport(
        Shadowsocks2022OutboundClient client,
        Shadowsocks2022OutboundSettings settings,
        DispatchContext context,
        IDnsResolver dnsResolver)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
        _account = Shadowsocks2022Account.Create(settings.Method, settings.Key);
    }

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (destination.Network != DispatchNetwork.Udp)
        {
            throw new NotSupportedException($"Shadowsocks 2022 UDP over TCP does not support '{destination.Network}'.");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            _context,
            destination,
            _settings.TargetStrategy,
            _dnsResolver,
            linkedCts.Token).ConfigureAwait(false);
        var association = await GetOrCreateAssociationAsync(resolvedDestination, linkedCts.Token).ConfigureAwait(false);
        await association.SendAsync(payload, linkedCts.Token).ConfigureAwait(false);
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

        var associations = _associations.Values.ToArray();
        foreach (var association in associations)
        {
            await association.DisposeAsync().ConfigureAwait(false);
        }

        _responses.Writer.TryComplete();
        _associationLock.Dispose();
        _disposeCts.Dispose();
    }

    private async ValueTask<UdpOverTcpAssociation> GetOrCreateAssociationAsync(
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var key = CreateAssociationKey(destination.Host, destination.Port);
        if (_associations.TryGetValue(key, out var existing))
        {
            return existing;
        }

        await _associationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_associations.TryGetValue(key, out existing))
            {
                return existing;
            }

            var created = await UdpOverTcpAssociation.CreateAsync(
                _client,
                _settings,
                _context,
                _account,
                destination,
                _responses.Writer,
                cancellationToken,
                _disposeCts.Token,
                SignalFailure).ConfigureAwait(false);
            _associations[key] = created;
            return created;
        }
        finally
        {
            _associationLock.Release();
        }
    }

    private void SignalFailure(Exception exception)
    {
        _responses.Writer.TryComplete(exception);
        _disposeCts.Cancel();
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(Shadowsocks2022UdpOverTcpTransport));
        }
    }

    private static string CreateAssociationKey(string host, int port)
        => host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private sealed class UdpOverTcpAssociation : IAsyncDisposable
    {
        private readonly DispatchDestination _destination;
        private readonly CancellationToken _disposeToken;
        private readonly Action<Exception> _signalFailure;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly Stream _stream;
        private readonly ChannelWriter<DispatchDatagram> _writer;
        private readonly Task _receiveLoop;

        private UdpOverTcpAssociation(
            Stream stream,
            DispatchDestination destination,
            ChannelWriter<DispatchDatagram> writer,
            CancellationToken disposeToken,
            Action<Exception> signalFailure)
        {
            _stream = stream;
            _destination = destination;
            _writer = writer;
            _disposeToken = disposeToken;
            _signalFailure = signalFailure;
            _receiveLoop = RunReceiveLoopAsync();
        }

        public static async ValueTask<UdpOverTcpAssociation> CreateAsync(
            Shadowsocks2022OutboundClient client,
            Shadowsocks2022OutboundSettings settings,
            DispatchContext context,
            Shadowsocks2022Account account,
            DispatchDestination destination,
            ChannelWriter<DispatchDatagram> writer,
            CancellationToken cancellationToken,
            CancellationToken disposeToken,
            Action<Exception> signalFailure)
        {
            var serverStream = await client.OpenServerTcpStreamAsync(
                settings,
                context,
                cancellationToken).ConfigureAwait(false);
            try
            {
                var requestDestination = UdpOverTcpProtocol.CreateRequestDestination(settings.UdpOverTcpVersion);
                var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                    serverStream,
                    account,
                    requestDestination.Host,
                    requestDestination.Port,
                    cancellationToken).ConfigureAwait(false);
                await UdpOverTcpProtocol.WriteRequestAsync(
                    stream,
                    settings.UdpOverTcpVersion,
                    isConnect: false,
                    destination,
                    cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                return new UdpOverTcpAssociation(
                    stream,
                    destination,
                    writer,
                    disposeToken,
                    signalFailure);
            }
            catch
            {
                await serverStream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        public async ValueTask SendAsync(
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await UdpOverTcpProtocol.WritePacketAsync(
                    _stream,
                    payload,
                    cancellationToken).ConfigureAwait(false);
                await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
            try
            {
                await _receiveLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeToken.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException)
            {
            }

            _writeLock.Dispose();
        }

        private async Task RunReceiveLoopAsync()
        {
            try
            {
                while (!_disposeToken.IsCancellationRequested)
                {
                    var packet = await UdpOverTcpProtocol.ReadPacketAsync(
                        _stream,
                        _disposeToken).ConfigureAwait(false);
                    if (packet is null)
                    {
                        break;
                    }

                    await _writer.WriteAsync(
                        new DispatchDatagram
                        {
                            SourceHost = _destination.Host,
                            SourcePort = _destination.Port,
                            Payload = packet
                        },
                        _disposeToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (_disposeToken.IsCancellationRequested)
            {
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                _signalFailure(ex);
            }
        }
    }
}

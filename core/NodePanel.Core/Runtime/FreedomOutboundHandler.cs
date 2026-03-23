using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

public sealed class FreedomOutboundHandler : IOutboundHandler
{
    public const string DefaultTag = "freedom";

    private static readonly OutboundCommonSettings DefaultSettings = new()
    {
        Tag = DefaultTag,
        Protocol = OutboundProtocols.Freedom
    };

    private readonly IDnsResolver _dnsResolver;
    private readonly IServiceProvider? _serviceProvider;
    private readonly IOutboundCommonSettingsProvider? _settingsProvider;

    public FreedomOutboundHandler()
        : this(dnsResolver: null)
    {
    }

    public FreedomOutboundHandler(
        IOutboundCommonSettingsProvider settingsProvider,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _settingsProvider = settingsProvider;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    private FreedomOutboundHandler(IDnsResolver? dnsResolver)
    {
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Freedom;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Freedom outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(settings.ProxyOutboundTag))
        {
            return await ResolveDispatcher().DispatchTcpAsync(
                CreateProxyContext(context, destination, settings.ProxyOutboundTag),
                resolvedDestination,
                cancellationToken).ConfigureAwait(false);
        }

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(context.ConnectTimeoutSeconds));
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            resolvedDestination.Host,
            resolvedDestination.Port,
            AddressFamily.Unspecified,
            _dnsResolver,
            connectCts.Token).ConfigureAwait(false);
        return await OutboundSocketDialer.OpenTcpStreamAsync(
            context,
            settings.Via,
            settings.ViaCidr,
            endPoints,
            connectCts.Token).ConfigureAwait(false);
    }

    public async ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var settings = ResolveSettings(context);
        if (!string.IsNullOrWhiteSpace(settings.ProxyOutboundTag))
        {
            var innerTransport = await ResolveDispatcher().DispatchUdpAsync(
                CreateProxyContext(context, destination: null, settings.ProxyOutboundTag),
                cancellationToken).ConfigureAwait(false);
            return new ProxyUdpTransport(innerTransport, context, settings.TargetStrategy, _dnsResolver);
        }

        return new FreedomUdpTransport(context, settings, _dnsResolver);
    }

    private OutboundCommonSettings ResolveSettings(DispatchContext context)
        => _settingsProvider is not null && _settingsProvider.TryResolve(context, out OutboundCommonSettings settings)
            ? settings
            : DefaultSettings;

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Freedom outbound proxy chaining requires an active dispatcher.");

    private static DispatchContext CreateProxyContext(
        DispatchContext context,
        DispatchDestination? destination,
        string outboundTag)
        => context with
        {
            OutboundTag = outboundTag,
            OriginalDestinationHost = string.IsNullOrWhiteSpace(context.OriginalDestinationHost)
                ? destination?.Host ?? string.Empty
                : context.OriginalDestinationHost,
            OriginalDestinationPort = context.OriginalDestinationPort > 0
                ? context.OriginalDestinationPort
                : destination?.Port ?? 0
        };

    private sealed class FreedomUdpTransport : IOutboundUdpTransport
    {
        private readonly SemaphoreSlim _associationLock = new(1, 1);
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Channel<DispatchDatagram> _responseChannel = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly Dictionary<string, ConnectedUdpAssociation> _connectedAssociations = new(StringComparer.Ordinal);
        private readonly Dictionary<AddressFamily, ConeUdpAssociation> _coneAssociations = new();
        private readonly DispatchContext _context;
        private readonly IDnsResolver _dnsResolver;
        private readonly OutboundCommonSettings _settings;

        private int _disposed;

        public FreedomUdpTransport(
            DispatchContext context,
            OutboundCommonSettings settings,
            IDnsResolver dnsResolver)
        {
            _context = context;
            _settings = settings;
            _dnsResolver = dnsResolver;
        }

        public async ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            if (destination.Network != DispatchNetwork.Udp)
            {
                throw new NotSupportedException($"Freedom outbound does not support UDP send for network '{destination.Network}'.");
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _settings.TargetStrategy,
                _dnsResolver,
                linkedCts.Token).ConfigureAwait(false);
            var remoteEndPoint = await ResolveRemoteEndPointAsync(
                resolvedDestination.Host,
                resolvedDestination.Port,
                AddressFamily.Unspecified,
                _dnsResolver,
                linkedCts.Token).ConfigureAwait(false);

            if (_context.UseCone)
            {
                var association = await GetOrCreateConeAssociationAsync(remoteEndPoint.AddressFamily, linkedCts.Token).ConfigureAwait(false);
                await association.SendAsync(remoteEndPoint, payload, linkedCts.Token).ConfigureAwait(false);
                return;
            }

            var connectedAssociation = await GetOrCreateConnectedAssociationAsync(
                resolvedDestination.Host,
                resolvedDestination.Port,
                remoteEndPoint,
                linkedCts.Token).ConfigureAwait(false);
            await connectedAssociation.SendAsync(payload, linkedCts.Token).ConfigureAwait(false);
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            try
            {
                return await _responseChannel.Reader.ReadAsync(linkedCts.Token).ConfigureAwait(false);
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

            foreach (var association in _connectedAssociations.Values)
            {
                await association.DisposeAsync().ConfigureAwait(false);
            }

            foreach (var association in _coneAssociations.Values)
            {
                await association.DisposeAsync().ConfigureAwait(false);
            }

            _responseChannel.Writer.TryComplete();
            _associationLock.Dispose();
            _disposeCts.Dispose();
        }

        private async ValueTask<ConnectedUdpAssociation> GetOrCreateConnectedAssociationAsync(
            string destinationHost,
            int destinationPort,
            IPEndPoint remoteEndPoint,
            CancellationToken cancellationToken)
        {
            var key = CreateAssociationKey(destinationHost, destinationPort);
            if (_connectedAssociations.TryGetValue(key, out var existing))
            {
                return existing;
            }

            await _associationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_connectedAssociations.TryGetValue(key, out existing))
                {
                    return existing;
                }

                var socket = OutboundSocketDialer.CreateUdpSocket(
                    _context,
                    _settings.Via,
                    _settings.ViaCidr,
                    remoteEndPoint.AddressFamily);
                try
                {
                    await socket.ConnectAsync(remoteEndPoint, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }

                var created = new ConnectedUdpAssociation(
                    socket,
                    RunConnectedReceiveLoopAsync(socket, remoteEndPoint));

                _connectedAssociations[key] = created;
                return created;
            }
            finally
            {
                _associationLock.Release();
            }
        }

        private async ValueTask<ConeUdpAssociation> GetOrCreateConeAssociationAsync(
            AddressFamily addressFamily,
            CancellationToken cancellationToken)
        {
            if (_coneAssociations.TryGetValue(addressFamily, out var existing))
            {
                return existing;
            }

            await _associationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_coneAssociations.TryGetValue(addressFamily, out existing))
                {
                    return existing;
                }

                var socket = OutboundSocketDialer.CreateUdpSocket(
                    _context,
                    _settings.Via,
                    _settings.ViaCidr,
                    addressFamily);
                try
                {
                    if (socket.LocalEndPoint is null)
                    {
                        socket.Bind(addressFamily == AddressFamily.InterNetworkV6
                            ? new IPEndPoint(IPAddress.IPv6Any, 0)
                            : new IPEndPoint(IPAddress.Any, 0));
                    }
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }

                var created = new ConeUdpAssociation(
                    socket,
                    RunConeReceiveLoopAsync(socket));

                _coneAssociations[addressFamily] = created;
                return created;
            }
            finally
            {
                _associationLock.Release();
            }
        }

        private async Task RunConnectedReceiveLoopAsync(Socket socket, IPEndPoint remoteEndPoint)
        {
            var buffer = new byte[64 * 1024];

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var received = await socket.ReceiveAsync(
                        buffer.AsMemory(0, buffer.Length),
                        SocketFlags.None,
                        _disposeCts.Token).ConfigureAwait(false);

                    await _responseChannel.Writer.WriteAsync(
                        new DispatchDatagram
                        {
                            SourceHost = remoteEndPoint.Address.ToString(),
                            SourcePort = remoteEndPoint.Port,
                            Payload = buffer.AsSpan(0, received).ToArray()
                        },
                        _disposeCts.Token).ConfigureAwait(false);
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
                Fail(ex);
            }
        }

        private async Task RunConeReceiveLoopAsync(Socket socket)
        {
            var buffer = new byte[64 * 1024];
            EndPoint remoteEndPoint = socket.AddressFamily == AddressFamily.InterNetworkV6
                ? new IPEndPoint(IPAddress.IPv6Any, 0)
                : new IPEndPoint(IPAddress.Any, 0);

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var received = await socket.ReceiveFromAsync(
                        buffer.AsMemory(0, buffer.Length),
                        SocketFlags.None,
                        remoteEndPoint,
                        _disposeCts.Token).ConfigureAwait(false);

                    var remote = (IPEndPoint)received.RemoteEndPoint;
                    await _responseChannel.Writer.WriteAsync(
                        new DispatchDatagram
                        {
                            SourceHost = remote.Address.ToString(),
                            SourcePort = remote.Port,
                            Payload = buffer.AsSpan(0, received.ReceivedBytes).ToArray()
                        },
                        _disposeCts.Token).ConfigureAwait(false);

                    remoteEndPoint = socket.AddressFamily == AddressFamily.InterNetworkV6
                        ? new IPEndPoint(IPAddress.IPv6Any, 0)
                        : new IPEndPoint(IPAddress.Any, 0);
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
                Fail(ex);
            }
        }

        private void Fail(Exception exception)
        {
            _responseChannel.Writer.TryComplete(exception);
            _disposeCts.Cancel();
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(FreedomUdpTransport));
            }
        }

        private static string CreateAssociationKey(string host, int port)
            => host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private static async ValueTask<IPEndPoint> ResolveRemoteEndPointAsync(
            string host,
            int port,
            AddressFamily addressFamily,
            IDnsResolver dnsResolver,
            CancellationToken cancellationToken)
        {
            var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
                host,
                port,
                addressFamily,
                dnsResolver,
                cancellationToken).ConfigureAwait(false);
            return endPoints[0];
        }

        private sealed class ConnectedUdpAssociation : IAsyncDisposable
        {
            private readonly Task _receiveLoop;
            private readonly Socket _socket;

            public ConnectedUdpAssociation(Socket socket, Task receiveLoop)
            {
                _socket = socket;
                _receiveLoop = receiveLoop;
            }

            public ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
                => new(_socket.SendAsync(payload, SocketFlags.None, cancellationToken).AsTask());

            public async ValueTask DisposeAsync()
            {
                _socket.Dispose();
                try
                {
                    await _receiveLoop.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }

        private sealed class ConeUdpAssociation : IAsyncDisposable
        {
            private readonly Task _receiveLoop;
            private readonly Socket _socket;

            public ConeUdpAssociation(Socket socket, Task receiveLoop)
            {
                _socket = socket;
                _receiveLoop = receiveLoop;
            }

            public ValueTask SendAsync(
                EndPoint remoteEndPoint,
                ReadOnlyMemory<byte> payload,
                CancellationToken cancellationToken)
                => new(_socket.SendToAsync(payload, SocketFlags.None, remoteEndPoint, cancellationToken).AsTask());

            public async ValueTask DisposeAsync()
            {
                _socket.Dispose();
                try
                {
                    await _receiveLoop.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                catch (ObjectDisposedException)
                {
                }
            }
        }
    }

    private sealed class ProxyUdpTransport : IOutboundUdpTransport
    {
        private readonly DispatchContext _context;
        private readonly IDnsResolver _dnsResolver;
        private readonly IOutboundUdpTransport _innerTransport;
        private readonly string _targetStrategy;

        public ProxyUdpTransport(
            IOutboundUdpTransport innerTransport,
            DispatchContext context,
            string targetStrategy,
            IDnsResolver dnsResolver)
        {
            _innerTransport = innerTransport;
            _context = context;
            _targetStrategy = targetStrategy;
            _dnsResolver = dnsResolver;
        }

        public async ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _targetStrategy,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);
            await _innerTransport.SendAsync(resolvedDestination, payload, cancellationToken).ConfigureAwait(false);
        }

        public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => _innerTransport.ReceiveAsync(cancellationToken);

        public ValueTask DisposeAsync() => _innerTransport.DisposeAsync();
    }
}

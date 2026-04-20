using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class Shadowsocks2022OutboundClient
{
    private readonly IDnsResolver _dnsResolver;
    private readonly IServiceProvider? _serviceProvider;

    public Shadowsocks2022OutboundClient()
        : this(dnsResolver: null, serviceProvider: null)
    {
    }

    public Shadowsocks2022OutboundClient(
        IDnsResolver? dnsResolver,
        IServiceProvider? serviceProvider = null)
    {
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
        _serviceProvider = serviceProvider;
    }

    public async ValueTask<Stream> OpenTcpAsync(
        Shadowsocks2022OutboundSettings settings,
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Shadowsocks 2022 outbound does not support TCP open for network '{destination.Network}'.");
        }

        ValidateSettings(settings);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);

        var account = Shadowsocks2022Account.Create(settings.Method, settings.Key);
        var serverStream = await OpenServerTcpStreamAsync(settings, context, cancellationToken).ConfigureAwait(false);
        try
        {
            var transport = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
                serverStream,
                account,
                resolvedDestination.Host,
                resolvedDestination.Port,
                cancellationToken).ConfigureAwait(false);

            if (context.InitialPayload.Length == 0)
            {
                return transport;
            }

            await transport.WriteAsync(context.InitialPayload, cancellationToken).ConfigureAwait(false);
            await transport.FlushAsync(cancellationToken).ConfigureAwait(false);
            return new InitialPayloadSentStream(transport, context.InitialPayload.Length);
        }
        catch
        {
            await serverStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        Shadowsocks2022OutboundSettings settings,
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(context);
        _ = cancellationToken;

        ValidateSettings(settings);
        if (settings.UdpOverTcp)
        {
            return ValueTask.FromResult<IOutboundUdpTransport>(
                new Shadowsocks2022UdpOverTcpTransport(
                    this,
                    settings,
                    context,
                    _dnsResolver));
        }

        return ValueTask.FromResult<IOutboundUdpTransport>(new Shadowsocks2022UdpTransport(this, settings, context));
    }

    internal async ValueTask<Stream> OpenServerTcpStreamAsync(
        Shadowsocks2022OutboundSettings settings,
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(settings.ProxyOutboundTag))
        {
            return await ResolveDispatcher().DispatchTcpAsync(
                CreateProxyContext(
                    context,
                    settings.ServerHost,
                    settings.ServerPort,
                    settings.ProxyOutboundTag),
                new DispatchDestination
                {
                    Host = settings.ServerHost,
                    Port = settings.ServerPort,
                    Network = DispatchNetwork.Tcp
                },
                cancellationToken).ConfigureAwait(false);
        }

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(ResolveTimeout(
            settings.ConnectTimeoutSeconds,
            context.ConnectTimeoutSeconds)));
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            context,
            settings.ServerHost,
            settings.ServerPort,
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

    internal IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Shadowsocks 2022 outbound proxy chaining requires an active dispatcher.");

    internal static void ValidateSettings(Shadowsocks2022OutboundSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentException.ThrowIfNullOrWhiteSpace(settings.ServerHost);

        if (settings.ServerPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(settings), settings.ServerPort, "Server port must be between 1 and 65535.");
        }

        if (!ShadowsocksCipherTypes.Is2022Method(settings.Method))
        {
            throw new NotSupportedException($"Unsupported Shadowsocks 2022 method: {settings.Method}.");
        }

        if (string.IsNullOrWhiteSpace(settings.Key))
        {
            throw new InvalidOperationException("Shadowsocks 2022 outbound key is required.");
        }

        if (settings.ConnectTimeoutSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(settings), settings.ConnectTimeoutSeconds, "Connect timeout must be zero or greater.");
        }

        if (settings.UdpOverTcpVersion < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(settings), settings.UdpOverTcpVersion, "UDP over TCP version must be zero or greater.");
        }
    }

    private static DispatchContext CreateProxyContext(
        DispatchContext context,
        string host,
        int port,
        string outboundTag)
        => context with
        {
            OutboundTag = outboundTag,
            InitialPayload = Array.Empty<byte>(),
            OriginalDestinationHost = host,
            OriginalDestinationPort = port
        };

    private static int ResolveTimeout(int configuredTimeoutSeconds, int fallbackTimeoutSeconds)
    {
        if (configuredTimeoutSeconds > 0)
        {
            return configuredTimeoutSeconds;
        }

        return fallbackTimeoutSeconds > 0 ? fallbackTimeoutSeconds : 10;
    }

    private sealed class Shadowsocks2022UdpTransport : IOutboundUdpTransport
    {
        private readonly SemaphoreSlim _connectLock = new(1, 1);
        private readonly DispatchContext _context;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Shadowsocks2022OutboundClient _client;
        private readonly IDnsResolver _dnsResolver;
        private readonly Shadowsocks2022Account _account;
        private readonly Channel<DispatchDatagram> _receiveChannel = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly Shadowsocks2022OutboundSettings _settings;

        private int _disposed;
        private Task? _receiveLoop;
        private IOutboundUdpTransport? _upstreamTransport;
        private Socket? _udpSocket;

        public Shadowsocks2022UdpTransport(
            Shadowsocks2022OutboundClient client,
            Shadowsocks2022OutboundSettings settings,
            DispatchContext context)
        {
            _client = client;
            _settings = settings;
            _context = context;
            _dnsResolver = client._dnsResolver;
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
                throw new NotSupportedException($"Shadowsocks 2022 outbound does not support UDP send for network '{destination.Network}'.");
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _settings.TargetStrategy,
                _dnsResolver,
                linkedCts.Token).ConfigureAwait(false);
            var encodedPayload = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
                _account,
                resolvedDestination.Host,
                resolvedDestination.Port,
                payload.Span);

            if (!string.IsNullOrWhiteSpace(_settings.ProxyOutboundTag))
            {
                var upstreamTransport = await EnsureUpstreamTransportAsync(linkedCts.Token).ConfigureAwait(false);
                await upstreamTransport.SendAsync(
                    new DispatchDestination
                    {
                        Host = _settings.ServerHost,
                        Port = _settings.ServerPort,
                        Network = DispatchNetwork.Udp
                    },
                    encodedPayload,
                    linkedCts.Token).ConfigureAwait(false);
                return;
            }

            var socket = await EnsureUdpSocketAsync(linkedCts.Token).ConfigureAwait(false);
            await socket.SendAsync(encodedPayload, SocketFlags.None, linkedCts.Token).ConfigureAwait(false);
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            if (!string.IsNullOrWhiteSpace(_settings.ProxyOutboundTag))
            {
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                var upstreamTransport = await EnsureUpstreamTransportAsync(linkedCts.Token).ConfigureAwait(false);
                var datagram = await upstreamTransport.ReceiveAsync(linkedCts.Token).ConfigureAwait(false);
                if (datagram is null)
                {
                    return null;
                }

                var packet = Shadowsocks2022ProtocolCodec.DecodeUdpPacket(_account, datagram.Payload);
                return new DispatchDatagram
                {
                    SourceHost = packet.Host,
                    SourcePort = packet.Port,
                    Payload = packet.Payload
                };
            }

            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            try
            {
                return await _receiveChannel.Reader.ReadAsync(readCts.Token).ConfigureAwait(false);
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
            _udpSocket?.Dispose();
            if (_upstreamTransport is not null)
            {
                await _upstreamTransport.DisposeAsync().ConfigureAwait(false);
            }

            if (_receiveLoop is not null)
            {
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

            _receiveChannel.Writer.TryComplete();
            _connectLock.Dispose();
            _disposeCts.Dispose();
        }

        private async ValueTask<IOutboundUdpTransport> EnsureUpstreamTransportAsync(CancellationToken cancellationToken)
        {
            if (_upstreamTransport is not null)
            {
                return _upstreamTransport;
            }

            await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_upstreamTransport is not null)
                {
                    return _upstreamTransport;
                }

                _upstreamTransport = await _client.ResolveDispatcher().DispatchUdpAsync(
                    CreateProxyContext(
                        _context,
                        _settings.ServerHost,
                        _settings.ServerPort,
                        _settings.ProxyOutboundTag),
                    cancellationToken).ConfigureAwait(false);
                return _upstreamTransport;
            }
            finally
            {
                _connectLock.Release();
            }
        }

        private async ValueTask<Socket> EnsureUdpSocketAsync(CancellationToken cancellationToken)
        {
            if (_udpSocket is not null)
            {
                return _udpSocket;
            }

            await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_udpSocket is not null)
                {
                    return _udpSocket;
                }

                var serverEndPoint = await ResolveServerEndPointAsync(cancellationToken).ConfigureAwait(false);
                var socket = OutboundSocketDialer.CreateUdpSocket(
                    _context,
                    _settings.Via,
                    _settings.ViaCidr,
                    serverEndPoint.AddressFamily);
                try
                {
                    await socket.ConnectAsync(serverEndPoint, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }

                _udpSocket = socket;
                _receiveLoop = RunReceiveLoopAsync(socket);
                return socket;
            }
            finally
            {
                _connectLock.Release();
            }
        }

        private async Task RunReceiveLoopAsync(Socket socket)
        {
            var buffer = new byte[64 * 1024];

            try
            {
                while (!_disposeCts.IsCancellationRequested)
                {
                    var read = await socket.ReceiveAsync(
                        buffer.AsMemory(0, buffer.Length),
                        SocketFlags.None,
                        _disposeCts.Token).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    var packet = Shadowsocks2022ProtocolCodec.DecodeUdpPacket(
                        _account,
                        buffer.AsSpan(0, read));
                    await _receiveChannel.Writer.WriteAsync(
                        new DispatchDatagram
                        {
                            SourceHost = packet.Host,
                            SourcePort = packet.Port,
                            Payload = packet.Payload
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
                _receiveChannel.Writer.TryComplete(ex);
                _disposeCts.Cancel();
            }
        }

        private async ValueTask<IPEndPoint> ResolveServerEndPointAsync(CancellationToken cancellationToken)
        {
            var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
                _context,
                _settings.ServerHost,
                _settings.ServerPort,
                AddressFamily.Unspecified,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);
            return endPoints[0];
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(Shadowsocks2022UdpTransport));
            }
        }
    }
}

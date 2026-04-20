using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class ShadowsocksOutboundHandler : IOutboundHandler
{
    private const int ConnectAttempts = 5;
    private static readonly TimeSpan InitialRetryDelay = TimeSpan.FromMilliseconds(100);

    private readonly IOutboundCommonSettingsProvider _commonSettingsProvider;
    private readonly IDnsResolver _dnsResolver;
    private readonly IRuntimeOutboundSettingsProvider _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;

    public ShadowsocksOutboundHandler(
        IOutboundCommonSettingsProvider commonSettingsProvider,
        IRuntimeOutboundSettingsProvider runtimeSettingsProvider,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _commonSettingsProvider = commonSettingsProvider ?? throw new ArgumentNullException(nameof(commonSettingsProvider));
        _runtimeSettingsProvider = runtimeSettingsProvider ?? throw new ArgumentNullException(nameof(runtimeSettingsProvider));
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Shadowsocks;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Shadowsocks outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.Common.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);

        return await OpenTcpWithRetryAsync(
            context,
            settings,
            resolvedDestination,
            cancellationToken).ConfigureAwait(false);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
        => ValueTask.FromResult<IOutboundUdpTransport>(new ShadowsocksUdpTransport(this, context, ResolveSettings(context)));

    internal ShadowsocksResolvedSettings ResolveSettings(DispatchContext context)
    {
        if (!_commonSettingsProvider.TryResolve(context, out var commonSettings) ||
            !string.Equals(commonSettings.Protocol, OutboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Shadowsocks outbound common settings could not be resolved for the current dispatch context.");
        }

        if (!_runtimeSettingsProvider.TryResolve(context, out IRuntimeOutboundOptions runtimeOptions) ||
            !string.Equals(
                OutboundProtocols.Normalize(runtimeOptions.Protocol),
                OutboundProtocols.Shadowsocks,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Shadowsocks outbound settings could not be resolved for the current dispatch context.");
        }

        var compiled = ShadowsocksOutboundOptionsCompiler.Compile(runtimeOptions);
        if (compiled is RuntimeShadowsocks2022OutboundOptions shadowsocks2022)
        {
            throw new NotSupportedException(
                $"Legacy Shadowsocks outbound handler only supports regular Shadowsocks methods. '{shadowsocks2022.Method}' must be resolved through the dedicated Shadowsocks 2022 outbound path.");
        }

        return new ShadowsocksResolvedSettings
        {
            Common = commonSettings,
            Outbound = (RuntimeShadowsocksOutboundOptions)compiled
        };
    }

    internal async ValueTask<Stream> OpenServerTcpStreamAsync(
        DispatchContext context,
        ShadowsocksResolvedSettings settings,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(settings.Common.ProxyOutboundTag))
        {
            return await ResolveDispatcher().DispatchTcpAsync(
                CreateProxyContext(
                    context,
                    settings.Outbound.ServerHost,
                    settings.Outbound.ServerPort,
                    settings.Common.ProxyOutboundTag),
                new DispatchDestination
                {
                    Host = settings.Outbound.ServerHost,
                    Port = settings.Outbound.ServerPort,
                    Network = DispatchNetwork.Tcp
                },
                cancellationToken).ConfigureAwait(false);
        }

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(ResolveTimeout(
            settings.Outbound.ConnectTimeoutSeconds,
            context.ConnectTimeoutSeconds)));
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            context,
            settings.Outbound.ServerHost,
            settings.Outbound.ServerPort,
            AddressFamily.Unspecified,
            _dnsResolver,
            connectCts.Token).ConfigureAwait(false);
        return await OutboundSocketDialer.OpenTcpStreamAsync(
            context,
            settings.Common.Via,
            settings.Common.ViaCidr,
            endPoints,
            connectCts.Token).ConfigureAwait(false);
    }

    internal IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Shadowsocks outbound proxy chaining requires an active dispatcher.");

    private async ValueTask<Stream> OpenTcpWithRetryAsync(
        DispatchContext context,
        ShadowsocksResolvedSettings settings,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        var delay = InitialRetryDelay;

        for (var attempt = 0; attempt < ConnectAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await OpenTcpCoreAsync(context, settings, destination, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < ConnectAttempts - 1 && ShouldRetry(ex))
            {
                lastError = ex;
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(delay.TotalMilliseconds * 2);
            }
            catch (Exception ex)
            {
                lastError = ex;
                break;
            }
        }

        throw new IOException("Shadowsocks outbound failed to connect.", lastError);
    }

    private async ValueTask<Stream> OpenTcpCoreAsync(
        DispatchContext context,
        ShadowsocksResolvedSettings settings,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var account = ShadowsocksAccount.Create(settings.Outbound.Cipher, settings.Outbound.Password);
        var serverStream = await OpenServerTcpStreamAsync(context, settings, cancellationToken).ConfigureAwait(false);
        try
        {
            var transport = await ShadowsocksProtocolCodec.OpenClientTcpStreamAsync(
                serverStream,
                account,
                destination.Host,
                destination.Port,
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

    private static int ResolveTimeout(int configuredTimeoutSeconds, int fallbackTimeoutSeconds)
    {
        if (configuredTimeoutSeconds > 0)
        {
            return configuredTimeoutSeconds;
        }

        return fallbackTimeoutSeconds > 0 ? fallbackTimeoutSeconds : 10;
    }

    private static bool ShouldRetry(Exception exception)
        => exception is not ArgumentException &&
           exception is not InvalidOperationException &&
           exception is not NotSupportedException;

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

    private sealed class ShadowsocksUdpTransport : IOutboundUdpTransport
    {
        private readonly SemaphoreSlim _connectLock = new(1, 1);
        private readonly DispatchContext _context;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly IDnsResolver _dnsResolver;
        private readonly ShadowsocksAccount _account;
        private readonly ShadowsocksOutboundHandler _handler;
        private readonly Channel<DispatchDatagram> _receiveChannel = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly ShadowsocksResolvedSettings _settings;

        private int _disposed;
        private Task? _receiveLoop;
        private IOutboundUdpTransport? _upstreamTransport;
        private Socket? _udpSocket;

        public ShadowsocksUdpTransport(
            ShadowsocksOutboundHandler handler,
            DispatchContext context,
            ShadowsocksResolvedSettings settings)
        {
            _handler = handler;
            _context = context;
            _settings = settings;
            _dnsResolver = handler._dnsResolver;
            _account = ShadowsocksAccount.Create(settings.Outbound.Cipher, settings.Outbound.Password);
        }

        public async ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            if (destination.Network != DispatchNetwork.Udp)
            {
                throw new NotSupportedException($"Shadowsocks outbound does not support UDP send for network '{destination.Network}'.");
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _settings.Common.TargetStrategy,
                _dnsResolver,
                linkedCts.Token).ConfigureAwait(false);
            var encodedPayload = ShadowsocksProtocolCodec.EncodeUdpPacket(
                _account,
                resolvedDestination.Host,
                resolvedDestination.Port,
                payload.Span);

            if (!string.IsNullOrWhiteSpace(_settings.Common.ProxyOutboundTag))
            {
                var upstreamTransport = await EnsureUpstreamTransportAsync(linkedCts.Token).ConfigureAwait(false);
                await upstreamTransport.SendAsync(
                    new DispatchDestination
                    {
                        Host = _settings.Outbound.ServerHost,
                        Port = _settings.Outbound.ServerPort,
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

            if (!string.IsNullOrWhiteSpace(_settings.Common.ProxyOutboundTag))
            {
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                var upstreamTransport = await EnsureUpstreamTransportAsync(linkedCts.Token).ConfigureAwait(false);
                var datagram = await upstreamTransport.ReceiveAsync(linkedCts.Token).ConfigureAwait(false);
                if (datagram is null)
                {
                    return null;
                }

                var packet = ShadowsocksProtocolCodec.DecodeUdpPacket(_account, datagram.Payload);
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

                _upstreamTransport = await _handler.ResolveDispatcher().DispatchUdpAsync(
                    CreateProxyContext(
                        _context,
                        _settings.Outbound.ServerHost,
                        _settings.Outbound.ServerPort,
                        _settings.Common.ProxyOutboundTag),
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
                    _settings.Common.Via,
                    _settings.Common.ViaCidr,
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

                    var packet = ShadowsocksProtocolCodec.DecodeUdpPacket(
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
                _settings.Outbound.ServerHost,
                _settings.Outbound.ServerPort,
                AddressFamily.Unspecified,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);
            return endPoints[0];
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(ShadowsocksUdpTransport));
            }
        }
    }
}

internal sealed record ShadowsocksResolvedSettings
{
    public required OutboundCommonSettings Common { get; init; }

    public required RuntimeShadowsocksOutboundOptions Outbound { get; init; }
}

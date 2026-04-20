using System.Collections.Concurrent;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class TrojanOutboundHandler : IOutboundHandler, IAsyncDisposable
{
    private readonly TrojanOutboundClient _client;
    private readonly IDnsResolver _dnsResolver;
    private readonly ITrojanOutboundSettingsProvider? _legacySettingsProvider;
    private readonly ConcurrentDictionary<string, TrojanMuxOutboundMultiplexState> _multiplexStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOutboundRuntimePlanProvider? _planProvider;
    private readonly IRuntimeOutboundSettingsProvider? _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;
    private readonly TrojanUdpPacketReader _udpPacketReader;
    private readonly TrojanUdpPacketWriter _udpPacketWriter;

    public TrojanOutboundHandler(
        TrojanOutboundClient client,
        IRuntimeOutboundSettingsProvider settingsProvider,
        IOutboundRuntimePlanProvider planProvider,
        TrojanUdpPacketReader udpPacketReader,
        TrojanUdpPacketWriter udpPacketWriter,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _client = client;
        _runtimeSettingsProvider = settingsProvider;
        _planProvider = planProvider;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public TrojanOutboundHandler(
        TrojanOutboundClient client,
        ITrojanOutboundSettingsProvider settingsProvider,
        TrojanUdpPacketReader udpPacketReader,
        TrojanUdpPacketWriter udpPacketWriter,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _client = client;
        _legacySettingsProvider = settingsProvider;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Trojan;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Trojan outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);
        if (TryResolveMultiplexState(settings, out var multiplexState) &&
            multiplexState.CanUseTcp)
        {
            return await multiplexState.OpenTcpAsync(
                context,
                resolvedDestination,
                CreateMuxConnectionFactory(settings),
                cancellationToken).ConfigureAwait(false);
        }

        var transportStreamFactory = CreateTransportStreamFactory(
            settings.ProxyOutboundTag,
            context,
            settings.ServerHost,
            settings.ServerPort);
        var splitHttpDownloadTransportStreamFactory = CreateSplitHttpDownloadTransportStreamFactory(settings, context);
        var connection = await _client.ConnectAsync(
            CreateClientOptions(
                settings,
                context,
                TrojanCommand.Connect,
                resolvedDestination,
                transportStreamFactory,
                splitHttpDownloadTransportStreamFactory),
            cancellationToken).ConfigureAwait(false);
        return new RuntimeConnectionStream(connection);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var settings = ResolveSettings(context);
        var transportStreamFactory = CreateTransportStreamFactory(
            settings.ProxyOutboundTag,
            context,
            settings.ServerHost,
            settings.ServerPort);
        var splitHttpDownloadTransportStreamFactory = CreateSplitHttpDownloadTransportStreamFactory(settings, context);
        Func<IOutboundUdpTransport> createDirectTransport = () => new TrojanUdpTransport(
            _client,
            _udpPacketReader,
            _udpPacketWriter,
            settings,
            context,
            transportStreamFactory,
            splitHttpDownloadTransportStreamFactory,
            _dnsResolver);

        if (TryResolveMultiplexState(settings, out var multiplexState) &&
            multiplexState.CanUseUdp)
        {
            return ValueTask.FromResult<IOutboundUdpTransport>(
                new TrojanAdaptiveUdpTransport(
                    createDirectTransport,
                    () => multiplexState.CreateUdpTransport(
                        context,
                        settings.TargetStrategy,
                        CreateMuxConnectionFactory(settings),
                        _dnsResolver),
                    multiplexState.Udp443Mode));
        }

        return ValueTask.FromResult(createDirectTransport());
    }

    private TrojanOutboundSettings ResolveSettings(DispatchContext context)
    {
        if (_legacySettingsProvider is not null &&
            _legacySettingsProvider.TryResolve(context, out var legacySettings))
        {
            return legacySettings;
        }

        if (_runtimeSettingsProvider is not null &&
            _planProvider is not null &&
            RuntimeOutboundSettingsResolver.TryResolveTrojan(
                _planProvider,
                _runtimeSettingsProvider,
                context,
                out var settings))
        {
            return settings;
        }

        throw new InvalidOperationException("Trojan outbound settings could not be resolved for the current dispatch context.");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var state in _multiplexStates.Values)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        _multiplexStates.Clear();
    }

    private static TrojanClientOptions CreateClientOptions(
        TrojanOutboundSettings settings,
        DispatchContext context,
        TrojanCommand command,
        DispatchDestination destination,
        Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory,
        Func<CancellationToken, ValueTask<Stream>>? splitHttpDownloadTransportStreamFactory)
    {
        var internetStack = ResolveInternetStack(settings.Transport, settings.TransportSecurity);

        return new TrojanClientOptions
        {
            DialContext = context,
            SourceEndPoint = context.SourceEndPoint,
            LocalEndPoint = context.LocalEndPoint,
            Via = settings.Via,
            ViaCidr = settings.ViaCidr,
            ServerHost = settings.ServerHost,
            ServerPort = settings.ServerPort,
            ServerName = settings.ServerName,
            Fingerprint = settings.Fingerprint,
            TransportProtocol = internetStack.TransportProtocol,
            SecurityType = internetStack.SecurityType,
            RealityOptions = settings.RealityOptions,
            WebSocketPath = settings.WebSocketPath,
            WebSocketHeaders = settings.WebSocketHeaders,
            WebSocketEarlyDataBytes = settings.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = settings.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = settings.SplitHttpHost,
            SplitHttpPath = settings.SplitHttpPath,
            SplitHttpHeaders = settings.SplitHttpHeaders,
            SplitHttpMode = settings.SplitHttpMode,
            SplitHttpNoGrpcHeader = settings.SplitHttpNoGrpcHeader,
            SplitHttpXPaddingBytes = settings.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = settings.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = settings.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = settings.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = settings.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = settings.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = settings.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = settings.SplitHttpSessionPlacement,
            SplitHttpSessionKey = settings.SplitHttpSessionKey,
            SplitHttpSeqPlacement = settings.SplitHttpSeqPlacement,
            SplitHttpSeqKey = settings.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = settings.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = settings.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = settings.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = settings.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = settings.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = settings.SplitHttpScMaxBufferedPosts,
            SplitHttpXmux = settings.SplitHttpXmux,
            SplitHttpDownloadSettings = settings.SplitHttpDownloadSettings,
            ApplicationProtocols = settings.ApplicationProtocols,
            QuicOptions = settings.QuicOptions,
            GrpcServiceName = settings.GrpcServiceName,
            GrpcAuthority = settings.GrpcAuthority,
            GrpcMultiMode = settings.GrpcMultiMode,
            GrpcUserAgent = settings.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = settings.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = settings.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = settings.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = settings.GrpcInitialWindowSize,
            Password = settings.Password,
            Command = command,
            TargetHost = destination.Host,
            TargetPort = destination.Port,
            ConnectTimeoutSeconds = ResolveTimeout(settings.ConnectTimeoutSeconds, context.ConnectTimeoutSeconds),
            HandshakeTimeoutSeconds = ResolveTimeout(settings.HandshakeTimeoutSeconds, context.ConnectTimeoutSeconds),
            EnableTlsSessionResumption = settings.EnableTlsSessionResumption,
            SkipCertificateValidation = settings.SkipCertificateValidation,
            RealityHandshakeProvider = settings.RealityHandshakeProvider,
            TransportStreamFactory = transportStreamFactory,
            SplitHttpDownloadTransportStreamFactory = splitHttpDownloadTransportStreamFactory
        };
    }

    private Func<CancellationToken, ValueTask<Stream>>? CreateTransportStreamFactory(
        string proxyOutboundTag,
        DispatchContext context,
        string serverHost,
        int serverPort)
    {
        if (string.IsNullOrWhiteSpace(proxyOutboundTag))
        {
            return null;
        }

        var dispatcher = ResolveDispatcher();
        var proxyContext = context with
        {
            OutboundTag = proxyOutboundTag,
            OriginalDestinationHost = serverHost,
            OriginalDestinationPort = serverPort
        };
        var proxyDestination = new DispatchDestination
        {
            Host = serverHost,
            Port = serverPort,
            Network = DispatchNetwork.Tcp
        };

        return token => dispatcher.DispatchTcpAsync(proxyContext, proxyDestination, token);
    }

    private Func<CancellationToken, ValueTask<Stream>>? CreateSplitHttpDownloadTransportStreamFactory(
        TrojanOutboundSettings settings,
        DispatchContext context)
    {
        if (settings.SplitHttpDownloadSettings is not { ServerHost: { } serverHost, ServerPort: { } serverPort })
        {
            return null;
        }

        return CreateTransportStreamFactory(settings.ProxyOutboundTag, context, serverHost, serverPort);
    }

    private Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> CreateMuxConnectionFactory(
        TrojanOutboundSettings settings)
        => async (dispatchContext, cancellationToken) =>
            await _client.ConnectAsync(
                CreateClientOptions(
                    settings,
                    dispatchContext,
                    TrojanCommand.Connect,
                    TrojanMuxProtocol.CreateMuxDestination(),
                    CreateTransportStreamFactory(
                        settings.ProxyOutboundTag,
                        dispatchContext,
                        settings.ServerHost,
                        settings.ServerPort),
                    CreateSplitHttpDownloadTransportStreamFactory(settings, dispatchContext)),
                cancellationToken).ConfigureAwait(false);

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Trojan outbound proxy chaining requires an active dispatcher.");

    private bool TryResolveMultiplexState(
        TrojanOutboundSettings settings,
        out TrojanMuxOutboundMultiplexState state)
    {
        if (!settings.MultiplexSettings.Enabled)
        {
            state = default!;
            return false;
        }

        var signature = TrojanMuxSignature.FromSettings(settings);
        while (true)
        {
            if (_multiplexStates.TryGetValue(settings.Tag, out var existing))
            {
                if (existing.Signature == signature)
                {
                    state = existing;
                    return true;
                }

                var replacement = new TrojanMuxOutboundMultiplexState(signature);
                if (_multiplexStates.TryUpdate(settings.Tag, replacement, existing))
                {
                    _ = existing.DisposeAsync().AsTask();
                    state = replacement;
                    return true;
                }

                _ = replacement.DisposeAsync().AsTask();
                continue;
            }

            var created = new TrojanMuxOutboundMultiplexState(signature);
            if (_multiplexStates.TryAdd(settings.Tag, created))
            {
                state = created;
                return true;
            }

            _ = created.DisposeAsync().AsTask();
        }
    }

    private static RuntimeInternetStack ResolveInternetStack(string transport, string transportSecurity)
        => ProxyInternetStackResolver.Resolve(transport, transportSecurity).ToRuntimeInternetStack();

    private static int ResolveTimeout(int configuredTimeoutSeconds, int fallbackTimeoutSeconds)
    {
        if (configuredTimeoutSeconds > 0)
        {
            return configuredTimeoutSeconds;
        }

        return fallbackTimeoutSeconds > 0 ? fallbackTimeoutSeconds : 10;
    }

    private sealed class TrojanUdpTransport : IOutboundUdpTransport
    {
        private readonly TrojanOutboundClient _client;
        private readonly SemaphoreSlim _connectLock = new(1, 1);
        private readonly DispatchContext _context;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly TaskCompletionSource<TrojanClientConnection> _connectionTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly IDnsResolver _dnsResolver;
        private readonly TrojanOutboundSettings _settings;
        private readonly Func<CancellationToken, ValueTask<Stream>>? _transportStreamFactory;
        private readonly Func<CancellationToken, ValueTask<Stream>>? _splitHttpDownloadTransportStreamFactory;
        private readonly TrojanUdpPacketReader _udpPacketReader;
        private readonly TrojanUdpPacketWriter _udpPacketWriter;
        private readonly SemaphoreSlim _writeLock = new(1, 1);

        private TrojanClientConnection? _connection;
        private int _disposed;

        public TrojanUdpTransport(
            TrojanOutboundClient client,
            TrojanUdpPacketReader udpPacketReader,
            TrojanUdpPacketWriter udpPacketWriter,
            TrojanOutboundSettings settings,
            DispatchContext context,
            Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory,
            Func<CancellationToken, ValueTask<Stream>>? splitHttpDownloadTransportStreamFactory,
            IDnsResolver dnsResolver)
        {
            _client = client;
            _udpPacketReader = udpPacketReader;
            _udpPacketWriter = udpPacketWriter;
            _settings = settings;
            _context = context;
            _transportStreamFactory = transportStreamFactory;
            _splitHttpDownloadTransportStreamFactory = splitHttpDownloadTransportStreamFactory;
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
                throw new NotSupportedException($"Trojan outbound does not support UDP send for network '{destination.Network}'.");
            }

            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _settings.TargetStrategy,
                _dnsResolver,
                cancellationToken).ConfigureAwait(false);
            var connection = await EnsureConnectedAsync(resolvedDestination, cancellationToken).ConfigureAwait(false);
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);

            await _writeLock.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            try
            {
                await _udpPacketWriter.WriteAsync(
                    connection.Stream,
                    new TrojanUdpPacket
                    {
                        DestinationHost = resolvedDestination.Host,
                        DestinationPort = resolvedDestination.Port,
                        Payload = payload.ToArray()
                    },
                    linkedCts.Token).ConfigureAwait(false);
                await connection.Stream.FlushAsync(linkedCts.Token).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);

            var connection = await WaitForConnectionAsync(linkedCts.Token).ConfigureAwait(false);
            var packet = await _udpPacketReader.ReadAsync(connection.Stream, linkedCts.Token).ConfigureAwait(false);
            if (packet is null)
            {
                return null;
            }

            return new DispatchDatagram
            {
                SourceHost = packet.DestinationHost,
                SourcePort = packet.DestinationPort,
                Payload = packet.Payload
            };
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            _connectionTcs.TrySetCanceled(_disposeCts.Token);

            if (_connection is not null)
            {
                await _connection.DisposeAsync().ConfigureAwait(false);
            }

            _writeLock.Dispose();
            _connectLock.Dispose();
            _disposeCts.Dispose();
        }

        private async ValueTask<TrojanClientConnection> EnsureConnectedAsync(
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            if (_connectionTcs.Task.IsCompletedSuccessfully)
            {
                return await _connectionTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            await _connectLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_connectionTcs.Task.IsCompletedSuccessfully)
                {
                    return await _connectionTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                }

                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                var connection = await _client.ConnectAsync(
                    CreateClientOptions(
                        _settings,
                        _context,
                        TrojanCommand.Associate,
                        destination,
                        _transportStreamFactory,
                        _splitHttpDownloadTransportStreamFactory),
                    linkedCts.Token).ConfigureAwait(false);
                _connection = connection;
                _connectionTcs.TrySetResult(connection);
                return connection;
            }
            catch (Exception ex)
            {
                _connectionTcs.TrySetException(ex);
                throw;
            }
            finally
            {
                _connectLock.Release();
            }
        }

        private ValueTask<TrojanClientConnection> WaitForConnectionAsync(CancellationToken cancellationToken)
            => new(_connectionTcs.Task.WaitAsync(cancellationToken));

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(TrojanUdpTransport));
            }
        }
    }
}

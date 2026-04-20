using System.Collections.Concurrent;
using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VmessOutboundHandler : IOutboundHandler, IAsyncDisposable
{
    private readonly VmessOutboundClient _client;
    private readonly IDnsResolver _dnsResolver;
    private readonly IVmessOutboundSettingsProvider? _legacySettingsProvider;
    private readonly ConcurrentDictionary<string, TrojanMuxOutboundMultiplexState> _multiplexStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOutboundRuntimePlanProvider? _planProvider;
    private readonly IRuntimeOutboundSettingsProvider? _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;

    public VmessOutboundHandler(
        VmessOutboundClient client,
        IRuntimeOutboundSettingsProvider settingsProvider,
        IOutboundRuntimePlanProvider planProvider,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _client = client;
        _runtimeSettingsProvider = settingsProvider;
        _planProvider = planProvider;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public VmessOutboundHandler(
        VmessOutboundClient client,
        IVmessOutboundSettingsProvider settingsProvider,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _client = client;
        _legacySettingsProvider = settingsProvider;
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Vmess;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"VMess outbound does not support TCP open for network '{destination.Network}'.");
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
                CreateMuxConnectionFactory(settings, TrojanMuxProtocol.CreateMuxDestination()),
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
                VmessCommand.Connect,
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
        Func<IOutboundUdpTransport> createDirectTransport = () => new VmessUdpTransport(
            _client,
            settings,
            context,
            transportStreamFactory,
            splitHttpDownloadTransportStreamFactory,
            _dnsResolver);
        Func<IOutboundUdpTransport> createXudpTransport = () => new TrojanXudpTransport(
            context,
            settings.TargetStrategy,
            CreateMuxConnectionFactory(settings, TrojanMuxProtocol.CreateXudpDestination()),
            _dnsResolver,
            TrojanMuxProtocol.CreateGlobalId(context));

        if (context.UseCone)
        {
            return ValueTask.FromResult<IOutboundUdpTransport>(
                new RoutedUdpTransport(
                    createDirectTransport,
                    createXudpTransport,
                    ShouldUseXudp));
        }

        if (TryResolveMultiplexState(settings, out var multiplexState) &&
            multiplexState.CanUseUdp)
        {
            return ValueTask.FromResult<IOutboundUdpTransport>(
                new TrojanAdaptiveUdpTransport(
                    createDirectTransport,
                    () => multiplexState.CreateUdpTransport(
                        context,
                        settings.TargetStrategy,
                        CreateMuxConnectionFactory(settings, TrojanMuxProtocol.CreateMuxDestination()),
                        _dnsResolver),
                    multiplexState.Udp443Mode));
        }

        return ValueTask.FromResult(createDirectTransport());
    }

    private VmessOutboundSettings ResolveSettings(DispatchContext context)
    {
        if (_legacySettingsProvider is not null &&
            _legacySettingsProvider.TryResolve(context, out var legacySettings))
        {
            return legacySettings;
        }

        if (_runtimeSettingsProvider is not null &&
            _planProvider is not null &&
            RuntimeOutboundSettingsResolver.TryResolveVmess(
                _planProvider,
                _runtimeSettingsProvider,
                context,
                out var settings))
        {
            return settings;
        }

        throw new InvalidOperationException("VMess outbound settings could not be resolved for the current dispatch context.");
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var state in _multiplexStates.Values)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        _multiplexStates.Clear();
    }

    private static VmessClientOptions CreateClientOptions(
        VmessOutboundSettings settings,
        DispatchContext context,
        VmessCommand command,
        DispatchDestination destination,
        Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory,
        Func<CancellationToken, ValueTask<Stream>>? splitHttpDownloadTransportStreamFactory)
    {
        var internetStack = ResolveInternetStack(settings.Transport, settings.TransportSecurity);

        return new VmessClientOptions
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
            UserUuid = settings.UserUuid,
            RequestSecurity = settings.Security,
            AuthenticatedLength = settings.AuthenticatedLength,
            NoTerminationSignal = settings.NoTerminationSignal,
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
        VmessOutboundSettings settings,
        DispatchContext context)
    {
        if (settings.SplitHttpDownloadSettings is not { ServerHost: { } serverHost, ServerPort: { } serverPort })
        {
            return null;
        }

        return CreateTransportStreamFactory(settings.ProxyOutboundTag, context, serverHost, serverPort);
    }

    private Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> CreateMuxConnectionFactory(
        VmessOutboundSettings settings,
        DispatchDestination muxDestination)
        => async (dispatchContext, cancellationToken) =>
            await _client.ConnectAsync(
                CreateClientOptions(
                    settings,
                    dispatchContext,
                    VmessCommand.Mux,
                    muxDestination,
                    CreateTransportStreamFactory(
                        settings.ProxyOutboundTag,
                        dispatchContext,
                        settings.ServerHost,
                        settings.ServerPort),
                    CreateSplitHttpDownloadTransportStreamFactory(settings, dispatchContext)),
                cancellationToken).ConfigureAwait(false);

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("VMess outbound proxy chaining requires an active dispatcher.");

    private bool TryResolveMultiplexState(
        VmessOutboundSettings settings,
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

    private static bool ShouldUseXudp(DispatchDestination destination)
        => destination.Network == DispatchNetwork.Udp &&
           destination.Port != 53 &&
           destination.Port != 443;

    private sealed class VmessUdpTransport : IOutboundUdpTransport
    {
        private readonly SemaphoreSlim _associationLock = new(1, 1);
        private readonly VmessOutboundClient _client;
        private readonly DispatchContext _context;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly IDnsResolver _dnsResolver;
        private readonly Channel<DispatchDatagram> _responseChannel = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly VmessOutboundSettings _settings;
        private readonly Func<CancellationToken, ValueTask<Stream>>? _transportStreamFactory;
        private readonly Func<CancellationToken, ValueTask<Stream>>? _splitHttpDownloadTransportStreamFactory;
        private readonly ConcurrentDictionary<string, ConnectedUdpAssociation> _associations = new(StringComparer.Ordinal);

        private int _disposed;

        public VmessUdpTransport(
            VmessOutboundClient client,
            VmessOutboundSettings settings,
            DispatchContext context,
            Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory,
            Func<CancellationToken, ValueTask<Stream>>? splitHttpDownloadTransportStreamFactory,
            IDnsResolver dnsResolver)
        {
            _client = client;
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
                throw new NotSupportedException($"VMess outbound does not support UDP send for network '{destination.Network}'.");
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

            ConnectedUdpAssociation[] associations;
            await _associationLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                associations = _associations.Values.ToArray();
                _associations.Clear();
            }
            finally
            {
                _associationLock.Release();
            }

            foreach (var association in associations)
            {
                await association.DisposeAsync().ConfigureAwait(false);
            }

            _responseChannel.Writer.TryComplete();
            _associationLock.Dispose();
            _disposeCts.Dispose();
        }

        private async ValueTask<ConnectedUdpAssociation> GetOrCreateAssociationAsync(
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            var key = CreateAssociationKey(destination.Host, destination.Port);
            if (_associations.TryGetValue(key, out var existing) && !existing.IsClosed)
            {
                return existing;
            }

            await _associationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_associations.TryGetValue(key, out existing))
                {
                    if (!existing.IsClosed)
                    {
                        return existing;
                    }

                    _associations.TryRemove(key, out _);
                }

                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                var connection = await _client.ConnectAsync(
                    CreateClientOptions(
                        _settings,
                        _context,
                        VmessCommand.Udp,
                        destination,
                        _transportStreamFactory,
                        _splitHttpDownloadTransportStreamFactory),
                    linkedCts.Token).ConfigureAwait(false);

                var created = new ConnectedUdpAssociation(
                    key,
                    destination,
                    connection,
                    _responseChannel.Writer,
                    _disposeCts.Token,
                    RemoveAssociation);
                _associations[key] = created;
                return created;
            }
            finally
            {
                _associationLock.Release();
            }
        }

        private void RemoveAssociation(string key, ConnectedUdpAssociation association)
        {
            if (_disposed != 0)
            {
                return;
            }

            if (_associations.TryGetValue(key, out var existing) && ReferenceEquals(existing, association))
            {
                _associations.TryRemove(key, out _);
            }
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(VmessUdpTransport));
            }
        }

        private static string CreateAssociationKey(string host, int port)
            => host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private sealed class ConnectedUdpAssociation : IAsyncDisposable
        {
            private readonly VmessClientConnection _connection;
            private readonly CancellationTokenSource _disposeCts;
            private readonly string _key;
            private readonly Action<string, ConnectedUdpAssociation> _onClosed;
            private readonly DispatchDestination _destination;
            private readonly ChannelWriter<DispatchDatagram> _responseWriter;
            private readonly Task _receiveLoop;
            private readonly VmessClientDataStream _vmessStream;
            private readonly SemaphoreSlim _writeLock = new(1, 1);

            private int _disposed;

            public ConnectedUdpAssociation(
                string key,
                DispatchDestination destination,
                VmessClientConnection connection,
                ChannelWriter<DispatchDatagram> responseWriter,
                CancellationToken transportCancellationToken,
                Action<string, ConnectedUdpAssociation> onClosed)
            {
                _key = key;
                _destination = destination;
                _connection = connection;
                _vmessStream = connection.Stream as VmessClientDataStream
                    ?? throw new InvalidOperationException("VMess UDP connection does not expose a VMess client stream.");
                _responseWriter = responseWriter;
                _onClosed = onClosed;
                _disposeCts = CancellationTokenSource.CreateLinkedTokenSource(transportCancellationToken);
                _receiveLoop = RunReceiveLoopAsync();
            }

            public bool IsClosed => Volatile.Read(ref _disposed) != 0;

            public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
            {
                if (Volatile.Read(ref _disposed) != 0)
                {
                    throw new ObjectDisposedException(nameof(ConnectedUdpAssociation));
                }

                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                await _writeLock.WaitAsync(linkedCts.Token).ConfigureAwait(false);
                try
                {
                    await _vmessStream.WritePacketAsync(payload, linkedCts.Token).ConfigureAwait(false);
                    await _connection.Stream.FlushAsync(linkedCts.Token).ConfigureAwait(false);
                }
                finally
                {
                    _writeLock.Release();
                }
            }

            public async ValueTask DisposeAsync()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                {
                    return;
                }

                _disposeCts.Cancel();
                await _connection.DisposeAsync().ConfigureAwait(false);

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

                _writeLock.Dispose();
                _disposeCts.Dispose();
            }

            private async Task RunReceiveLoopAsync()
            {
                try
                {
                    while (!_disposeCts.IsCancellationRequested)
                    {
                        var payload = await _vmessStream.ReadPacketAsync(_disposeCts.Token).ConfigureAwait(false);
                        if (payload is null)
                        {
                            break;
                        }

                        await _responseWriter.WriteAsync(
                            new DispatchDatagram
                            {
                                SourceHost = _destination.Host,
                                SourcePort = _destination.Port,
                                Payload = payload
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
                finally
                {
                    _onClosed(_key, this);
                    if (Interlocked.Exchange(ref _disposed, 1) == 0)
                    {
                        await _connection.DisposeAsync().ConfigureAwait(false);
                        _writeLock.Dispose();
                        _disposeCts.Dispose();
                    }
                }
            }
        }
    }
}

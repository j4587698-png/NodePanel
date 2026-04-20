using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VlessOutboundHandler : IOutboundHandler, IRuntimeStartable, IAsyncDisposable
{
    private static readonly TimeSpan ReverseReconnectDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan TestPreConnectionTtl = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan TestPreRefillDelay = TimeSpan.FromMilliseconds(200);

    private readonly VlessOutboundClient _client;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly IDnsResolver _dnsResolver;
    private readonly IVlessOutboundSettingsProvider? _legacySettingsProvider;
    private readonly ConcurrentDictionary<string, TrojanMuxOutboundMultiplexState> _multiplexStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOutboundRuntimePlanProvider? _planProvider;
    private readonly ConcurrentDictionary<string, VlessTransportPreconnectState> _preconnectStates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ReversePortalState> _reversePortalStates = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _reverseMuxInboundServerSync = new();
    private readonly IRuntimeOutboundSettingsProvider? _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;
    private readonly VlessUdpPacketReader _udpPacketReader;
    private readonly VlessUdpPacketWriter _udpPacketWriter;
    private TrojanMuxInboundServer? _reverseMuxInboundServer;
    private int _disposed;
    private int _started;

    public VlessOutboundHandler(
        VlessOutboundClient client,
        IRuntimeOutboundSettingsProvider settingsProvider,
        IOutboundRuntimePlanProvider planProvider,
        VlessUdpPacketReader udpPacketReader,
        VlessUdpPacketWriter udpPacketWriter,
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

    public VlessOutboundHandler(
        VlessOutboundClient client,
        IVlessOutboundSettingsProvider settingsProvider,
        VlessUdpPacketReader udpPacketReader,
        VlessUdpPacketWriter udpPacketWriter,
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

    public string Protocol => OutboundProtocols.Vless;

    public void Start()
    {
        ThrowIfDisposed();
        if (Interlocked.Exchange(ref _started, 1) != 0)
        {
            return;
        }

        foreach (var settings in EnumerateReverseSettings())
        {
            _reversePortalStates.TryAdd(
                settings.Tag,
                new ReversePortalState(this, settings, _disposeCts.Token));
        }
    }

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"VLESS outbound does not support TCP open for network '{destination.Network}'.");
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

        var connection = await OpenConnectionAsync(
            settings,
            context,
            VlessCommand.Connect,
            resolvedDestination,
            cancellationToken).ConfigureAwait(false);
        return new RuntimeConnectionStream(connection);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var settings = ResolveSettings(context);
        Func<IOutboundUdpTransport> createDirectTransport = () => new VlessUdpTransport(
            async (destination, token) =>
                await OpenConnectionAsync(settings, context, VlessCommand.Udp, destination, token).ConfigureAwait(false),
            _udpPacketReader,
            _udpPacketWriter,
            context,
            settings.TargetStrategy,
            _dnsResolver);
        Func<IOutboundUdpTransport> createXudpTransport = () => new TrojanXudpTransport(
            context,
            settings.TargetStrategy,
            CreateMuxConnectionFactory(settings, TrojanMuxProtocol.CreateXudpDestination()),
            _dnsResolver,
            TrojanMuxProtocol.CreateGlobalId(context));

        if (VlessFlowTypes.IsVision(settings.Flow))
        {
            return ValueTask.FromResult<IOutboundUdpTransport>(
                new GuardedUdpTransport(
                    createXudpTransport,
                    destination => destination.Port != 443 || VlessFlowTypes.AllowsUdp443(settings.Flow),
                    "XTLS rejected UDP/443 traffic."));
        }

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

    private VlessOutboundSettings ResolveSettings(DispatchContext context)
    {
        if (_legacySettingsProvider is not null &&
            _legacySettingsProvider.TryResolve(context, out var legacySettings))
        {
            return legacySettings;
        }

        if (_runtimeSettingsProvider is not null &&
            _planProvider is not null &&
            RuntimeOutboundSettingsResolver.TryResolveVless(
                _planProvider,
                _runtimeSettingsProvider,
                context,
                out var settings))
        {
            return settings;
        }

        throw new InvalidOperationException("VLESS outbound settings could not be resolved for the current dispatch context.");
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();

        foreach (var state in _reversePortalStates.Values)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        _reversePortalStates.Clear();

        foreach (var state in _preconnectStates.Values)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        _preconnectStates.Clear();

        foreach (var state in _multiplexStates.Values)
        {
            await state.DisposeAsync().ConfigureAwait(false);
        }

        _multiplexStates.Clear();
        _disposeCts.Dispose();
    }

    private async ValueTask<VlessClientConnection> OpenConnectionAsync(
        VlessOutboundSettings settings,
        DispatchContext context,
        VlessCommand command,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var transportStreamFactory = CreateTransportStreamFactory(
            settings.ProxyOutboundTag,
            context,
            settings.ServerHost,
            settings.ServerPort);
        var splitHttpDownloadTransportStreamFactory = CreateSplitHttpDownloadTransportStreamFactory(settings, context);
        var options = CreateClientOptions(
            settings,
            context,
            command,
            destination,
            transportStreamFactory,
            splitHttpDownloadTransportStreamFactory);

        if (command != VlessCommand.Rvs &&
            TryResolvePreconnectState(settings, context, out var preconnectState))
        {
            return await preconnectState.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
        }

        return await _client.ConnectAsync(options, cancellationToken).ConfigureAwait(false);
    }

    private static VlessClientOptions CreateClientOptions(
        VlessOutboundSettings settings,
        DispatchContext context,
        VlessCommand command,
        DispatchDestination destination,
        Func<CancellationToken, ValueTask<Stream>>? transportStreamFactory,
        Func<CancellationToken, ValueTask<Stream>>? splitHttpDownloadTransportStreamFactory)
    {
        var internetStack = ResolveInternetStack(settings.Transport, settings.TransportSecurity);

        return new VlessClientOptions
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
            Version = settings.Version,
            UserUuid = settings.UserUuid,
            Flow = settings.Flow,
            Encryption = settings.Encryption,
            XorMode = settings.XorMode,
            Seconds = settings.Seconds,
            Padding = settings.Padding,
            TestSeed = settings.TestSeed,
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
        VlessOutboundSettings settings,
        DispatchContext context)
    {
        if (settings.SplitHttpDownloadSettings is not { ServerHost: { } serverHost, ServerPort: { } serverPort })
        {
            return null;
        }

        return CreateTransportStreamFactory(settings.ProxyOutboundTag, context, serverHost, serverPort);
    }

    private Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> CreateMuxConnectionFactory(
        VlessOutboundSettings settings,
        DispatchDestination muxDestination)
        => async (dispatchContext, cancellationToken) =>
            await OpenConnectionAsync(
                settings,
                dispatchContext,
                VlessCommand.Mux,
                muxDestination,
                cancellationToken).ConfigureAwait(false);

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("VLESS outbound proxy chaining requires an active dispatcher.");

    private TrojanMuxInboundServer ResolveReverseMuxInboundServer()
    {
        if (_serviceProvider?.GetService(typeof(TrojanMuxInboundServer)) is TrojanMuxInboundServer registered)
        {
            return registered;
        }

        lock (_reverseMuxInboundServerSync)
        {
            if (_reverseMuxInboundServer is not null)
            {
                return _reverseMuxInboundServer;
            }

            _reverseMuxInboundServer = new TrojanMuxInboundServer(
                ResolveDispatcher(),
                _serviceProvider?.GetService(typeof(IRuntimeRateLimiterRegistry)) as IRuntimeRateLimiterRegistry ?? new RateLimiterRegistry(),
                _serviceProvider?.GetService(typeof(IRuntimeTrafficRegistry)) as IRuntimeTrafficRegistry ?? new TrafficRegistry(),
                _serviceProvider?.GetService(typeof(IRuntimeSniffer)) as IRuntimeSniffer ?? new DefaultRuntimeSniffer());
            return _reverseMuxInboundServer;
        }
    }

    private DispatchContext CreateReverseDialContext(VlessOutboundSettings settings)
    {
        var plan = ResolveRuntimePlan();
        var limits = plan.TransportLimits;
        return new DispatchContext
        {
            OutboundTag = settings.Tag,
            ConnectTimeoutSeconds = Math.Max(1, limits.ConnectTimeoutSeconds),
            ConnectionIdleSeconds = Math.Max(1, limits.ConnectionIdleSeconds),
            UplinkOnlySeconds = Math.Max(1, limits.UplinkOnlySeconds),
            DownlinkOnlySeconds = Math.Max(1, limits.DownlinkOnlySeconds),
            UseCone = plan.UseCone
        };
    }

    private DispatchContext CreateReverseBridgeDispatchContext(VlessOutboundSettings settings)
    {
        var plan = ResolveRuntimePlan();
        var limits = plan.TransportLimits;
        var userId = settings.UserUuid;
        return new DispatchContext
        {
            InboundProtocol = InboundProtocols.Vless,
            InboundKind = InboundProtocols.Vless,
            InboundTag = settings.ReverseTag,
            InboundSourceNetwork = RoutingNetworks.Tcp,
            UserId = userId,
            ScopedUserId = RuntimeUserKeys.Create(InboundProtocols.Vless, settings.ReverseTag, userId),
            ConnectTimeoutSeconds = Math.Max(1, limits.ConnectTimeoutSeconds),
            ConnectionIdleSeconds = Math.Max(1, limits.ConnectionIdleSeconds),
            UplinkOnlySeconds = Math.Max(1, limits.UplinkOnlySeconds),
            DownlinkOnlySeconds = Math.Max(1, limits.DownlinkOnlySeconds),
            UseCone = plan.UseCone
        };
    }

    private IReadOnlyList<VlessOutboundSettings> EnumerateReverseSettings()
    {
        if (_legacySettingsProvider is not null)
        {
            return _legacySettingsProvider.TryResolve(CreateOutboundResolutionContext(string.Empty), out var legacySettings) &&
                   !string.IsNullOrWhiteSpace(legacySettings.ReverseTag)
                ? [legacySettings]
                : Array.Empty<VlessOutboundSettings>();
        }

        if (_runtimeSettingsProvider is null || _planProvider is null)
        {
            return Array.Empty<VlessOutboundSettings>();
        }

        var settings = new List<VlessOutboundSettings>();
        foreach (var outbound in _planProvider.GetCurrentOutboundPlan().Outbounds)
        {
            if (!string.Equals(
                    OutboundProtocols.Normalize(outbound.Protocol),
                    OutboundProtocols.Vless,
                    StringComparison.Ordinal))
            {
                continue;
            }

            var context = CreateOutboundResolutionContext(outbound.Tag);
            if (RuntimeOutboundSettingsResolver.TryResolveVless(
                    _planProvider,
                    _runtimeSettingsProvider,
                    context,
                    out var resolved) &&
                !string.IsNullOrWhiteSpace(resolved.ReverseTag))
            {
                settings.Add(resolved);
            }
        }

        return settings;
    }

    private RuntimePlan ResolveRuntimePlan()
        => _serviceProvider?.GetService(typeof(IRuntimePlanState)) as IRuntimePlanState is { } planState
            ? planState.GetCurrentPlan()
            : RuntimePlan.Empty;

    private static DispatchContext CreateOutboundResolutionContext(string tag)
        => new()
        {
            OutboundTag = tag,
            ConnectTimeoutSeconds = 10
        };

    private bool TryResolveMultiplexState(
        VlessOutboundSettings settings,
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

    private bool TryResolvePreconnectState(
        VlessOutboundSettings settings,
        DispatchContext context,
        out VlessTransportPreconnectState state)
    {
        if (!CanUseTestPre(settings))
        {
            state = default!;
            return false;
        }

        var signature = VlessTransportPreconnectSignature.FromSettings(settings, context);
        while (true)
        {
            if (_preconnectStates.TryGetValue(signature.StateKey, out var existing))
            {
                if (existing.Signature == signature)
                {
                    state = existing;
                    return true;
                }

                var replacement = CreatePreconnectState(signature, settings, context);
                if (_preconnectStates.TryUpdate(signature.StateKey, replacement, existing))
                {
                    _ = existing.DisposeAsync().AsTask();
                    state = replacement;
                    return true;
                }

                _ = replacement.DisposeAsync().AsTask();
                continue;
            }

            var created = CreatePreconnectState(signature, settings, context);
            if (_preconnectStates.TryAdd(signature.StateKey, created))
            {
                state = created;
                return true;
            }

            _ = created.DisposeAsync().AsTask();
        }
    }

    private VlessTransportPreconnectState CreatePreconnectState(
        VlessTransportPreconnectSignature signature,
        VlessOutboundSettings settings,
        DispatchContext context)
        => new(
            signature,
            _client,
            CreateClientOptions(
                settings,
                context,
                VlessCommand.Connect,
                CreateDummyTarget(settings),
                CreateTransportStreamFactory(
                    settings.ProxyOutboundTag,
                    context,
                    settings.ServerHost,
                    settings.ServerPort),
                CreateSplitHttpDownloadTransportStreamFactory(settings, context)));

    private static bool CanUseTestPre(VlessOutboundSettings settings)
        => settings.TestPre > 0 &&
           settings.WebSocketEarlyDataBytes <= 0 &&
           string.IsNullOrWhiteSpace(settings.ReverseTag);

    private static DispatchDestination CreateDummyTarget(VlessOutboundSettings settings)
        => new()
        {
            Host = settings.ServerHost,
            Port = settings.ServerPort > 0 ? settings.ServerPort : 443,
            Network = DispatchNetwork.Tcp
        };

    private static DispatchDestination CreateReverseDestination()
        => new()
        {
            Host = string.Empty,
            Port = 0,
            Network = DispatchNetwork.Tcp
        };

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

    private sealed record VlessTransportPreconnectSignature(
        string StateKey,
        string ServerHost,
        int ServerPort,
        string ServerName,
        string Fingerprint,
        string Transport,
        string TransportSecurity,
        string Via,
        string ViaCidr,
        string ProxyOutboundTag,
        string WebSocketPath,
        string WebSocketHeaders,
        int WebSocketEarlyDataBytes,
        int WebSocketHeartbeatPeriodSeconds,
        string SplitHttpHost,
        string SplitHttpPath,
        string SplitHttpHeaders,
        string SplitHttpMode,
        bool SplitHttpNoGrpcHeader,
        RuntimeInt32Range SplitHttpXPaddingBytes,
        bool SplitHttpXPaddingObfsMode,
        string SplitHttpXPaddingKey,
        string SplitHttpXPaddingHeader,
        string SplitHttpXPaddingPlacement,
        string SplitHttpXPaddingMethod,
        string SplitHttpUplinkHttpMethod,
        string SplitHttpSessionPlacement,
        string SplitHttpSessionKey,
        string SplitHttpSeqPlacement,
        string SplitHttpSeqKey,
        string SplitHttpUplinkDataPlacement,
        string SplitHttpUplinkDataKey,
        RuntimeInt32Range SplitHttpUplinkChunkSize,
        RuntimeInt32Range SplitHttpScMaxEachPostBytes,
        RuntimeInt32Range SplitHttpScMinPostsIntervalMs,
        int SplitHttpScMaxBufferedPosts,
        string SplitHttpXmux,
        string SplitHttpDownloadSettings,
        string ApplicationProtocols,
        string GrpcServiceName,
        string GrpcAuthority,
        bool GrpcMultiMode,
        string GrpcUserAgent,
        int GrpcIdleTimeoutSeconds,
        int GrpcHealthCheckTimeoutSeconds,
        bool GrpcPermitWithoutStream,
        int GrpcInitialWindowSize,
        string RealitySignature,
        string UserUuid,
        string Flow,
        string Encryption,
        uint XorMode,
        int Seconds,
        string Padding,
        string TestSeed,
        bool SkipCertificateValidation,
        int ConnectTimeoutSeconds,
        int HandshakeTimeoutSeconds,
        string SourceIdentity,
        string LocalIdentity,
        bool SkipDnsResolve,
        int TestPre)
    {
        public static VlessTransportPreconnectSignature FromSettings(
            VlessOutboundSettings settings,
            DispatchContext context)
            => new(
                CreateStateKey(settings, context),
                settings.ServerHost,
                settings.ServerPort,
                settings.ServerName,
                settings.Fingerprint,
                VlessOutboundTransports.Normalize(settings.Transport),
                RuntimeInternetSecurityTypes.Normalize(settings.TransportSecurity),
                settings.Via,
                settings.ViaCidr,
                settings.ProxyOutboundTag,
                settings.WebSocketPath,
                string.Join(
                    "\n",
                settings.WebSocketHeaders
                    .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(static pair => pair.Key + "=" + pair.Value)),
                settings.WebSocketEarlyDataBytes,
                settings.WebSocketHeartbeatPeriodSeconds,
                settings.SplitHttpHost,
                settings.SplitHttpPath,
                string.Join(
                    "\n",
                settings.SplitHttpHeaders
                    .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(static pair => pair.Key + "=" + pair.Value)),
                settings.SplitHttpMode,
                settings.SplitHttpNoGrpcHeader,
                settings.SplitHttpXPaddingBytes,
                settings.SplitHttpXPaddingObfsMode,
                settings.SplitHttpXPaddingKey,
                settings.SplitHttpXPaddingHeader,
                settings.SplitHttpXPaddingPlacement,
                settings.SplitHttpXPaddingMethod,
                settings.SplitHttpUplinkHttpMethod,
                settings.SplitHttpSessionPlacement,
                settings.SplitHttpSessionKey,
                settings.SplitHttpSeqPlacement,
                settings.SplitHttpSeqKey,
                settings.SplitHttpUplinkDataPlacement,
                settings.SplitHttpUplinkDataKey,
                settings.SplitHttpUplinkChunkSize,
                settings.SplitHttpScMaxEachPostBytes,
                settings.SplitHttpScMinPostsIntervalMs,
                settings.SplitHttpScMaxBufferedPosts,
                SerializeSplitHttpXmux(settings.SplitHttpXmux),
                SerializeSplitHttpDownloadSettings(settings.SplitHttpDownloadSettings),
                string.Join("\n", settings.ApplicationProtocols),
                settings.GrpcServiceName,
                settings.GrpcAuthority,
                settings.GrpcMultiMode,
                settings.GrpcUserAgent,
                settings.GrpcIdleTimeoutSeconds,
                settings.GrpcHealthCheckTimeoutSeconds,
                settings.GrpcPermitWithoutStream,
                settings.GrpcInitialWindowSize,
                CreateRealitySignature(settings.RealityOptions, settings.RealityHandshakeProvider),
                settings.UserUuid,
                VlessFlowTypes.Normalize(settings.Flow),
                VlessTransportEncryption.NormalizeEncryption(settings.Encryption),
                settings.XorMode,
                settings.Seconds,
                settings.Padding.Trim(),
                string.Join(",", settings.TestSeed),
                settings.SkipCertificateValidation,
                ResolveTimeout(settings.ConnectTimeoutSeconds, context.ConnectTimeoutSeconds),
                ResolveTimeout(settings.HandshakeTimeoutSeconds, context.ConnectTimeoutSeconds),
                NormalizeBindIdentity(context.SourceEndPoint),
                NormalizeBindIdentity(context.LocalEndPoint),
                DispatchDnsResolution.ShouldSkipDnsResolve(context),
                settings.TestPre);

        private static string CreateStateKey(
            VlessOutboundSettings settings,
            DispatchContext context)
            => string.Join(
                "|",
                settings.Tag.Trim(),
                NormalizeBindIdentity(context.SourceEndPoint),
                NormalizeBindIdentity(context.LocalEndPoint),
                DispatchDnsResolution.ShouldSkipDnsResolve(context)
                    ? "skipdns"
                    : "dns");

        private static string CreateRealitySignature(
            RuntimeRealityOptions options,
            IRuntimeRealityHandshakeProvider? handshakeProvider)
            => string.Join(
                "|",
                options.Fingerprint,
                options.PublicKey,
                options.ShortId,
                options.Mldsa65Verify,
                options.SpiderX,
                ResolveRealityHandshakeProviderIdentity(handshakeProvider));

        private static string SerializeSplitHttpDownloadSettings(RuntimeSplitHttpDownloadOptions? settings)
        {
            if (settings is null)
            {
                return string.Empty;
            }

            var headers = settings.Headers is null
                ? string.Empty
                : string.Join(
                    "\n",
                    settings.Headers
                        .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                        .Select(static pair => pair.Key + "=" + pair.Value));
            return string.Join(
                "|",
                settings.ServerHost ?? string.Empty,
                settings.ServerPort?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                settings.ServerName ?? string.Empty,
                settings.Fingerprint ?? string.Empty,
                settings.TransportSecurity ?? string.Empty,
                settings.RealityOptions?.Fingerprint ?? string.Empty,
                settings.RealityOptions?.PublicKey ?? string.Empty,
                settings.RealityOptions?.ShortId ?? string.Empty,
                settings.RealityOptions?.Mldsa65Verify ?? string.Empty,
                settings.RealityOptions?.SpiderX ?? string.Empty,
                settings.Host ?? string.Empty,
                settings.Path ?? string.Empty,
                headers,
                settings.ConnectTimeoutSeconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                settings.HandshakeTimeoutSeconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
                settings.SkipCertificateValidation?.ToString() ?? string.Empty);
        }

        private static string SerializeSplitHttpXmux(RuntimeSplitHttpXmuxOptions? settings)
        {
            settings ??= RuntimeSplitHttpXmuxOptions.Empty;
            return string.Join(
                "|",
                SerializeRange(settings.MaxConcurrency),
                SerializeRange(settings.MaxConnections),
                SerializeRange(settings.CMaxReuseTimes),
                SerializeRange(settings.HMaxRequestTimes),
                SerializeRange(settings.HMaxReusableSecs),
                settings.HKeepAlivePeriodSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        private static string SerializeRange(RuntimeInt32Range? value)
            => value is null
                ? string.Empty
                : string.Join(
                    ",",
                    value.From.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    value.To.ToString(System.Globalization.CultureInfo.InvariantCulture));

        private static string ResolveRealityHandshakeProviderIdentity(IRuntimeRealityHandshakeProvider? handshakeProvider)
            => handshakeProvider is null
                ? string.Empty
                : !string.IsNullOrWhiteSpace(handshakeProvider.Identity)
                    ? handshakeProvider.Identity.Trim()
                    : handshakeProvider.GetType().FullName ?? handshakeProvider.GetType().Name;

        private static string NormalizeBindIdentity(EndPoint? endPoint)
            => endPoint switch
            {
                IPEndPoint ipEndPoint => ipEndPoint.Address.ToString(),
                null => string.Empty,
                _ => endPoint.ToString()?.Trim() ?? string.Empty
            };
    }

    private sealed class VlessTransportPreconnectState : IAsyncDisposable
    {
        private readonly VlessOutboundClient _client;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly Channel<PreconnectedTransport> _transports;
        private readonly VlessClientOptions _templateOptions;
        private readonly Task[] _workers;

        private int _disposed;

        public VlessTransportPreconnectState(
            VlessTransportPreconnectSignature signature,
            VlessOutboundClient client,
            VlessClientOptions templateOptions)
        {
            Signature = signature;
            _client = client;
            _templateOptions = templateOptions;
            _transports = Channel.CreateBounded<PreconnectedTransport>(
                new BoundedChannelOptions(Math.Max(1, signature.TestPre))
                {
                    SingleReader = false,
                    SingleWriter = false,
                    FullMode = BoundedChannelFullMode.Wait
                });
            _workers = new Task[Math.Max(1, signature.TestPre)];
            for (var index = 0; index < _workers.Length; index++)
            {
                _workers[index] = Task.Run(() => RunWorkerAsync(_disposeCts.Token));
            }
        }

        public VlessTransportPreconnectSignature Signature { get; }

        public async ValueTask<VlessClientConnection> ConnectAsync(
            VlessClientOptions options,
            CancellationToken cancellationToken)
        {
            while (true)
            {
                PreconnectedTransport transport;
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
                try
                {
                    transport = await _transports.Reader.ReadAsync(linkedCts.Token).ConfigureAwait(false);
                }
                catch (ChannelClosedException ex)
                {
                    throw new InvalidOperationException("VLESS testpre transport pool is unavailable.", ex);
                }

                if (DateTimeOffset.UtcNow >= transport.ExpireAt)
                {
                    await transport.Connection.DisposeAsync().ConfigureAwait(false);
                    continue;
                }

                try
                {
                    return await _client.CompleteConnectAsync(
                        transport.Connection,
                        options,
                        linkedCts.Token).ConfigureAwait(false);
                }
                catch
                {
                    await transport.Connection.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            _transports.Writer.TryComplete();

            try
            {
                await Task.WhenAll(_workers).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }

            while (_transports.Reader.TryRead(out var transport))
            {
                await transport.Connection.DisposeAsync().ConfigureAwait(false);
            }

            _disposeCts.Dispose();
        }

        private async Task RunWorkerAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                VlessClientConnection? connection = null;
                var shouldBreak = false;

                try
                {
                    connection = await _client.OpenTransportConnectionAsync(_templateOptions, cancellationToken).ConfigureAwait(false);
                    await _transports.Writer.WriteAsync(
                        new PreconnectedTransport(connection, DateTimeOffset.UtcNow.Add(TestPreConnectionTtl)),
                        cancellationToken).ConfigureAwait(false);
                    connection = null;
                    await Task.Delay(TestPreRefillDelay, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    shouldBreak = true;
                }
                catch (ChannelClosedException)
                {
                    shouldBreak = true;
                }
                finally
                {
                    if (connection is not null)
                    {
                        await connection.DisposeAsync().ConfigureAwait(false);
                    }
                }

                if (shouldBreak)
                {
                    break;
                }
            }
        }

        private sealed record PreconnectedTransport(
            VlessClientConnection Connection,
            DateTimeOffset ExpireAt);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(VlessOutboundHandler));
        }
    }

    private sealed class ReversePortalState : IAsyncDisposable
    {
        private readonly VlessOutboundHandler _owner;
        private readonly VlessOutboundSettings _settings;
        private readonly CancellationTokenSource _disposeCts;
        private readonly Task _runTask;
        private int _disposed;

        public ReversePortalState(
            VlessOutboundHandler owner,
            VlessOutboundSettings settings,
            CancellationToken cancellationToken)
        {
            _owner = owner;
            _settings = settings;
            _disposeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _runTask = Task.Run(RunAsync);
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _disposeCts.Cancel();
            try
            {
                await _runTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
            {
            }
            finally
            {
                _disposeCts.Dispose();
            }
        }

        private async Task RunAsync()
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                try
                {
                    var inboundServer = _owner.ResolveReverseMuxInboundServer();
                    var dialContext = _owner.CreateReverseDialContext(_settings);
                    var bridgeContext = _owner.CreateReverseBridgeDispatchContext(_settings);
                    var connection = await _owner.OpenConnectionAsync(
                        _settings,
                        dialContext,
                        VlessCommand.Rvs,
                        CreateReverseDestination(),
                        _disposeCts.Token).ConfigureAwait(false);
                    await using var reverseStream = new RuntimeConnectionStream(connection);
                    await inboundServer.HandleAsync(
                        reverseStream,
                        new ReverseBridgeRuntimeUser(_settings),
                        bridgeContext,
                        bridgeContext.ConnectionIdleSeconds,
                        RuntimeSniffingOptions.Disabled,
                        _disposeCts.Token,
                        allowedTargetNetwork: null,
                        readSourceAndLocal: true).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
                {
                    return;
                }
                catch
                {
                }

                try
                {
                    await Task.Delay(ReverseReconnectDelay, _disposeCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
                {
                    return;
                }
            }
        }
    }

    private sealed class ReverseBridgeRuntimeUser : IRuntimeScopedUserDefinition
    {
        public ReverseBridgeRuntimeUser(VlessOutboundSettings settings)
        {
            ArgumentNullException.ThrowIfNull(settings);

            UserId = settings.UserUuid;
            RuntimeKey = RuntimeUserKeys.Create(
                InboundProtocols.Vless,
                settings.ReverseTag,
                settings.UserUuid);
        }

        public string UserId { get; }

        public int Level => 0;

        public long BytesPerSecond => 0;

        public int DeviceLimit => 0;

        public string RuntimeKey { get; }
    }

    private sealed class VlessUdpTransport : IOutboundUdpTransport
    {
        private readonly SemaphoreSlim _associationLock = new(1, 1);
        private readonly Func<DispatchDestination, CancellationToken, ValueTask<RuntimeClientConnection>> _connectAsync;
        private readonly DispatchContext _context;
        private readonly CancellationTokenSource _disposeCts = new();
        private readonly IDnsResolver _dnsResolver;
        private readonly Channel<DispatchDatagram> _responseChannel = Channel.CreateUnbounded<DispatchDatagram>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly string _targetStrategy;
        private readonly VlessUdpPacketReader _udpPacketReader;
        private readonly VlessUdpPacketWriter _udpPacketWriter;
        private readonly ConcurrentDictionary<string, ConnectedUdpAssociation> _associations = new(StringComparer.Ordinal);

        private int _disposed;

        public VlessUdpTransport(
            Func<DispatchDestination, CancellationToken, ValueTask<RuntimeClientConnection>> connectAsync,
            VlessUdpPacketReader udpPacketReader,
            VlessUdpPacketWriter udpPacketWriter,
            DispatchContext context,
            string targetStrategy,
            IDnsResolver dnsResolver)
        {
            _connectAsync = connectAsync;
            _udpPacketReader = udpPacketReader;
            _udpPacketWriter = udpPacketWriter;
            _context = context;
            _targetStrategy = targetStrategy;
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
                throw new NotSupportedException($"VLESS outbound does not support UDP send for network '{destination.Network}'.");
            }

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
            var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
                _context,
                destination,
                _targetStrategy,
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
                var connection = await _connectAsync(destination, linkedCts.Token).ConfigureAwait(false);

                var created = new ConnectedUdpAssociation(
                    key,
                    destination,
                    connection,
                    _udpPacketReader,
                    _udpPacketWriter,
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
                throw new ObjectDisposedException(nameof(VlessUdpTransport));
            }
        }

        private static string CreateAssociationKey(string host, int port)
            => host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private sealed class ConnectedUdpAssociation : IAsyncDisposable
        {
            private readonly RuntimeClientConnection _connection;
            private readonly CancellationTokenSource _disposeCts;
            private readonly string _key;
            private readonly Action<string, ConnectedUdpAssociation> _onClosed;
            private readonly DispatchDestination _destination;
            private readonly ChannelWriter<DispatchDatagram> _responseWriter;
            private readonly Task _receiveLoop;
            private readonly VlessUdpPacketReader _udpPacketReader;
            private readonly VlessUdpPacketWriter _udpPacketWriter;
            private readonly SemaphoreSlim _writeLock = new(1, 1);

            private int _disposed;

            public ConnectedUdpAssociation(
                string key,
                DispatchDestination destination,
                RuntimeClientConnection connection,
                VlessUdpPacketReader udpPacketReader,
                VlessUdpPacketWriter udpPacketWriter,
                ChannelWriter<DispatchDatagram> responseWriter,
                CancellationToken transportCancellationToken,
                Action<string, ConnectedUdpAssociation> onClosed)
            {
                _key = key;
                _destination = destination;
                _connection = connection;
                _udpPacketReader = udpPacketReader;
                _udpPacketWriter = udpPacketWriter;
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
                    await _udpPacketWriter.WriteAsync(_connection.Stream, payload, linkedCts.Token).ConfigureAwait(false);
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
                        var payload = await _udpPacketReader.ReadAsync(_connection.Stream, _disposeCts.Token).ConfigureAwait(false);
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

using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeDispatcherServices : IRuntimeDispatcherController
{
    private IDispatcher? _dispatcher;

    public void SetDispatcher(IDispatcher dispatcher)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        Volatile.Write(ref _dispatcher, dispatcher);
    }

    public void ClearDispatcher()
    {
        Volatile.Write(ref _dispatcher, null);
    }

    public IDispatcher GetRequiredDispatcher()
        => Volatile.Read(ref _dispatcher)
           ?? throw new InvalidOperationException("Runtime dispatcher is not available.");

    public object? GetService(Type serviceType)
        => serviceType == typeof(IDispatcher) ? Volatile.Read(ref _dispatcher) : null;
}

internal sealed record RuntimeExecutionTask(
    string Name,
    IReadOnlyList<string> ListenerKeys,
    Task Task);

internal sealed class RuntimeStartupCoordinator
{
    private readonly TaskCompletionSource _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _remaining;

    public RuntimeStartupCoordinator(int expectedSignals)
    {
        _remaining = Math.Max(0, expectedSignals);
        if (_remaining == 0)
        {
            _completion.TrySetResult();
        }
    }

    public void ReportStarted()
    {
        if (_remaining == 0)
        {
            return;
        }

        if (Interlocked.Decrement(ref _remaining) <= 0)
        {
            _completion.TrySetResult();
        }
    }

    public void ReportFault(Exception exception)
    {
        _completion.TrySetException(exception);
    }

    public Task Completion => _completion.Task;

    public Task WaitAsync(CancellationToken cancellationToken)
    {
        return _completion.Task.WaitAsync(cancellationToken);
    }
}

public static class RuntimeListenerKeys
{
    public static string CreateListenerKey(
        string protocol,
        string tag,
        string transport,
        ListenerBinding binding)
    {
        return $"{protocol}|{tag}|{transport}|{binding.ListenAddress}|{binding.Port}";
    }

    public static IReadOnlyList<string> GetListenerKeys(TrojanInboundRuntimePlan plan)
    {
        return plan.Listeners
            .SelectMany(static listener => GetListenerKeys(listener))
            .ToArray();
    }

    public static IReadOnlyList<string> GetListenerKeys(VlessInboundRuntimePlan plan)
    {
        return plan.Listeners
            .SelectMany(static listener => GetListenerKeys(listener))
            .ToArray();
    }

    public static IReadOnlyList<string> GetListenerKeys(VmessInboundRuntimePlan plan)
    {
        return plan.Listeners
            .SelectMany(static listener => GetListenerKeys(listener))
            .ToArray();
    }

    public static IReadOnlyList<string> GetListenerKeys(ShadowsocksInboundRuntimePlan plan)
    {
        return plan.Inbounds
            .SelectMany(static inbound => GetListenerKeys(inbound))
            .Concat(plan.Inbounds2022.SelectMany(static inbound => GetListenerKeys(inbound)))
            .ToArray();
    }

    public static IReadOnlyList<string> GetListenerKeys(TrojanTlsListenerRuntime listener)
    {
        var keys = new List<string>(listener.Inbounds.Count);
        foreach (var inbound in listener.Inbounds)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Trojan,
                inbound.Tag,
                inbound.Transport,
                inbound.Binding));
        }

        return keys;
    }

    public static IReadOnlyList<string> GetListenerKeys(VlessTlsListenerRuntime listener)
    {
        var keys = new List<string>(listener.Inbounds.Count);
        foreach (var inbound in listener.Inbounds)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Vless,
                inbound.Tag,
                inbound.Transport,
                inbound.Binding));
        }

        return keys;
    }

    public static IReadOnlyList<string> GetListenerKeys(VmessTlsListenerRuntime listener)
    {
        var keys = new List<string>(listener.Inbounds.Count);
        foreach (var inbound in listener.Inbounds)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Vmess,
                inbound.Tag,
                inbound.Transport,
                inbound.Binding));
        }

        return keys;
    }

    public static IReadOnlyList<string> GetListenerKeys(ShadowsocksInboundRuntime inbound)
    {
        var keys = new List<string>(2);
        if (inbound.HasTcp)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Tcp,
                inbound.Binding));
        }

        if (inbound.HasUdp)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Udp,
                inbound.Binding));
        }

        return keys;
    }

    public static IReadOnlyList<string> GetListenerKeys(Shadowsocks2022InboundRuntime inbound)
    {
        var keys = new List<string>(2);
        if (inbound.HasTcp)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Tcp,
                inbound.Binding));
        }

        if (inbound.HasUdp)
        {
            keys.Add(CreateListenerKey(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Udp,
                inbound.Binding));
        }

        return keys;
    }

    public static IReadOnlyList<string> GetListenerKeys(ShadowsocksInboundRuntime inbound, string network)
    {
        var normalizedNetwork = RoutingNetworks.Normalize(network);
        return normalizedNetwork switch
        {
            RoutingNetworks.Tcp when inbound.HasTcp => GetListenerKeys(inbound.Tag, RoutingNetworks.Tcp, inbound.Binding),
            RoutingNetworks.Udp when inbound.HasUdp => GetListenerKeys(inbound.Tag, RoutingNetworks.Udp, inbound.Binding),
            _ => Array.Empty<string>()
        };
    }

    public static IReadOnlyList<string> GetListenerKeys(
        string tag,
        string network,
        ListenerBinding binding)
    {
        var normalizedNetwork = RoutingNetworks.Normalize(network);
        return normalizedNetwork is RoutingNetworks.Tcp or RoutingNetworks.Udp
            ? [CreateListenerKey(InboundProtocols.Shadowsocks, tag, normalizedNetwork, binding)]
            : Array.Empty<string>();
    }

    public static IReadOnlyList<string> GetListenerKeys(
        string protocol,
        IReadOnlyList<ProxyInboundListenerDefinition> listeners)
    {
        return listeners
            .Select(listener => CreateListenerKey(protocol, listener.Tag, transport: string.Empty, listener.Binding))
            .ToArray();
    }

    public static string DescribeBinding(ListenerBinding binding)
    {
        return binding.IsUnix
            ? $"unix:{binding.ListenAddress}"
            : $"{binding.ListenAddress}:{binding.Port}";
    }
}

public sealed class RuntimeComponentRegistry
{
    private readonly Dictionary<Type, RuntimeComponentFactoryRegistration> _factories = new();
    private readonly List<RuntimeComponentResolution> _resolutions = [];

    public RuntimeComponentRegistry AddSingleton<TService>(
        Func<RuntimeComponentResolver, TService> factory,
        bool replaceExisting = false,
        bool trackLifecycle = true)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(factory);

        var serviceType = typeof(TService);
        if (_factories.ContainsKey(serviceType) && !replaceExisting)
        {
            throw new InvalidOperationException($"Runtime component '{serviceType.Name}' is already registered.");
        }

        _factories[serviceType] = new RuntimeComponentFactoryRegistration(
            resolver => factory(resolver),
            trackLifecycle);
        return this;
    }

    public RuntimeComponentRegistry Require<TService>(Action<TService> callback)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(callback);
        _resolutions.Add(new RuntimeComponentResolution<TService>(callback));
        return this;
    }

    public RuntimeComponentRegistry Require<TService1, TService2>(Action<TService1, TService2> callback)
        where TService1 : class
        where TService2 : class
    {
        ArgumentNullException.ThrowIfNull(callback);
        _resolutions.Add(new RuntimeComponentResolution<TService1, TService2>(callback));
        return this;
    }

    public RuntimeComponentRegistry Optional<TService>(Action<TService> callback)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(callback);
        _resolutions.Add(new RuntimeOptionalComponentResolution<TService>(callback));
        return this;
    }

    internal RuntimeComponentResolver CreateResolver(
        RuntimeFeatureGraph graph,
        IReadOnlyDictionary<Type, object>? seededInstances = null)
    {
        ArgumentNullException.ThrowIfNull(graph);
        return new RuntimeComponentResolver(graph, _factories, _resolutions, seededInstances);
    }
}

internal sealed record RuntimeComponentFactoryRegistration(
    Func<RuntimeComponentResolver, object> Factory,
    bool TrackLifecycle);

public sealed class RuntimeComponentResolver
{
    private readonly IReadOnlyDictionary<Type, RuntimeComponentFactoryRegistration> _factories;
    private readonly IReadOnlyList<RuntimeComponentResolution> _resolutions;
    private readonly RuntimeComponentLifecycle _lifecycle = new();
    private readonly Dictionary<Type, object> _instances = new();
    private readonly object _initializationSync = new();
    private readonly object _sync = new();
    private int _graphInitialized;

    internal RuntimeComponentResolver(
        RuntimeFeatureGraph graph,
        IReadOnlyDictionary<Type, RuntimeComponentFactoryRegistration> factories,
        IReadOnlyList<RuntimeComponentResolution> resolutions,
        IReadOnlyDictionary<Type, object>? seededInstances = null)
    {
        Graph = graph;
        _factories = factories;
        _resolutions = resolutions;

        if (seededInstances is null)
        {
            return;
        }

        foreach (var (serviceType, instance) in seededInstances)
        {
            ArgumentNullException.ThrowIfNull(serviceType);
            ArgumentNullException.ThrowIfNull(instance);
            _instances[serviceType] = instance;
            _lifecycle.Track(instance);
        }
    }

    internal RuntimeFeatureGraph Graph { get; }

    internal RuntimeComponentLifecycle Lifecycle => _lifecycle;

    internal void InitializeGraph()
    {
        if (Volatile.Read(ref _graphInitialized) != 0)
        {
            return;
        }

        lock (_initializationSync)
        {
            if (_graphInitialized != 0)
            {
                return;
            }

            foreach (var resolution in _resolutions)
            {
                resolution.Invoke(this);
            }

            Volatile.Write(ref _graphInitialized, 1);
        }
    }

    public TService GetRequired<TService>()
        where TService : class
    {
        return GetOptional<TService>()
            ?? throw new InvalidOperationException($"Runtime component '{typeof(TService).Name}' is not registered.");
    }

    public TService? GetOptional<TService>()
        where TService : class
    {
        var serviceType = typeof(TService);

        lock (_sync)
        {
            if (_instances.TryGetValue(serviceType, out var existing))
            {
                return (TService)existing;
            }

            if (!_factories.TryGetValue(serviceType, out var registration))
            {
                if (!Graph.TryResolveService(serviceType, out var sharedService))
                {
                    return null;
                }

                _instances[serviceType] = sharedService;
                _lifecycle.Track(sharedService);
                return (TService)sharedService;
            }

            var created = registration.Factory(this);
            _instances[serviceType] = created;
            if (registration.TrackLifecycle)
            {
                _lifecycle.Track(created);
            }
            return (TService)created;
        }
    }
}

public interface IRuntimeOutboundHandlerFactory
{
    string Protocol { get; }

    IOutboundHandler Create(RuntimeComponentResolver resolver);
}

public interface IRuntimeBoundOutboundHandlerFactory : IRuntimeOutboundHandlerFactory
{
    IOutboundHandler Create(RuntimeComponentResolver resolver, OutboundRuntime outbound);
}

public sealed class RuntimeComponentCatalog
{
    public static RuntimeComponentCatalog Default { get; } = CreateDefault();

    private readonly RuntimeComponentRegistry _components;
    private readonly IReadOnlyList<IRuntimeInboundHandlerFactory> _inboundFactories;
    private readonly IReadOnlyList<IRuntimeOutboundHandlerFactory> _outboundFactories;

    private RuntimeComponentCatalog(
        RuntimeComponentRegistry components,
        IReadOnlyList<IRuntimeOutboundHandlerFactory> outboundFactories,
        IReadOnlyList<IRuntimeInboundHandlerFactory> inboundFactories)
    {
        _components = components;
        _inboundFactories = inboundFactories;
        _outboundFactories = outboundFactories;

        var supportedProtocols = new List<string>(_outboundFactories.Count);
        var seenProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var factory in _outboundFactories)
        {
            ArgumentNullException.ThrowIfNull(factory);

            var protocol = OutboundProtocols.Normalize(factory.Protocol);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new InvalidOperationException("Runtime outbound handler factory protocol cannot be empty.");
            }

            if (!seenProtocols.Add(protocol))
            {
                throw new InvalidOperationException($"Runtime outbound handler factory '{protocol}' is already registered.");
            }

            supportedProtocols.Add(protocol);
        }

        SupportedOutboundProtocols = supportedProtocols.ToArray();

        var supportedInboundProtocols = new List<string>(_inboundFactories.Count);
        var seenInboundProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var factory in _inboundFactories)
        {
            ArgumentNullException.ThrowIfNull(factory);

            var protocol = NormalizeProtocol(factory.Protocol);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new InvalidOperationException("Runtime inbound handler factory protocol cannot be empty.");
            }

            if (!seenInboundProtocols.Add(protocol))
            {
                throw new InvalidOperationException($"Runtime inbound handler factory '{protocol}' is already registered.");
            }

            supportedInboundProtocols.Add(protocol);
        }

        SupportedInboundProtocols = supportedInboundProtocols.ToArray();
    }

    public IReadOnlyList<string> SupportedOutboundProtocols { get; }

    public IReadOnlyList<string> SupportedInboundProtocols { get; }

    public bool SupportsOutboundProtocol(string? protocol)
        => !string.IsNullOrWhiteSpace(protocol) &&
           SupportedOutboundProtocols.Contains(
               OutboundProtocols.Normalize(protocol),
               StringComparer.OrdinalIgnoreCase);

    public bool SupportsInboundProtocol(string? protocol)
        => !string.IsNullOrWhiteSpace(protocol) &&
           SupportedInboundProtocols.Contains(
               NormalizeProtocol(protocol),
               StringComparer.OrdinalIgnoreCase);

    public static RuntimeComponentCatalog Create(
        Action<RuntimeComponentRegistry>? configureComponents = null,
        IEnumerable<IRuntimeOutboundHandlerFactory>? outboundFactories = null,
        IEnumerable<IRuntimeInboundHandlerFactory>? inboundFactories = null,
        bool replaceExistingOutboundFactories = false,
        bool replaceExistingInboundFactories = false)
    {
        var mergedOutboundFactories = MergeFactories(
            CreateDefaultOutboundFactories(),
            outboundFactories,
            static factory => OutboundProtocols.Normalize(factory.Protocol),
            replaceExistingOutboundFactories,
            static protocol => $"Runtime outbound handler factory '{protocol}' is already registered.");
        var mergedInboundFactories = MergeFactories(
            CreateDefaultInboundFactories(),
            inboundFactories,
            static factory => NormalizeProtocol(factory.Protocol),
            replaceExistingInboundFactories,
            static protocol => $"Runtime inbound handler factory '{protocol}' is already registered.");
        var components = CreateDefaultComponentRegistry(mergedOutboundFactories, mergedInboundFactories);
        configureComponents?.Invoke(components);

        return new RuntimeComponentCatalog(
            components,
            mergedOutboundFactories,
            mergedInboundFactories);
    }

    internal RuntimeComponentResolver CreateResolver(
        RuntimeFeatureGraph graph,
        IReadOnlyDictionary<Type, object>? seededInstances = null)
    {
        return _components.CreateResolver(graph, seededInstances);
    }

    private static RuntimeComponentCatalog CreateDefault()
    {
        var outboundFactories = CreateDefaultOutboundFactories();
        var inboundFactories = CreateDefaultInboundFactories();
        return new RuntimeComponentCatalog(
            CreateDefaultComponentRegistry(outboundFactories, inboundFactories),
            outboundFactories,
            inboundFactories);
    }

    private static RuntimeComponentRegistry CreateDefaultComponentRegistry(
        IReadOnlyList<IRuntimeOutboundHandlerFactory> outboundFactories,
        IReadOnlyList<IRuntimeInboundHandlerFactory> inboundFactories)
    {
        ArgumentNullException.ThrowIfNull(outboundFactories);
        ArgumentNullException.ThrowIfNull(inboundFactories);

        static IDispatcher ResolveDispatcher(RuntimeComponentResolver resolver)
            => resolver.GetRequired<IRuntimeDispatcherAccessor>().GetRequiredDispatcher();

        return new RuntimeComponentRegistry()
            .Require<IDispatcher, IRuntimeDispatcherController>((dispatcher, controller) => controller.SetDispatcher(dispatcher))
            .AddSingleton(_ => new TrojanUdpPacketReader())
            .AddSingleton(_ => new TrojanUdpPacketWriter())
            .AddSingleton(_ => new VlessUdpPacketReader())
            .AddSingleton(_ => new VlessUdpPacketWriter())
            .AddSingleton(_ => new DefaultRuntimeInboundComposition(inboundFactories))
            .AddSingleton<IRuntimeInboundComposition>(resolver => resolver.GetRequired<DefaultRuntimeInboundComposition>())
            .AddSingleton(_ => new DefaultRuntimeExecutionFactory())
            .AddSingleton<IRuntimeExecutionFactory>(resolver => resolver.GetRequired<DefaultRuntimeExecutionFactory>())
            .AddSingleton(resolver => CreateDefaultOutboundManager(resolver, outboundFactories))
            .AddSingleton<IOutboundManager>(resolver => resolver.GetRequired<DefaultOutboundManager>())
            .AddSingleton(resolver => new DefaultOutboundRouter(
                resolver.GetRequired<IOutboundManager>(),
                resolver.GetRequired<IRuntimeRoutingService>(),
                resolver.GetRequired<IOutboundRuntimePlanProvider>()))
            .AddSingleton<IOutboundRouter>(resolver => resolver.GetRequired<DefaultOutboundRouter>())
            .AddSingleton(resolver => new DefaultDispatcher(
                resolver.GetRequired<IOutboundRouter>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton<IDispatcher>(resolver => resolver.GetRequired<DefaultDispatcher>())
            .AddSingleton<IDokodemoUdpRedirectSupport>(_ => new DefaultDokodemoUdpRedirectSupport())
            .AddSingleton(resolver => new TrojanOutboundClient(new TrojanHandshakeWriter(), resolver.GetRequired<IDnsResolver>()))
            .AddSingleton(resolver => new Shadowsocks2022OutboundClient(
                resolver.GetRequired<IDnsResolver>(),
                resolver.GetRequired<IServiceProvider>()))
            .AddSingleton(resolver => new VlessOutboundClient(new VlessHandshakeWriter(), resolver.GetRequired<IDnsResolver>()))
            .AddSingleton(resolver => new VmessOutboundClient(new VmessHandshakeWriter(), resolver.GetRequired<IDnsResolver>()))
            .AddSingleton(_ => new Http2TunnelSessionPool())
            .AddSingleton(resolver => new DnsOutboundHandler(
                resolver.GetRequired<IOutboundCommonSettingsProvider>(),
                resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                resolver.GetRequired<IServiceProvider>(),
                resolver.GetRequired<IDnsResolver>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new FreedomOutboundHandler(
                resolver.GetRequired<IOutboundCommonSettingsProvider>(),
                resolver.GetRequired<IServiceProvider>(),
                resolver.GetRequired<IDnsResolver>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new TrojanOutboundHandler(
                resolver.GetRequired<TrojanOutboundClient>(),
                resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                resolver.GetRequired<IOutboundRuntimePlanProvider>(),
                resolver.GetRequired<TrojanUdpPacketReader>(),
                resolver.GetRequired<TrojanUdpPacketWriter>(),
                resolver.GetRequired<IServiceProvider>(),
                resolver.GetRequired<IDnsResolver>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new VlessOutboundHandler(
                resolver.GetRequired<VlessOutboundClient>(),
                resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                resolver.GetRequired<IOutboundRuntimePlanProvider>(),
                resolver.GetRequired<VlessUdpPacketReader>(),
                resolver.GetRequired<VlessUdpPacketWriter>(),
                resolver.GetRequired<IServiceProvider>(),
                resolver.GetRequired<IDnsResolver>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new VmessOutboundHandler(
                resolver.GetRequired<VmessOutboundClient>(),
                resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                resolver.GetRequired<IOutboundRuntimePlanProvider>(),
                resolver.GetRequired<IServiceProvider>(),
                resolver.GetRequired<IDnsResolver>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new SelectorOutboundHandler(
                resolver.GetRequired<IStrategyOutboundSettingsProvider>(),
                resolver.GetRequired<IStrategyOutboundProbeService>(),
                resolver.GetRequired<IServiceProvider>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new LoadBalanceOutboundHandler(
                resolver.GetRequired<IStrategyOutboundSettingsProvider>(),
                resolver.GetRequired<IStrategyOutboundProbeService>(),
                resolver.GetRequired<IServiceProvider>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new FallbackOutboundHandler(
                resolver.GetRequired<IStrategyOutboundSettingsProvider>(),
                resolver.GetRequired<IStrategyOutboundProbeService>(),
                resolver.GetRequired<IServiceProvider>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new UrlTestOutboundHandler(
                resolver.GetRequired<IStrategyOutboundSettingsProvider>(),
                resolver.GetRequired<IStrategyOutboundProbeService>(),
                resolver.GetRequired<IServiceProvider>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new LoopbackOutboundHandler(
                resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                resolver.GetRequired<IServiceProvider>()),
                trackLifecycle: false)
            .AddSingleton(resolver => new DokodemoInboundConnectionHandler(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new DokodemoUdpInboundServer(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeSniffer>(),
                resolver.GetRequired<IDokodemoUdpRedirectSupport>()))
            .AddSingleton(resolver => new DokodemoInboundServer(
                resolver.GetRequired<DokodemoInboundConnectionHandler>(),
                resolver.GetRequired<DokodemoUdpInboundServer>()))
            .AddSingleton(resolver => new TrojanMuxInboundServer(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new TrojanUdpAssociateRelay(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<TrojanUdpPacketReader>(),
                resolver.GetRequired<TrojanUdpPacketWriter>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new TrojanFallbackRelayService(
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IDnsResolver>()))
            .AddSingleton(resolver => new TrojanInboundConnectionHandler(
                ResolveDispatcher(resolver),
                new TrojanHandshakeReader(),
                resolver.GetRequired<TrojanUdpAssociateRelay>(),
                resolver.GetRequired<TrojanMuxInboundServer>(),
                resolver.GetRequired<TrojanFallbackRelayService>(),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new TrojanInboundServer(
                resolver.GetRequired<TrojanInboundConnectionHandler>()))
            .AddSingleton(resolver => new ShadowsocksInboundConnectionHandler(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new Shadowsocks2022InboundConnectionHandler(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new ShadowsocksUdpInboundServer(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new Shadowsocks2022UdpInboundServer(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new Shadowsocks2022InboundServer(
                resolver.GetRequired<Shadowsocks2022InboundConnectionHandler>(),
                resolver.GetRequired<Shadowsocks2022UdpInboundServer>()))
            .AddSingleton(resolver => new ShadowsocksInboundServer(
                resolver.GetRequired<ShadowsocksInboundConnectionHandler>(),
                resolver.GetRequired<Shadowsocks2022InboundServer>(),
                resolver.GetRequired<ShadowsocksUdpInboundServer>()))
            .AddSingleton(resolver => new VlessUdpRelay(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<VlessUdpPacketReader>(),
                resolver.GetRequired<VlessUdpPacketWriter>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new VlessInboundConnectionHandler(
                ResolveDispatcher(resolver),
                new VlessHandshakeReader(),
                resolver.GetRequired<TrojanMuxInboundServer>(),
                resolver.GetRequired<VlessUdpRelay>(),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<DefaultOutboundManager>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new VlessInboundServer(
                resolver.GetRequired<VlessInboundConnectionHandler>()))
            .AddSingleton(resolver => new VmessUdpRelay(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new VmessInboundConnectionHandler(
                ResolveDispatcher(resolver),
                new VmessHandshakeReader(),
                resolver.GetRequired<TrojanMuxInboundServer>(),
                resolver.GetRequired<VmessUdpRelay>(),
                resolver.GetRequired<IRuntimeSessionRegistry>(),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
                resolver.GetRequired<IRuntimeTrafficRegistry>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new VmessInboundServer(
                resolver.GetRequired<VmessInboundConnectionHandler>()))
            .AddSingleton(resolver => new SocksInboundServer(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeSniffer>()))
            .AddSingleton(resolver => new HttpInboundServer(
                ResolveDispatcher(resolver),
                resolver.GetRequired<IRuntimeRelayService>(),
                resolver.GetRequired<IRuntimeSniffer>()));
    }

    private static DefaultOutboundManager CreateDefaultOutboundManager(
        RuntimeComponentResolver resolver,
        IReadOnlyList<IRuntimeOutboundHandlerFactory> outboundFactories)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outboundFactories);

        var planProvider = resolver.GetRequired<IOutboundRuntimePlanProvider>();
        var manager = new DefaultOutboundManager(planProvider);
        var factoriesByProtocol = outboundFactories.ToDictionary(
            static factory => OutboundProtocols.Normalize(factory.Protocol),
            StringComparer.OrdinalIgnoreCase);

        foreach (var outbound in planProvider.GetCurrentOutboundPlan().Outbounds)
        {
            var protocol = OutboundProtocols.Normalize(outbound.Protocol);
            if (!factoriesByProtocol.TryGetValue(protocol, out var factory))
            {
                throw new InvalidOperationException($"Outbound '{outbound.Tag}' uses unsupported protocol '{outbound.Protocol}'.");
            }

            var handler = factory is IRuntimeBoundOutboundHandlerFactory boundFactory
                ? boundFactory.Create(resolver, outbound)
                : factory.Create(resolver);
            manager.AddHandler(outbound.Tag, handler);
        }

        return manager;
    }

    private static IReadOnlyList<IRuntimeOutboundHandlerFactory> CreateDefaultOutboundFactories()
    {
        return
        [
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Dns,
                static (resolver, _) => resolver.GetRequired<DnsOutboundHandler>(),
                static resolver => resolver.GetRequired<DnsOutboundHandler>()),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Freedom,
                (resolver, outbound) => new FreedomOutboundHandler(
                    new FixedOutboundCommonSettingsProvider(ResolveOutboundCommonSettings(resolver, outbound)),
                    resolver.GetRequired<IServiceProvider>(),
                    resolver.GetRequired<IDnsResolver>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Blackhole,
                static (_, _) => new BlackholeOutboundHandler()),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Shadowsocks,
                (resolver, outbound) => CreateShadowsocksOutboundHandler(resolver, outbound)),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Socks,
                (resolver, _) => new SocksOutboundHandler(
                    resolver.GetRequired<IOutboundCommonSettingsProvider>(),
                    resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                    resolver.GetRequired<IServiceProvider>(),
                    resolver.GetRequired<IDnsResolver>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Http,
                (resolver, _) => new HttpOutboundHandler(
                    resolver.GetRequired<IOutboundCommonSettingsProvider>(),
                    resolver.GetRequired<IRuntimeOutboundSettingsProvider>(),
                    resolver.GetRequired<IServiceProvider>(),
                    resolver.GetRequired<IDnsResolver>(),
                    internetProfile: null,
                    http2TunnelSessionPool: resolver.GetRequired<Http2TunnelSessionPool>())),
            new ResolvedRuntimeOutboundHandlerFactory<LoopbackOutboundHandler>(
                OutboundProtocols.Loopback),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Trojan,
                (resolver, outbound) => new TrojanOutboundHandler(
                    resolver.GetRequired<TrojanOutboundClient>(),
                    new FixedTrojanOutboundSettingsProvider(ResolveTrojanOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<TrojanUdpPacketReader>(),
                    resolver.GetRequired<TrojanUdpPacketWriter>(),
                    resolver.GetRequired<IServiceProvider>(),
                    resolver.GetRequired<IDnsResolver>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Vless,
                (resolver, outbound) => new VlessOutboundHandler(
                    resolver.GetRequired<VlessOutboundClient>(),
                    new FixedVlessOutboundSettingsProvider(ResolveVlessOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<VlessUdpPacketReader>(),
                    resolver.GetRequired<VlessUdpPacketWriter>(),
                    resolver.GetRequired<IServiceProvider>(),
                    resolver.GetRequired<IDnsResolver>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Vmess,
                (resolver, outbound) => new VmessOutboundHandler(
                    resolver.GetRequired<VmessOutboundClient>(),
                    new FixedVmessOutboundSettingsProvider(ResolveVmessOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<IServiceProvider>(),
                    resolver.GetRequired<IDnsResolver>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Selector,
                (resolver, outbound) => new SelectorOutboundHandler(
                    new FixedStrategyOutboundSettingsProvider(ResolveStrategyOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<IStrategyOutboundProbeService>(),
                    resolver.GetRequired<IServiceProvider>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.LoadBalance,
                (resolver, outbound) => new LoadBalanceOutboundHandler(
                    new FixedStrategyOutboundSettingsProvider(ResolveStrategyOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<IStrategyOutboundProbeService>(),
                    resolver.GetRequired<IServiceProvider>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.Fallback,
                (resolver, outbound) => new FallbackOutboundHandler(
                    new FixedStrategyOutboundSettingsProvider(ResolveStrategyOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<IStrategyOutboundProbeService>(),
                    resolver.GetRequired<IServiceProvider>())),
            new DelegatedRuntimeOutboundHandlerFactory(
                OutboundProtocols.UrlTest,
                (resolver, outbound) => new UrlTestOutboundHandler(
                    new FixedStrategyOutboundSettingsProvider(ResolveStrategyOutboundSettings(resolver, outbound)),
                    resolver.GetRequired<IStrategyOutboundProbeService>(),
                    resolver.GetRequired<IServiceProvider>()))
        ];
    }

    private static DispatchContext CreateOutboundResolutionContext(string tag)
        => new()
        {
            OutboundTag = tag
        };

    private static OutboundCommonSettings ResolveOutboundCommonSettings(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var provider = resolver.GetRequired<IOutboundCommonSettingsProvider>();
        if (provider.TryResolve(CreateOutboundResolutionContext(outbound.Tag), out OutboundCommonSettings settings))
        {
            return settings;
        }

        throw new InvalidOperationException($"Outbound settings for '{outbound.Tag}' could not be resolved.");
    }

    private static IOutboundHandler CreateShadowsocksOutboundHandler(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var context = CreateOutboundResolutionContext(outbound.Tag);
        var settingsProvider = resolver.GetRequired<IRuntimeOutboundSettingsProvider>();
        if (settingsProvider.TryResolve(context, out IRuntimeOutboundOptions runtimeOptions) &&
            string.Equals(
                OutboundProtocols.Normalize(runtimeOptions.Protocol),
                OutboundProtocols.Shadowsocks,
                StringComparison.Ordinal) &&
            ShadowsocksOutboundOptionsCompiler.TryCompile(runtimeOptions, out var compiled, out _) &&
            compiled is RuntimeShadowsocks2022OutboundOptions)
        {
            return new Shadowsocks2022OutboundHandler(
                resolver.GetRequired<Shadowsocks2022OutboundClient>(),
                new FixedShadowsocks2022OutboundSettingsProvider(
                    ResolveShadowsocks2022OutboundSettings(resolver, outbound)));
        }

        return new ShadowsocksOutboundHandler(
            resolver.GetRequired<IOutboundCommonSettingsProvider>(),
            settingsProvider,
            resolver.GetRequired<IServiceProvider>(),
            resolver.GetRequired<IDnsResolver>());
    }

    private static TrojanOutboundSettings ResolveTrojanOutboundSettings(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var provider = resolver.GetRequired<ITrojanOutboundSettingsProvider>();
        if (provider.TryResolve(CreateOutboundResolutionContext(outbound.Tag), out TrojanOutboundSettings settings))
        {
            return settings;
        }

        throw new InvalidOperationException($"Trojan outbound settings for '{outbound.Tag}' could not be resolved.");
    }

    private static Shadowsocks2022OutboundSettings ResolveShadowsocks2022OutboundSettings(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var provider = resolver.GetRequired<IShadowsocks2022OutboundSettingsProvider>();
        if (provider.TryResolve(CreateOutboundResolutionContext(outbound.Tag), out Shadowsocks2022OutboundSettings settings))
        {
            return settings;
        }

        throw new InvalidOperationException($"Shadowsocks 2022 outbound settings for '{outbound.Tag}' could not be resolved.");
    }

    private static VlessOutboundSettings ResolveVlessOutboundSettings(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var provider = resolver.GetRequired<IVlessOutboundSettingsProvider>();
        if (provider.TryResolve(CreateOutboundResolutionContext(outbound.Tag), out VlessOutboundSettings settings))
        {
            return settings;
        }

        throw new InvalidOperationException($"VLESS outbound settings for '{outbound.Tag}' could not be resolved.");
    }

    private static VmessOutboundSettings ResolveVmessOutboundSettings(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var provider = resolver.GetRequired<IVmessOutboundSettingsProvider>();
        if (provider.TryResolve(CreateOutboundResolutionContext(outbound.Tag), out VmessOutboundSettings settings))
        {
            return settings;
        }

        throw new InvalidOperationException($"VMess outbound settings for '{outbound.Tag}' could not be resolved.");
    }

    private static StrategyOutboundSettings ResolveStrategyOutboundSettings(
        RuntimeComponentResolver resolver,
        OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);

        var provider = resolver.GetRequired<IStrategyOutboundSettingsProvider>();
        if (provider.TryResolve(CreateOutboundResolutionContext(outbound.Tag), out StrategyOutboundSettings settings))
        {
            return settings;
        }

        throw new InvalidOperationException($"Strategy outbound settings for '{outbound.Tag}' could not be resolved.");
    }

    private static IReadOnlyList<IRuntimeInboundHandlerFactory> CreateDefaultInboundFactories()
    {
        return
        [
            new DokodemoInboundHandlerFactory(),
            new TrojanInboundHandlerFactory(),
            new ShadowsocksInboundHandlerFactory(),
            new VlessInboundHandlerFactory(),
            new VmessInboundHandlerFactory(),
            new SocksInboundHandlerFactory(),
            new HttpInboundHandlerFactory()
        ];
    }

    private static string NormalizeProtocol(string? protocol)
        => string.IsNullOrWhiteSpace(protocol)
            ? string.Empty
            : protocol.Trim().ToLowerInvariant();

    private static IReadOnlyList<TFactory> MergeFactories<TFactory>(
        IReadOnlyList<TFactory> defaults,
        IEnumerable<TFactory>? overrides,
        Func<TFactory, string> protocolSelector,
        bool replaceExisting,
        Func<string, string> duplicateMessageFactory)
        where TFactory : class
    {
        ArgumentNullException.ThrowIfNull(defaults);
        ArgumentNullException.ThrowIfNull(protocolSelector);
        ArgumentNullException.ThrowIfNull(duplicateMessageFactory);

        var merged = defaults.ToList();
        var indexByProtocol = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < defaults.Count; index++)
        {
            var factory = defaults[index] ?? throw new InvalidOperationException("Runtime handler factory cannot be null.");
            var protocol = protocolSelector(factory);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new InvalidOperationException("Runtime handler factory protocol cannot be empty.");
            }

            indexByProtocol[protocol] = index;
        }

        var providedProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var factory in overrides ?? Array.Empty<TFactory>())
        {
            ArgumentNullException.ThrowIfNull(factory);

            var protocol = protocolSelector(factory);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new InvalidOperationException("Runtime handler factory protocol cannot be empty.");
            }

            if (!providedProtocols.Add(protocol))
            {
                throw new InvalidOperationException(duplicateMessageFactory(protocol));
            }

            if (indexByProtocol.TryGetValue(protocol, out var existingIndex))
            {
                if (!replaceExisting)
                {
                    throw new InvalidOperationException(duplicateMessageFactory(protocol));
                }

                merged[existingIndex] = factory;
                continue;
            }

            indexByProtocol[protocol] = merged.Count;
            merged.Add(factory);
        }

        return merged.ToArray();
    }
}

public sealed class ResolvedRuntimeOutboundHandlerFactory<THandler> : IRuntimeOutboundHandlerFactory
    where THandler : class, IOutboundHandler
{
    public ResolvedRuntimeOutboundHandlerFactory(string protocol)
    {
        Protocol = OutboundProtocols.Normalize(protocol);
    }

    public string Protocol { get; }

    public IOutboundHandler Create(RuntimeComponentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        return resolver.GetRequired<THandler>();
    }
}

public sealed class DelegatedRuntimeOutboundHandlerFactory : IRuntimeBoundOutboundHandlerFactory
{
    private readonly Func<RuntimeComponentResolver, OutboundRuntime, IOutboundHandler> _boundFactory;
    private readonly Func<RuntimeComponentResolver, IOutboundHandler>? _sharedFactory;

    public DelegatedRuntimeOutboundHandlerFactory(
        string protocol,
        Func<RuntimeComponentResolver, OutboundRuntime, IOutboundHandler> boundFactory,
        Func<RuntimeComponentResolver, IOutboundHandler>? sharedFactory = null)
    {
        Protocol = OutboundProtocols.Normalize(protocol);
        _boundFactory = boundFactory ?? throw new ArgumentNullException(nameof(boundFactory));
        _sharedFactory = sharedFactory;
    }

    public string Protocol { get; }

    public IOutboundHandler Create(RuntimeComponentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        if (_sharedFactory is null)
        {
            throw new InvalidOperationException(
                $"Runtime outbound handler factory '{Protocol}' requires an outbound runtime instance.");
        }

        return _sharedFactory(resolver);
    }

    public IOutboundHandler Create(RuntimeComponentResolver resolver, OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outbound);
        return _boundFactory(resolver, outbound);
    }
}

internal sealed class FixedOutboundCommonSettingsProvider : IOutboundCommonSettingsProvider
{
    private readonly OutboundCommonSettings _settings;

    public FixedOutboundCommonSettingsProvider(OutboundCommonSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
    {
        settings = _settings;
        return true;
    }
}

internal sealed class FixedTrojanOutboundSettingsProvider : ITrojanOutboundSettingsProvider
{
    private readonly TrojanOutboundSettings _settings;

    public FixedTrojanOutboundSettingsProvider(TrojanOutboundSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
    {
        settings = _settings;
        return true;
    }
}

internal sealed class FixedShadowsocks2022OutboundSettingsProvider : IShadowsocks2022OutboundSettingsProvider
{
    private readonly Shadowsocks2022OutboundSettings _settings;

    public FixedShadowsocks2022OutboundSettingsProvider(Shadowsocks2022OutboundSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public bool TryResolve(DispatchContext context, out Shadowsocks2022OutboundSettings settings)
    {
        settings = _settings;
        return true;
    }
}

internal sealed class FixedVlessOutboundSettingsProvider : IVlessOutboundSettingsProvider
{
    private readonly VlessOutboundSettings _settings;

    public FixedVlessOutboundSettingsProvider(VlessOutboundSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public bool TryResolve(DispatchContext context, out VlessOutboundSettings settings)
    {
        settings = _settings;
        return true;
    }
}

internal sealed class FixedVmessOutboundSettingsProvider : IVmessOutboundSettingsProvider
{
    private readonly VmessOutboundSettings _settings;

    public FixedVmessOutboundSettingsProvider(VmessOutboundSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public bool TryResolve(DispatchContext context, out VmessOutboundSettings settings)
    {
        settings = _settings;
        return true;
    }
}

internal sealed class FixedStrategyOutboundSettingsProvider : IStrategyOutboundSettingsProvider
{
    private readonly StrategyOutboundSettings _settings;

    public FixedStrategyOutboundSettingsProvider(StrategyOutboundSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    public bool TryResolve(DispatchContext context, out StrategyOutboundSettings settings)
    {
        settings = _settings;
        return true;
    }
}

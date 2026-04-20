namespace NodePanel.Core.Runtime;

internal sealed class RuntimeFeatureGraph
{
    public RuntimeFeatureGraph(
        IRuntimePlanState planState,
        IRuntimeRoutingService routingService,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeRelayService relayService,
        IDnsResolver dnsResolver,
        IFakeDnsEngine fakeDnsEngine,
        IRuntimeSniffer sniffer,
        IRuntimeUserStore userStore,
        IStrategyOutboundProbeService strategyProbeService,
        IRuntimeDispatcherController dispatcherController)
    {
        PlanState = planState ?? throw new ArgumentNullException(nameof(planState));
        RoutingService = routingService ?? throw new ArgumentNullException(nameof(routingService));
        SessionRegistry = sessionRegistry ?? throw new ArgumentNullException(nameof(sessionRegistry));
        TrafficRegistry = trafficRegistry ?? throw new ArgumentNullException(nameof(trafficRegistry));
        RateLimiterRegistry = rateLimiterRegistry ?? throw new ArgumentNullException(nameof(rateLimiterRegistry));
        RelayService = relayService ?? throw new ArgumentNullException(nameof(relayService));
        DnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
        FakeDnsEngine = fakeDnsEngine ?? throw new ArgumentNullException(nameof(fakeDnsEngine));
        Sniffer = sniffer ?? throw new ArgumentNullException(nameof(sniffer));
        UserStore = userStore ?? throw new ArgumentNullException(nameof(userStore));
        StrategyProbeService = strategyProbeService ?? throw new ArgumentNullException(nameof(strategyProbeService));
        DispatcherController = dispatcherController ?? throw new ArgumentNullException(nameof(dispatcherController));
        StrategyProbeCache = strategyProbeService as IStrategyOutboundProbeCache;
    }

    public IRuntimePlanState PlanState { get; }

    public IRuntimeRoutingService RoutingService { get; }

    public IRuntimeSessionRegistry SessionRegistry { get; }

    public IRuntimeTrafficRegistry TrafficRegistry { get; }

    public IRuntimeRateLimiterRegistry RateLimiterRegistry { get; }

    public IRuntimeRelayService RelayService { get; }

    public IDnsResolver DnsResolver { get; }

    public IFakeDnsEngine FakeDnsEngine { get; }

    public IRuntimeSniffer Sniffer { get; }

    public IRuntimeUserStore UserStore { get; }

    public IStrategyOutboundProbeService StrategyProbeService { get; }

    public IStrategyOutboundProbeCache? StrategyProbeCache { get; }

    public IRuntimeDispatcherController DispatcherController { get; }

    public static RuntimeFeatureGraph CreateDefault()
    {
        var planState = new RuntimePlanState();
        var dispatcherController = new RuntimeDispatcherServices();
        var fakeDnsEngine = new RuntimeFakeDnsEngine(planState);
        var sniffer = new DefaultRuntimeSniffer(fakeDnsEngine);
        var graph = new RuntimeFeatureGraph(
            planState,
            new DefaultRuntimeRoutingService(planState),
            new SessionRegistry(),
            new TrafficRegistry(),
            new RateLimiterRegistry(),
            new RelayService(),
            new RuntimeDnsResolver(planState, fakeDnsEngine: fakeDnsEngine),
            fakeDnsEngine,
            sniffer,
            new UserStore(),
            new DefaultStrategyOutboundProbeService(dispatcherController),
            dispatcherController);
        planState.Apply(RuntimePlan.Empty);
        return graph;
    }

    public RuntimeFeatureGraphActivation Activate(
        RuntimeComponentCatalog components,
        RuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(components);
        ArgumentNullException.ThrowIfNull(plan);

        var bootstrapResolver = components.CreateResolver(this);
        var bootstrapGraph = WithBootstrapOverrides(
            bootstrapResolver.GetRequired<IRuntimePlanState>(),
            bootstrapResolver.GetRequired<IRuntimeDispatcherController>());
        bootstrapGraph.PlanState.Apply(plan);

        var resolver = components.CreateResolver(
            bootstrapGraph,
            bootstrapGraph.CreateSeededInstances());

        return new RuntimeFeatureGraphActivation(
            bootstrapGraph.WithResolvedRuntimeServices(resolver),
            resolver);
    }

    public IReadOnlyDictionary<Type, object> CreateSeededInstances()
    {
        var seededInstances = new Dictionary<Type, object>
        {
            [typeof(IRuntimePlanState)] = PlanState,
            [typeof(IRuntimeDispatcherController)] = DispatcherController
        };

        if (PlanState is RuntimePlanState runtimePlanState)
        {
            seededInstances[typeof(RuntimePlanState)] = runtimePlanState;
        }

        if (DispatcherController is RuntimeDispatcherServices runtimeDispatcherServices)
        {
            seededInstances[typeof(RuntimeDispatcherServices)] = runtimeDispatcherServices;
        }

        return seededInstances;
    }

    internal bool TryResolveService(Type serviceType, out object service)
    {
        ArgumentNullException.ThrowIfNull(serviceType);

        if (serviceType == typeof(IRuntimePlanState))
        {
            service = PlanState;
            return true;
        }

        if (serviceType == typeof(RuntimePlanState) &&
            PlanState is RuntimePlanState runtimePlanState)
        {
            service = runtimePlanState;
            return true;
        }

        if (serviceType == typeof(IOutboundRuntimePlanProvider) ||
            serviceType == typeof(IOutboundCommonSettingsProvider) ||
            serviceType == typeof(IRuntimeOutboundSettingsProvider) ||
            serviceType == typeof(IShadowsocks2022OutboundSettingsProvider) ||
            serviceType == typeof(ITrojanOutboundSettingsProvider) ||
            serviceType == typeof(IVlessOutboundSettingsProvider) ||
            serviceType == typeof(IVmessOutboundSettingsProvider) ||
            serviceType == typeof(IStrategyOutboundSettingsProvider) ||
            serviceType == typeof(IDnsRuntimeSettingsProvider))
        {
            service = PlanState;
            return true;
        }

        if (serviceType == typeof(IRuntimeRoutingService))
        {
            service = RoutingService;
            return true;
        }

        if (serviceType == typeof(DefaultRuntimeRoutingService) &&
            RoutingService is DefaultRuntimeRoutingService defaultRuntimeRoutingService)
        {
            service = defaultRuntimeRoutingService;
            return true;
        }

        if (serviceType == typeof(IDnsResolver))
        {
            service = DnsResolver;
            return true;
        }

        if (serviceType == typeof(IFakeDnsEngine))
        {
            service = FakeDnsEngine;
            return true;
        }

        if (serviceType == typeof(IRuntimeSniffer))
        {
            service = Sniffer;
            return true;
        }

        if (serviceType == typeof(RuntimeDnsResolver) &&
            DnsResolver is RuntimeDnsResolver runtimeDnsResolver)
        {
            service = runtimeDnsResolver;
            return true;
        }

        if (serviceType == typeof(RuntimeFakeDnsEngine) &&
            FakeDnsEngine is RuntimeFakeDnsEngine runtimeFakeDnsEngine)
        {
            service = runtimeFakeDnsEngine;
            return true;
        }

        if (serviceType == typeof(DefaultRuntimeSniffer) &&
            Sniffer is DefaultRuntimeSniffer defaultRuntimeSniffer)
        {
            service = defaultRuntimeSniffer;
            return true;
        }

        if (serviceType == typeof(IRuntimeSessionRegistry))
        {
            service = SessionRegistry;
            return true;
        }

        if (serviceType == typeof(SessionRegistry) &&
            SessionRegistry is SessionRegistry sessionRegistry)
        {
            service = sessionRegistry;
            return true;
        }

        if (serviceType == typeof(IRuntimeTrafficRegistry))
        {
            service = TrafficRegistry;
            return true;
        }

        if (serviceType == typeof(TrafficRegistry) &&
            TrafficRegistry is TrafficRegistry trafficRegistry)
        {
            service = trafficRegistry;
            return true;
        }

        if (serviceType == typeof(IRuntimeRateLimiterRegistry))
        {
            service = RateLimiterRegistry;
            return true;
        }

        if (serviceType == typeof(RateLimiterRegistry) &&
            RateLimiterRegistry is RateLimiterRegistry rateLimiterRegistry)
        {
            service = rateLimiterRegistry;
            return true;
        }

        if (serviceType == typeof(IRuntimeRelayService))
        {
            service = RelayService;
            return true;
        }

        if (serviceType == typeof(RelayService) &&
            RelayService is RelayService relayService)
        {
            service = relayService;
            return true;
        }

        if (serviceType == typeof(IRuntimeUserStore))
        {
            service = UserStore;
            return true;
        }

        if (serviceType == typeof(UserStore) &&
            UserStore is UserStore userStore)
        {
            service = userStore;
            return true;
        }

        if (serviceType == typeof(IStrategyOutboundProbeService))
        {
            service = StrategyProbeService;
            return true;
        }

        if (serviceType == typeof(IStrategyOutboundProbeCache) &&
            StrategyProbeService is IStrategyOutboundProbeCache strategyProbeCache)
        {
            service = strategyProbeCache;
            return true;
        }

        if (serviceType == typeof(IRuntimeDispatcherController) ||
            serviceType == typeof(IRuntimeDispatcherAccessor) ||
            serviceType == typeof(IServiceProvider))
        {
            service = DispatcherController;
            return true;
        }

        if (serviceType == typeof(RuntimeDispatcherServices) &&
            DispatcherController is RuntimeDispatcherServices runtimeDispatcherServices)
        {
            service = runtimeDispatcherServices;
            return true;
        }

        service = default!;
        return false;
    }

    private RuntimeFeatureGraph WithBootstrapOverrides(
        IRuntimePlanState planState,
        IRuntimeDispatcherController dispatcherController)
    {
        ArgumentNullException.ThrowIfNull(planState);
        ArgumentNullException.ThrowIfNull(dispatcherController);

        var dnsResolver = DnsResolver;
        var fakeDnsEngine = FakeDnsEngine;
        var sniffer = Sniffer;
        var routingService = RoutingService;
        if (!ReferenceEquals(PlanState, planState))
        {
            if (FakeDnsEngine is RuntimeFakeDnsEngine)
            {
                fakeDnsEngine = new RuntimeFakeDnsEngine(planState);
            }

            if (DnsResolver is RuntimeDnsResolver)
            {
                dnsResolver = new RuntimeDnsResolver(planState, fakeDnsEngine: fakeDnsEngine);
            }

            if (Sniffer is DefaultRuntimeSniffer)
            {
                sniffer = new DefaultRuntimeSniffer(fakeDnsEngine);
            }
        }

        if (RoutingService is DefaultRuntimeRoutingService)
        {
            routingService = new DefaultRuntimeRoutingService(planState);
        }

        var strategyProbeService = StrategyProbeService;
        if (!ReferenceEquals(DispatcherController, dispatcherController) &&
            StrategyProbeService is DefaultStrategyOutboundProbeService)
        {
            strategyProbeService = new DefaultStrategyOutboundProbeService(dispatcherController);
        }

        return new RuntimeFeatureGraph(
            planState,
            routingService,
            SessionRegistry,
            TrafficRegistry,
            RateLimiterRegistry,
            RelayService,
            dnsResolver,
            fakeDnsEngine,
            sniffer,
            UserStore,
            strategyProbeService,
            dispatcherController);
    }

    private RuntimeFeatureGraph WithResolvedRuntimeServices(RuntimeComponentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        return new RuntimeFeatureGraph(
            PlanState,
            resolver.GetRequired<IRuntimeRoutingService>(),
            resolver.GetRequired<IRuntimeSessionRegistry>(),
            resolver.GetRequired<IRuntimeTrafficRegistry>(),
            resolver.GetRequired<IRuntimeRateLimiterRegistry>(),
            resolver.GetRequired<IRuntimeRelayService>(),
            resolver.GetRequired<IDnsResolver>(),
            resolver.GetRequired<IFakeDnsEngine>(),
            resolver.GetRequired<IRuntimeSniffer>(),
            resolver.GetRequired<IRuntimeUserStore>(),
            resolver.GetRequired<IStrategyOutboundProbeService>(),
            DispatcherController);
    }
}

internal sealed record RuntimeFeatureGraphActivation(
    RuntimeFeatureGraph Graph,
    RuntimeComponentResolver Resolver);

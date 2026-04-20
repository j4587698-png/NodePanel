namespace NodePanel.Core.Runtime;

public sealed class DefaultOutboundRouter : IOutboundRouter
{
    private readonly IOutboundManager _outboundManager;
    private readonly IOutboundRuntimePlanProvider _planProvider;
    private readonly IRuntimeRoutingService _routingService;

    public DefaultOutboundRouter(
        IOutboundManager outboundManager,
        IRuntimeRoutingService routingService,
        IOutboundRuntimePlanProvider planProvider)
    {
        ArgumentNullException.ThrowIfNull(outboundManager);
        ArgumentNullException.ThrowIfNull(routingService);
        ArgumentNullException.ThrowIfNull(planProvider);

        _outboundManager = outboundManager;
        _planProvider = planProvider;
        _routingService = routingService;
    }

    public DefaultOutboundRouter(
        IOutboundManager outboundManager,
        IOutboundRuntimePlanProvider planProvider)
        : this(outboundManager, new DefaultRuntimeRoutingService(planProvider), planProvider)
    {
    }

    public DefaultOutboundRouter(
        IEnumerable<IOutboundHandler> outbounds,
        IOutboundRuntimePlanProvider planProvider)
        : this(new DefaultOutboundManager(outbounds, planProvider), planProvider)
    {
    }

    public ResolvedOutboundRoute Resolve(DispatchContext context, DispatchDestination? destination)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (_routingService.TryPickRoute(context, out var route) &&
            _outboundManager.GetHandler(route.OutboundTag) is { } handler)
        {
            return new ResolvedOutboundRoute
            {
                Handler = handler,
                Context = context with
                {
                    OutboundTag = route.OutboundTag
                },
                OutboundTag = route.OutboundTag,
                RuleTag = route.RuleTag,
                OutboundGroupTags = route.OutboundGroupTags
            };
        }

        var defaultTag = _planProvider.GetCurrentOutboundPlan().DefaultOutboundTag;
        return new ResolvedOutboundRoute
        {
            Handler = _outboundManager.GetDefaultHandler(),
            Context = string.IsNullOrWhiteSpace(defaultTag)
                ? context
                : context with
                {
                    OutboundTag = defaultTag.Trim()
                },
            OutboundTag = string.IsNullOrWhiteSpace(defaultTag) ? string.Empty : defaultTag.Trim()
        };
    }
}

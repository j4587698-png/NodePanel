namespace NodePanel.Core.Runtime;

public sealed class DefaultOutboundRouter : IOutboundRouter
{
    private readonly IOutboundHandler _fallbackOutbound;
    private readonly IReadOnlyDictionary<string, IOutboundHandler> _outboundsByProtocol;
    private readonly IOutboundRuntimePlanProvider _planProvider;

    public DefaultOutboundRouter(
        IEnumerable<IOutboundHandler> outbounds,
        IOutboundRuntimePlanProvider planProvider)
    {
        var materialized = outbounds.ToArray();
        if (materialized.Length == 0)
        {
            throw new InvalidOperationException("At least one outbound handler must be registered.");
        }

        _outboundsByProtocol = materialized.ToDictionary(
            static outbound => OutboundProtocols.Normalize(outbound.Protocol),
            StringComparer.OrdinalIgnoreCase);

        _fallbackOutbound = materialized.FirstOrDefault(static outbound =>
            string.Equals(OutboundProtocols.Normalize(outbound.Protocol), OutboundProtocols.Freedom, StringComparison.Ordinal))
            ?? materialized[0];
        _planProvider = planProvider;
    }

    public IOutboundHandler Resolve(DispatchContext context, DispatchDestination? destination)
    {
        ArgumentNullException.ThrowIfNull(context);

        var plan = _planProvider.GetCurrentOutboundPlan();
        if (TryResolveConfiguredOutbound(plan, context, out var outbound) &&
            _outboundsByProtocol.TryGetValue(OutboundProtocols.Normalize(outbound.Protocol), out var handler))
        {
            return handler;
        }

        var defaultOutbound = plan.GetDefaultOutbound();
        if (defaultOutbound is not null &&
            _outboundsByProtocol.TryGetValue(OutboundProtocols.Normalize(defaultOutbound.Protocol), out handler))
        {
            return handler;
        }

        return _fallbackOutbound;
    }

    private static bool TryResolveConfiguredOutbound(
        OutboundRuntimePlan plan,
        DispatchContext context,
        out OutboundRuntime outbound)
    {
        if (plan.TryResolveOutboundTag(context, out var outboundTag) &&
            plan.TryGetOutbound(outboundTag, out outbound))
        {
            return true;
        }

        outbound = default!;
        return false;
    }
}

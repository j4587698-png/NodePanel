namespace NodePanel.Core.Runtime;

public sealed class DefaultRuntimeRoutingService : IRuntimeRoutingService
{
    private readonly IOutboundRuntimePlanProvider _planProvider;
    private readonly object _sync = new();
    private OutboundRuntimePlan? _overridePlan;

    public DefaultRuntimeRoutingService(IOutboundRuntimePlanProvider planProvider)
    {
        _planProvider = planProvider ?? throw new ArgumentNullException(nameof(planProvider));
    }

    public bool TryPickRoute(DispatchContext context, out OutboundRouteDecision route)
        => GetCurrentPlan().TryPickRoute(context, out route);

    public OutboundRouteDecision PickRoute(DispatchContext context)
    {
        if (TryPickRoute(context, out var route))
        {
            return route;
        }

        throw new InvalidOperationException("Routing service could not resolve a matching route.");
    }

    public void AddRule(IRoutingRuleDefinition rule, bool shouldAppend = true)
    {
        ArgumentNullException.ThrowIfNull(rule);
        AddRules([rule], shouldAppend);
    }

    public void AddRules(IReadOnlyList<IRoutingRuleDefinition> rules, bool shouldAppend)
    {
        ArgumentNullException.ThrowIfNull(rules);

        lock (_sync)
        {
            var currentPlan = GetCurrentPlanLocked();
            if (!OutboundRuntimePlanner.TryNormalizeRules(rules, currentPlan.Outbounds, out var normalizedRules, out var error))
            {
                throw new InvalidOperationException(error ?? "Routing rule normalization failed.");
            }

            if (shouldAppend && normalizedRules.Count == 0)
            {
                return;
            }

            ValidateDuplicateRuleTags(
                shouldAppend ? currentPlan.RoutingRules : Array.Empty<RoutingRuleRuntime>(),
                normalizedRules);

            var updatedRules = shouldAppend
                ? currentPlan.RoutingRules.Concat(normalizedRules).ToArray()
                : normalizedRules.ToArray();

            Volatile.Write(ref _overridePlan, currentPlan with
            {
                RoutingRules = updatedRules
            });
        }
    }

    public bool RemoveRule(string ruleTag)
    {
        if (string.IsNullOrWhiteSpace(ruleTag))
        {
            return false;
        }

        lock (_sync)
        {
            var currentPlan = GetCurrentPlanLocked();
            var normalizedRuleTag = ruleTag.Trim();
            var remainingRules = currentPlan.RoutingRules
                .Where(rule => !string.Equals(rule.RuleTag, normalizedRuleTag, StringComparison.Ordinal))
                .ToArray();
            if (remainingRules.Length == currentPlan.RoutingRules.Count)
            {
                return false;
            }

            Volatile.Write(ref _overridePlan, currentPlan with
            {
                RoutingRules = remainingRules
            });
            return true;
        }
    }

    public IReadOnlyList<RoutingRuleRuntime> ListRules()
        => GetCurrentPlan().RoutingRules.ToArray();

    private OutboundRuntimePlan GetCurrentPlan()
        => Volatile.Read(ref _overridePlan) ?? _planProvider.GetCurrentOutboundPlan();

    private OutboundRuntimePlan GetCurrentPlanLocked()
        => _overridePlan ?? _planProvider.GetCurrentOutboundPlan();

    private static void ValidateDuplicateRuleTags(
        IReadOnlyList<RoutingRuleRuntime> existingRules,
        IReadOnlyList<RoutingRuleRuntime> incomingRules)
    {
        var seenRuleTags = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < existingRules.Count; index++)
        {
            if (!string.IsNullOrWhiteSpace(existingRules[index].RuleTag))
            {
                seenRuleTags.Add(existingRules[index].RuleTag);
            }
        }

        for (var index = 0; index < incomingRules.Count; index++)
        {
            var ruleTag = incomingRules[index].RuleTag;
            if (string.IsNullOrWhiteSpace(ruleTag))
            {
                continue;
            }

            if (!seenRuleTags.Add(ruleTag))
            {
                throw new InvalidOperationException($"Routing rule tag '{ruleTag}' is already registered.");
            }
        }
    }
}

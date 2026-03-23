namespace NodePanel.Core.Runtime;

public interface IInboundProtocolRuntimePlan
{
    string Protocol { get; }

    bool RequiresCertificate { get; }
}

public sealed record InboundRuntimePlanCollection
{
    public static InboundRuntimePlanCollection Empty { get; } = new();

    public IReadOnlyDictionary<string, IInboundProtocolRuntimePlan> Plans { get; init; }
        = new Dictionary<string, IInboundProtocolRuntimePlan>(StringComparer.OrdinalIgnoreCase);

    public bool RequiresCertificate => Plans.Values.Any(static plan => plan.RequiresCertificate);

    public bool TryGet(string? protocol, out IInboundProtocolRuntimePlan plan)
    {
        var key = NormalizeProtocolKey(protocol);
        if (!string.IsNullOrWhiteSpace(key) &&
            Plans.TryGetValue(key, out var resolvedPlan) &&
            resolvedPlan is not null)
        {
            plan = resolvedPlan;
            return true;
        }

        plan = default!;
        return false;
    }

    public bool TryGet<TPlan>(string? protocol, out TPlan plan)
        where TPlan : class, IInboundProtocolRuntimePlan
    {
        if (TryGet(protocol, out var rawPlan) && rawPlan is TPlan typedPlan)
        {
            plan = typedPlan;
            return true;
        }

        plan = default!;
        return false;
    }

    public TPlan GetOrDefault<TPlan>(string? protocol, TPlan fallback)
        where TPlan : class, IInboundProtocolRuntimePlan
        => TryGet(protocol, out TPlan plan) ? plan : fallback;

    public static InboundRuntimePlanCollection Create(IEnumerable<IInboundProtocolRuntimePlan> plans)
    {
        ArgumentNullException.ThrowIfNull(plans);

        var materialized = new Dictionary<string, IInboundProtocolRuntimePlan>(StringComparer.OrdinalIgnoreCase);
        foreach (var plan in plans)
        {
            if (plan is null)
            {
                continue;
            }

            var protocol = NormalizeProtocolKey(plan.Protocol);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                continue;
            }

            materialized[protocol] = plan;
        }

        return new InboundRuntimePlanCollection
        {
            Plans = materialized
        };
    }

    private static string NormalizeProtocolKey(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();
}

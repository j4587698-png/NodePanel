namespace NodePanel.Core.Runtime;

public interface IRuntimePlanState
    : IOutboundRuntimePlanProvider,
      IOutboundCommonSettingsProvider,
      IRuntimeOutboundSettingsProvider,
      IShadowsocks2022OutboundSettingsProvider,
      ITrojanOutboundSettingsProvider,
      IVlessOutboundSettingsProvider,
      IVmessOutboundSettingsProvider,
      IStrategyOutboundSettingsProvider,
      IDnsRuntimeSettingsProvider
{
    void Apply(RuntimePlan plan);

    RuntimePlan GetCurrentPlan();
}

internal sealed class RuntimePlanState
    : IRuntimePlanState
{
    private RuntimePlan _plan = RuntimePlan.Empty;

    public void Apply(RuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        Volatile.Write(ref _plan, plan);
    }

    public RuntimePlan GetCurrentPlan() => Volatile.Read(ref _plan);

    public OutboundRuntimePlan GetCurrentOutboundPlan() => GetCurrentPlan().Plan.Outbound;

    public DnsRuntimeSettings GetCurrentDnsSettings() => GetCurrentPlan().Dns;

    public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
    {
        if (!RuntimeOutboundSettingsResolver.TryResolveOutbound(this, context, out var outbound) ||
            !GetCurrentPlan().OutboundSettings.TryGet(outbound.Tag, out IRuntimeOutboundOptions resolved) ||
            !string.Equals(
                OutboundProtocols.Normalize(outbound.Protocol),
                OutboundProtocols.Normalize(resolved.Protocol),
                StringComparison.Ordinal))
        {
            settings = default!;
            return false;
        }

        settings = resolved;
        return true;
    }

    public bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
        where TOptions : class, IRuntimeOutboundOptions
    {
        if (TryResolve(context, out IRuntimeOutboundOptions resolved) &&
            resolved is TOptions typed)
        {
            settings = typed;
            return true;
        }

        settings = default!;
        return false;
    }

    public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
    {
        if (!RuntimeOutboundSettingsResolver.TryResolveOutbound(this, context, out var outbound))
        {
            settings = default!;
            return false;
        }

        settings = RuntimeOutboundSettingsResolver.CreateCommonSettings(outbound);
        return true;
    }

    public bool TryResolve(DispatchContext context, out Shadowsocks2022OutboundSettings settings)
        => RuntimeOutboundSettingsResolver.TryResolveShadowsocks2022(this, this, context, out settings);

    public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
        => RuntimeOutboundSettingsResolver.TryResolveTrojan(this, this, context, out settings);

    public bool TryResolve(DispatchContext context, out VlessOutboundSettings settings)
        => RuntimeOutboundSettingsResolver.TryResolveVless(this, this, context, out settings);

    public bool TryResolve(DispatchContext context, out StrategyOutboundSettings settings)
    {
        if (!RuntimeOutboundSettingsResolver.TryResolveOutbound(this, context, out var outbound))
        {
            settings = default!;
            return false;
        }

        var protocol = OutboundProtocols.Normalize(outbound.Protocol);
        if (protocol is not (
            OutboundProtocols.Selector or
            OutboundProtocols.UrlTest or
            OutboundProtocols.Fallback or
            OutboundProtocols.LoadBalance))
        {
            settings = default!;
            return false;
        }

        settings = new StrategyOutboundSettings
        {
            Tag = outbound.Tag,
            Protocol = protocol,
            CandidateTags = outbound.CandidateTags.ToArray(),
            SelectedTag = outbound.SelectedTag,
            ProbeUrl = outbound.ProbeUrl,
            ProbeIntervalSeconds = outbound.ProbeIntervalSeconds,
            ProbeTimeoutSeconds = outbound.ProbeTimeoutSeconds,
            ToleranceMilliseconds = outbound.ToleranceMilliseconds
        };
        return true;
    }

    public bool TryResolve(DispatchContext context, out VmessOutboundSettings settings)
        => RuntimeOutboundSettingsResolver.TryResolveVmess(this, this, context, out settings);
}

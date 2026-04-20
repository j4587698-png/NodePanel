using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class RuntimeConfigStore
    : IOutboundRuntimePlanProvider,
      IRuntimeOutboundSettingsProvider,
      IShadowsocks2022OutboundSettingsProvider,
      ITrojanOutboundSettingsProvider,
      IVlessOutboundSettingsProvider,
      IVmessOutboundSettingsProvider,
      IStrategyOutboundSettingsProvider,
      IOutboundCommonSettingsProvider,
      IDnsRuntimeSettingsProvider
{
    private readonly object _sync = new();
    private TaskCompletionSource<int> _changeSignal = CreateChangeSignal();
    private NodeRuntimeSnapshot _snapshot = NodeRuntimeSnapshot.Empty;

    public NodeRuntimeSnapshot GetSnapshot() => Volatile.Read(ref _snapshot);

    public OutboundRuntimePlan GetCurrentOutboundPlan() => GetSnapshot().OutboundPlan;

    public DnsRuntimeSettings GetCurrentDnsSettings() => GetSnapshot().Dns;

    public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
    {
        var snapshot = GetSnapshot();
        if (!TryResolveOutbound(snapshot, context, out var outbound) ||
            !snapshot.OutboundSettings.TryGet(outbound.Tag, out IRuntimeOutboundOptions resolved) ||
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
        if (!TryResolveOutbound(context, out var outbound))
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

    public void Bootstrap(NodeRuntimeSnapshot snapshot)
    {
        lock (_sync)
        {
            _snapshot = snapshot with
            {
                Revision = Math.Max(0, snapshot.Revision)
            };
        }
    }

    public bool TryCommit(NodeRuntimeSnapshot snapshot, out string? error)
    {
        lock (_sync)
        {
            if (snapshot.Revision <= _snapshot.Revision)
            {
                error = $"Revision {snapshot.Revision} is stale. Current revision is {_snapshot.Revision}.";
                return false;
            }

            _snapshot = snapshot;
            var completed = _changeSignal;
            _changeSignal = CreateChangeSignal();
            completed.TrySetResult(snapshot.Revision);
            error = null;
            return true;
        }
    }

    public Task WaitForChangeAsync(int knownRevision, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_snapshot.Revision != knownRevision)
            {
                return Task.CompletedTask;
            }

            return _changeSignal.Task.WaitAsync(cancellationToken);
        }
    }

    private bool TryResolveOutbound(DispatchContext context, out OutboundRuntime outbound)
        => RuntimeOutboundSettingsResolver.TryResolveOutbound(this, context, out outbound);

    private static bool TryResolveOutbound(
        NodeRuntimeSnapshot snapshot,
        DispatchContext context,
        out OutboundRuntime outbound)
    {
        var plan = snapshot.OutboundPlan;
        if (plan.TryResolveOutboundTag(context, out var outboundTag) &&
            plan.TryGetOutbound(outboundTag, out outbound))
        {
            return true;
        }

        outbound = default!;
        return false;
    }

    private static TaskCompletionSource<int> CreateChangeSignal()
        => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

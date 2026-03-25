using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class RuntimeConfigStore
    : IOutboundRuntimePlanProvider,
      ITrojanOutboundSettingsProvider,
      IStrategyOutboundSettingsProvider,
      IOutboundCommonSettingsProvider,
      IDnsRuntimeSettingsProvider
{
    private readonly object _sync = new();
    private TaskCompletionSource<int> _changeSignal = CreateChangeSignal();
    private NodeRuntimeSnapshot _snapshot = new(0, new NodeServiceConfig(), NodeRuntimePlan.Empty);

    public NodeRuntimeSnapshot GetSnapshot() => Volatile.Read(ref _snapshot);

    public OutboundRuntimePlan GetCurrentOutboundPlan() => GetSnapshot().OutboundPlan;

    public DnsRuntimeSettings GetCurrentDnsSettings()
    {
        var dns = GetSnapshot().Config.Dns;
        return new DnsRuntimeSettings
        {
            Mode = DnsModes.Normalize(dns.Mode),
            TimeoutSeconds = dns.TimeoutSeconds,
            CacheTtlSeconds = dns.CacheTtlSeconds,
            Servers = dns.Servers
                .Select(static server => new DnsHttpServerRuntime
                {
                    Url = server.Url,
                    Headers = server.Headers.ToDictionary(
                        static pair => pair.Key,
                        static pair => pair.Value,
                        StringComparer.OrdinalIgnoreCase)
                })
                .ToArray()
        };
    }

    public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
    {
        if (!TryResolveOutbound(context, out var outbound))
        {
            settings = default!;
            return false;
        }

        settings = new OutboundCommonSettings
        {
            Tag = outbound.Tag,
            Protocol = OutboundProtocols.Normalize(outbound.Protocol),
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            MultiplexSettings = new OutboundMultiplexRuntime
            {
                Enabled = outbound.MultiplexSettings.Enabled,
                Concurrency = outbound.MultiplexSettings.Concurrency,
                XudpConcurrency = outbound.MultiplexSettings.XudpConcurrency,
                XudpProxyUdp443 = OutboundXudpProxyModes.Normalize(outbound.MultiplexSettings.XudpProxyUdp443)
            }
        };
        return true;
    }

    public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
    {
        if (!TryResolveOutbound(context, out var outbound))
        {
            settings = default!;
            return false;
        }

        if (!string.Equals(OutboundProtocols.Normalize(outbound.Protocol), OutboundProtocols.Trojan, StringComparison.Ordinal))
        {
            settings = default!;
            return false;
        }

        settings = new TrojanOutboundSettings
        {
            Tag = outbound.Tag,
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            MultiplexSettings = new OutboundMultiplexRuntime
            {
                Enabled = outbound.MultiplexSettings.Enabled,
                Concurrency = outbound.MultiplexSettings.Concurrency,
                XudpConcurrency = outbound.MultiplexSettings.XudpConcurrency,
                XudpProxyUdp443 = OutboundXudpProxyModes.Normalize(outbound.MultiplexSettings.XudpProxyUdp443)
            },
            ServerHost = outbound.ServerHost,
            ServerPort = outbound.ServerPort,
            ServerName = outbound.ServerName,
            Transport = TrojanOutboundTransports.Normalize(outbound.Transport),
            WebSocketPath = outbound.WebSocketPath,
            WebSocketHeaders = outbound.WebSocketHeaders.ToDictionary(
                static pair => pair.Key,
                static pair => pair.Value,
                StringComparer.OrdinalIgnoreCase),
            WebSocketEarlyDataBytes = outbound.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = outbound.WebSocketHeartbeatPeriodSeconds,
            ApplicationProtocols = outbound.ApplicationProtocols.ToArray(),
            Password = outbound.Password,
            ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = outbound.HandshakeTimeoutSeconds,
            SkipCertificateValidation = outbound.SkipCertificateValidation
        };
        return true;
    }

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

    private bool TryResolveOutbound(DispatchContext context, out OutboundConfig outbound)
    {
        var snapshot = GetSnapshot();
        if (!snapshot.OutboundPlan.TryResolveOutboundTag(context, out var outboundTag))
        {
            outbound = default!;
            return false;
        }

        outbound = snapshot.Config.Outbounds.FirstOrDefault(item =>
            item.Enabled &&
            string.Equals(item.Tag, outboundTag, StringComparison.OrdinalIgnoreCase))!;
        return outbound is not null;
    }

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

    private static TaskCompletionSource<int> CreateChangeSignal()
        => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

public sealed record NodeRuntimeSnapshot(int Revision, NodeServiceConfig Config, NodeRuntimePlan Plan)
{
    public NodeRuntimeSnapshot(int Revision, NodeServiceConfig Config, TrojanInboundRuntimePlan trojanPlan)
        : this(
            Revision,
            Config,
            NodeRuntimePlanner.Create([trojanPlan], OutboundRuntimePlan.Empty))
    {
    }

    public InboundRuntimePlanCollection InboundPlans => Plan.Inbounds;

    public bool TryGetInboundPlan<TPlan>(string protocol, out TPlan plan)
        where TPlan : class, IInboundProtocolRuntimePlan
        => Plan.TryGetInboundPlan(protocol, out plan);

    public TPlan GetInboundPlanOrDefault<TPlan>(string protocol, TPlan fallback)
        where TPlan : class, IInboundProtocolRuntimePlan
        => InboundPlans.GetOrDefault(protocol, fallback);

    public TrojanInboundRuntimePlan TrojanPlan => Plan.Trojan;

    public OutboundRuntimePlan OutboundPlan => Plan.Outbound;
}

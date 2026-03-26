using System.Text.Json;
using Microsoft.Extensions.Hosting;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class TelemetryFlushService : BackgroundService
{
    private readonly CertificateStateStore _certificateStateStore;
    private readonly IControlPlaneConnection _controlPlaneConnection;
    private readonly HostResourceTelemetryProvider _hostResourceTelemetryProvider;
    private readonly LocalProxyStateStore _localProxyStateStore;
    private readonly string _nodeId;
    private readonly NodePanelOptions _options;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly SessionRegistry _sessionRegistry;
    private readonly StrategyOutboundProbeService _strategyOutboundProbeService;
    private readonly TelemetryDeltaTracker _telemetryDeltaTracker;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly UserStore _userStore;

    public TelemetryFlushService(
        CertificateStateStore certificateStateStore,
        IControlPlaneConnection controlPlaneConnection,
        HostResourceTelemetryProvider hostResourceTelemetryProvider,
        LocalProxyStateStore localProxyStateStore,
        NodePanelOptions options,
        RuntimeConfigStore runtimeConfigStore,
        SessionRegistry sessionRegistry,
        StrategyOutboundProbeService strategyOutboundProbeService,
        TelemetryDeltaTracker telemetryDeltaTracker,
        TrafficRegistry trafficRegistry,
        UserStore userStore)
    {
        _certificateStateStore = certificateStateStore;
        _controlPlaneConnection = controlPlaneConnection;
        _hostResourceTelemetryProvider = hostResourceTelemetryProvider;
        _localProxyStateStore = localProxyStateStore;
        _options = options;
        _nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId;
        _runtimeConfigStore = runtimeConfigStore;
        _sessionRegistry = sessionRegistry;
        _strategyOutboundProbeService = strategyOutboundProbeService;
        _telemetryDeltaTracker = telemetryDeltaTracker;
        _trafficRegistry = trafficRegistry;
        _userStore = userStore;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await FlushAsync(stoppingToken).ConfigureAwait(false);

            var snapshot = _runtimeConfigStore.GetSnapshot();
            await Task.Delay(TimeSpan.FromSeconds(snapshot.Config.Telemetry.FlushIntervalSeconds), stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task FlushAsync(CancellationToken cancellationToken)
    {
        var snapshot = _runtimeConfigStore.GetSnapshot();
        var trafficSnapshot = _trafficRegistry.CreateSnapshot();
        var traffic = _telemetryDeltaTracker.CreateDelta(trafficSnapshot);
        var inboundStatuses = NodeServiceConfigInbounds.GetEffectiveInbounds(snapshot.Config)
            .Where(static inbound => inbound.Enabled)
            .Select(static inbound => new NodeInboundStatusPayload
            {
                Tag = inbound.Tag,
                Protocol = InboundProtocols.Normalize(inbound.Protocol),
                Transport = InboundTransports.Normalize(inbound.Transport),
                ListenAddress = inbound.ListenAddress,
                Port = inbound.Port,
                ReceiveOriginalDestination = inbound.ReceiveOriginalDestination
            })
            .OrderBy(static inbound => inbound.Protocol, StringComparer.Ordinal)
            .ThenBy(static inbound => inbound.Tag, StringComparer.Ordinal)
            .ToArray();
        var localProxyStatuses = _localProxyStateStore.CreateSnapshot(snapshot.Config.LocalInbounds, snapshot.Revision);
        var outboundStrategies = await BuildOutboundStrategyStatusesAsync(snapshot, cancellationToken).ConfigureAwait(false);
        var status = new NodeStatusPayload
        {
            Timestamp = DateTimeOffset.UtcNow,
            ActiveSessions = _sessionRegistry.ActiveSessions,
            KnownUsers = _userStore.KnownUsers,
            Inbounds = inboundStatuses,
            Certificate = _certificateStateStore.GetSnapshot().ToPayload(),
            LocalProxies = localProxyStatuses,
            OutboundStrategies = outboundStrategies,
            Host = _hostResourceTelemetryProvider.Capture()
        };

        var payload = new TelemetryBatchPayload
        {
            NodeId = _nodeId,
            AppliedRevision = snapshot.Revision,
            Traffic = traffic,
            Status = status
        };

        var envelope = new ControlPlaneEnvelope
        {
            Type = ControlMessageTypes.TelemetryBatch,
            NodeId = _nodeId,
            Revision = snapshot.Revision,
            Payload = JsonSerializer.SerializeToElement(payload, ControlPlaneJsonSerializerContext.Default.TelemetryBatchPayload)
        };

        if (await _controlPlaneConnection.SendAsync(envelope, cancellationToken).ConfigureAwait(false))
        {
            _telemetryDeltaTracker.Commit(trafficSnapshot);
        }
    }

    private async Task<IReadOnlyList<NodeStrategyOutboundStatusPayload>> BuildOutboundStrategyStatusesAsync(
        NodeRuntimeSnapshot snapshot,
        CancellationToken cancellationToken)
    {
        var strategyOutbounds = snapshot.OutboundPlan.Outbounds
            .Where(static outbound => IsStrategyOutbound(outbound.Protocol))
            .OrderBy(static outbound => outbound.Tag, StringComparer.Ordinal)
            .ToArray();

        if (strategyOutbounds.Length == 0)
        {
            return Array.Empty<NodeStrategyOutboundStatusPayload>();
        }

        var statuses = new List<NodeStrategyOutboundStatusPayload>(strategyOutbounds.Length);
        foreach (var outbound in strategyOutbounds)
        {
            var settings = new StrategyOutboundSettings
            {
                Tag = outbound.Tag,
                Protocol = OutboundProtocols.Normalize(outbound.Protocol),
                CandidateTags = outbound.CandidateTags.ToArray(),
                SelectedTag = outbound.SelectedTag,
                ProbeUrl = outbound.ProbeUrl,
                ProbeIntervalSeconds = outbound.ProbeIntervalSeconds,
                ProbeTimeoutSeconds = outbound.ProbeTimeoutSeconds,
                ToleranceMilliseconds = outbound.ToleranceMilliseconds
            };

            var probeResults = settings.CandidateTags.Count == 0
                ? Array.Empty<StrategyCandidateProbeResult>()
                : await _strategyOutboundProbeService.ProbeAsync(settings, cancellationToken).ConfigureAwait(false);

            statuses.Add(
                new NodeStrategyOutboundStatusPayload
                {
                    Tag = outbound.Tag,
                    Protocol = OutboundProtocols.Normalize(outbound.Protocol),
                    SelectedTag = outbound.SelectedTag,
                    ProbeUrl = outbound.ProbeUrl,
                    Candidates = probeResults
                        .Select(static result => new NodeStrategyCandidateProbePayload
                        {
                            Tag = result.Tag,
                            Success = result.Success,
                            LatencyMilliseconds = result.Success ? result.LatencyMilliseconds : null,
                            CheckedAt = result.CheckedAt
                        })
                        .OrderBy(static result => result.Tag, StringComparer.Ordinal)
                        .ToArray()
                });
        }

        return statuses;
    }

    private static bool IsStrategyOutbound(string protocol)
    {
        var normalized = OutboundProtocols.Normalize(protocol);
        return normalized is
            OutboundProtocols.Selector or
            OutboundProtocols.UrlTest or
            OutboundProtocols.Fallback or
            OutboundProtocols.LoadBalance;
    }
}

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
    private readonly string _nodeId;
    private readonly NodePanelOptions _options;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly SessionRegistry _sessionRegistry;
    private readonly TelemetryDeltaTracker _telemetryDeltaTracker;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly UserStore _userStore;

    public TelemetryFlushService(
        CertificateStateStore certificateStateStore,
        IControlPlaneConnection controlPlaneConnection,
        NodePanelOptions options,
        RuntimeConfigStore runtimeConfigStore,
        SessionRegistry sessionRegistry,
        TelemetryDeltaTracker telemetryDeltaTracker,
        TrafficRegistry trafficRegistry,
        UserStore userStore)
    {
        _certificateStateStore = certificateStateStore;
        _controlPlaneConnection = controlPlaneConnection;
        _options = options;
        _nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId;
        _runtimeConfigStore = runtimeConfigStore;
        _sessionRegistry = sessionRegistry;
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
        var inboundStatuses = NodeServiceConfigInbounds.GetTrojanInbounds(snapshot.Config)
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
            .ToArray();
        var status = new NodeStatusPayload
        {
            Timestamp = DateTimeOffset.UtcNow,
            ActiveSessions = _sessionRegistry.ActiveSessions,
            KnownUsers = _userStore.KnownUsers,
            Inbounds = inboundStatuses,
            Certificate = _certificateStateStore.GetSnapshot().ToPayload()
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
}

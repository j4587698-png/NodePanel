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
    private readonly AppliedRuntimeSnapshotStore _appliedRuntimeSnapshotStore;
    private readonly CertificateStateStore _certificateStateStore;
    private readonly IControlPlaneConnection _controlPlaneConnection;
    private readonly HostResourceTelemetryProvider _hostResourceTelemetryProvider;
    private readonly string _nodeId;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly TelemetryDeltaTracker _telemetryDeltaTracker;
    private readonly IRuntime _runtime;

    public TelemetryFlushService(
        AppliedRuntimeSnapshotStore appliedRuntimeSnapshotStore,
        CertificateStateStore certificateStateStore,
        IControlPlaneConnection controlPlaneConnection,
        HostResourceTelemetryProvider hostResourceTelemetryProvider,
        NodePanelOptions options,
        RuntimeConfigStore runtimeConfigStore,
        TelemetryDeltaTracker telemetryDeltaTracker,
        IRuntime runtime)
    {
        _appliedRuntimeSnapshotStore = appliedRuntimeSnapshotStore;
        _certificateStateStore = certificateStateStore;
        _controlPlaneConnection = controlPlaneConnection;
        _hostResourceTelemetryProvider = hostResourceTelemetryProvider;
        _nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId;
        _runtimeConfigStore = runtimeConfigStore;
        _telemetryDeltaTracker = telemetryDeltaTracker;
        _runtime = runtime;
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
        var appliedSnapshot = _appliedRuntimeSnapshotStore.GetSnapshot();
        var runtimeStatus = _runtime.GetStatus();
        var trafficSnapshot = _runtime.GetTrafficSnapshot();
        var traffic = _telemetryDeltaTracker.CreateDelta(trafficSnapshot);
        var inboundStatuses = NodeServiceConfigInbounds.GetEffectiveInbounds(appliedSnapshot.Config)
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
        var proxyInboundStatuses = CreateProxyInboundStatuses(appliedSnapshot, runtimeStatus);
        var outboundStrategies = CreateOutboundStrategyStatuses(
            await _runtime.RefreshStrategyStatusesAsync(cancellationToken).ConfigureAwait(false));
        var status = new NodeStatusPayload
        {
            Timestamp = DateTimeOffset.UtcNow,
            ActiveSessions = runtimeStatus.ActiveSessions,
            KnownUsers = runtimeStatus.KnownUsers,
            Inbounds = inboundStatuses,
            Certificate = _certificateStateStore.GetSnapshot().ToPayload(),
            ProxyInbounds = proxyInboundStatuses,
            OutboundStrategies = outboundStrategies,
            Host = _hostResourceTelemetryProvider.Capture()
        };

        var payload = new TelemetryBatchPayload
        {
            NodeId = _nodeId,
            AppliedRevision = appliedSnapshot.Revision,
            Traffic = traffic,
            Status = status
        };

        var envelope = new ControlPlaneEnvelope
        {
            Type = ControlMessageTypes.TelemetryBatch,
            NodeId = _nodeId,
            Revision = appliedSnapshot.Revision,
            Payload = JsonSerializer.SerializeToElement(payload, ControlPlaneJsonSerializerContext.Default.TelemetryBatchPayload)
        };

        if (await _controlPlaneConnection.SendAsync(envelope, cancellationToken).ConfigureAwait(false))
        {
            _telemetryDeltaTracker.Commit(trafficSnapshot);
        }
    }

    private static IReadOnlyList<NodeProxyInboundStatusPayload> CreateProxyInboundStatuses(
        NodeRuntimeSnapshot snapshot,
        RuntimeStatusSnapshot runtimeStatus)
    {
        var listeners = runtimeStatus.Listeners
            .Where(static listener => listener.IsProxyInbound)
            .ToDictionary(
                static listener => BuildProxyInboundKey(
                    listener.Protocol,
                    listener.Tag,
                    listener.Binding.ListenAddress,
                    listener.Binding.Port),
                StringComparer.Ordinal);

        return snapshot.Config.ProxyInbounds
            .Where(static inbound => inbound.Enabled)
            .Select(inbound =>
            {
                var protocol = ProxyInboundProtocols.Normalize(inbound.Protocol);
                var key = BuildProxyInboundKey(protocol, inbound.Tag, inbound.ListenAddress, inbound.Port);
                listeners.TryGetValue(key, out var listener);

                return new NodeProxyInboundStatusPayload
                {
                    Tag = inbound.Tag ?? string.Empty,
                    Protocol = protocol,
                    ListenAddress = inbound.ListenAddress ?? string.Empty,
                    Port = inbound.Port,
                    Listening = listener?.State == RuntimeState.Running,
                    LastStartedAt = listener?.LastStartedAt,
                    Error = listener?.State == RuntimeState.Faulted &&
                            !string.IsNullOrWhiteSpace(listener.Message)
                        ? listener.Message
                        : null
                };
            })
            .OrderBy(static inbound => inbound.Protocol, StringComparer.Ordinal)
            .ThenBy(static inbound => inbound.Tag, StringComparer.Ordinal)
            .ToArray();
    }

    private static IReadOnlyList<NodeStrategyOutboundStatusPayload> CreateOutboundStrategyStatuses(
        IReadOnlyList<RuntimeStrategyStatus> strategyStatuses)
    {
        return strategyStatuses
            .OrderBy(static outbound => outbound.Tag, StringComparer.Ordinal)
            .Select(outbound => new NodeStrategyOutboundStatusPayload
            {
                Tag = outbound.Tag,
                Protocol = OutboundProtocols.Normalize(outbound.Protocol),
                SelectedTag = outbound.SelectedTag,
                ProbeUrl = outbound.ProbeUrl,
                Candidates = outbound.ProbeResults
                    .Select(static result => new NodeStrategyCandidateProbePayload
                    {
                        Tag = result.Tag,
                        Success = result.Success,
                        LatencyMilliseconds = result.Success ? result.LatencyMilliseconds : null,
                        CheckedAt = result.CheckedAt
                    })
                    .OrderBy(static result => result.Tag, StringComparer.Ordinal)
                    .ToArray()
            })
            .ToArray();
    }

    private static string BuildProxyInboundKey(string? protocol, string? tag, string? listenAddress, int port)
        => string.Concat(
            ProxyInboundProtocols.Normalize(protocol),
            "\u0000",
            tag?.Trim() ?? string.Empty,
            "\u0000",
            listenAddress?.Trim() ?? string.Empty,
            "\u0000",
            port.ToString(System.Globalization.CultureInfo.InvariantCulture));
}

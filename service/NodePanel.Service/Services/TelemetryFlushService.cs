using System.Text.Json;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
    private readonly bool _controlPlaneEnabled;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly TelemetryDeltaTracker _telemetryDeltaTracker;
    private readonly TelemetryOutbox _telemetryOutbox;
    private readonly TelemetryDeliveryState _telemetryDeliveryState;
    private readonly ILogger<TelemetryFlushService> _logger;
    private readonly IRuntime _runtime;
    private bool _warnedMissingCapability;
    private readonly UserActivityTracker _userActivityTracker = new();

    public TelemetryFlushService(
        AppliedRuntimeSnapshotStore appliedRuntimeSnapshotStore,
        CertificateStateStore certificateStateStore,
        IControlPlaneConnection controlPlaneConnection,
        HostResourceTelemetryProvider hostResourceTelemetryProvider,
        NodePanelOptions options,
        RuntimeConfigStore runtimeConfigStore,
        TelemetryDeltaTracker telemetryDeltaTracker,
        TelemetryOutbox telemetryOutbox,
        TelemetryDeliveryState telemetryDeliveryState,
        ILogger<TelemetryFlushService> logger,
        IRuntime runtime)
    {
        _appliedRuntimeSnapshotStore = appliedRuntimeSnapshotStore;
        _certificateStateStore = certificateStateStore;
        _controlPlaneConnection = controlPlaneConnection;
        _hostResourceTelemetryProvider = hostResourceTelemetryProvider;
        _nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId;
        _controlPlaneEnabled = options.ControlPlane.Enabled && !string.IsNullOrWhiteSpace(options.ControlPlane.Url);
        _runtimeConfigStore = runtimeConfigStore;
        _telemetryDeltaTracker = telemetryDeltaTracker;
        _telemetryOutbox = telemetryOutbox;
        _telemetryDeliveryState = telemetryDeliveryState;
        _logger = logger;
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

    internal async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (!_controlPlaneEnabled) return;
        var appliedSnapshot = _appliedRuntimeSnapshotStore.GetSnapshot();
        var runtimeStatus = _runtime.GetStatus();
        var trafficSnapshot = _runtime.GetTrafficSnapshot();
        var (userActivity, ratesAvailable) = _userActivityTracker.Capture(
            _runtime.GetSessionSnapshot(), trafficSnapshot, Stopwatch.GetTimestamp());
        var traffic = _telemetryDeltaTracker.CreateDelta(trafficSnapshot);
        await _telemetryOutbox.AppendAsync(traffic, cancellationToken).ConfigureAwait(false);
        _telemetryDeltaTracker.Commit(trafficSnapshot);
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
            Host = _hostResourceTelemetryProvider.Capture(),
            UserActivity = userActivity,
            UserActivityRatesAvailable = ratesAvailable,
            UserActivityIntervalSeconds = _runtimeConfigStore.GetSnapshot().Config.Telemetry.FlushIntervalSeconds
        };

        if (!_telemetryDeliveryState.IsReady)
        {
            if (_controlPlaneConnection.IsConnected && !_warnedMissingCapability)
            {
                _logger.LogWarning("Panel has not negotiated durable telemetry; traffic will remain in the local outbox until a compatible panel is available.");
                _warnedMissingCapability = true;
            }
            await SendTelemetryAsync(appliedSnapshot.Revision, status, null, cancellationToken).ConfigureAwait(false);
            return;
        }
        _warnedMissingCapability = false;

        var sent = 0;
        while (_telemetryDeliveryState.IsReady && sent < 100)
        {
            var batch = _telemetryOutbox.Pending.FirstOrDefault();
            if (batch is null) break;
            var ack = _telemetryDeliveryState.BeginWait(batch.BatchId);
            try
            {
                if (!await SendTelemetryAsync(appliedSnapshot.Revision, status, batch, cancellationToken).ConfigureAwait(false))
                    return;
                bool acknowledged;
                try
                {
                    acknowledged = await ack.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
                }
                catch (TimeoutException)
                {
                    _logger.LogWarning("Timed out waiting for acknowledgment of telemetry batch {BatchId}; it will be retried.", batch.BatchId);
                    return;
                }
                if (!acknowledged) return;
                _telemetryOutbox.RemoveAcknowledged(batch.BatchId);
                sent++;
            }
            finally
            {
                _telemetryDeliveryState.EndWait(batch.BatchId);
            }
        }

        if (sent == 0)
            await SendTelemetryAsync(appliedSnapshot.Revision, status, null, cancellationToken).ConfigureAwait(false);
    }

    private Task<bool> SendTelemetryAsync(int revision, NodeStatusPayload status, PendingTelemetryBatch? batch, CancellationToken cancellationToken)
    {
        var payload = new TelemetryBatchPayload
        {
            NodeId = _nodeId,
            AppliedRevision = revision,
            Traffic = batch is null ? Array.Empty<UserTrafficDelta>() : batch.Traffic,
            Status = status,
            BatchId = batch?.BatchId
        };
        return _controlPlaneConnection.SendAsync(new ControlPlaneEnvelope
        {
            Type = ControlMessageTypes.TelemetryBatch,
            NodeId = _nodeId,
            Revision = revision,
            Payload = JsonSerializer.SerializeToElement(payload, ControlPlaneJsonSerializerContext.Default.TelemetryBatchPayload)
        }, cancellationToken);
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

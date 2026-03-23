using System.Text.Json;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Panel.Services;

public sealed class ControlPlanePushService
{
    private readonly ILogger<ControlPlanePushService> _logger;
    private readonly NodeConnectionRegistry _nodeConnectionRegistry;
    private readonly PanelSnapshotBuilder _snapshotBuilder;

    public ControlPlanePushService(
        PanelSnapshotBuilder snapshotBuilder,
        NodeConnectionRegistry nodeConnectionRegistry,
        ILogger<ControlPlanePushService> logger)
    {
        _snapshotBuilder = snapshotBuilder;
        _nodeConnectionRegistry = nodeConnectionRegistry;
        _logger = logger;
    }

    public async Task PushSnapshotAsync(string nodeId, CancellationToken cancellationToken)
    {
        var buildResult = await _snapshotBuilder.TryBuildAsync(nodeId, cancellationToken);
        if (!buildResult.Success)
        {
            return;
        }

        var session = _nodeConnectionRegistry.GetSession(nodeId);
        if (session is null)
        {
            return;
        }

        var payload = new ApplySnapshotPayload
        {
            Config = buildResult.Config
        };

        var envelope = new ControlPlaneEnvelope
        {
            Type = ControlMessageTypes.ApplySnapshot,
            NodeId = nodeId,
            Revision = buildResult.Revision,
            Payload = JsonSerializer.SerializeToElement(payload, ControlPlaneJsonSerializerContext.Default.ApplySnapshotPayload)
        };

        if (!await session.SendAsync(envelope, cancellationToken).ConfigureAwait(false))
        {
            _logger.LogWarning("Failed to deliver snapshot revision {Revision} to node {NodeId}.", buildResult.Revision, nodeId);
        }
    }

    public async Task PushSnapshotsAsync(IEnumerable<string> nodeIds, CancellationToken cancellationToken)
    {
        foreach (var nodeId in nodeIds
                     .Where(static nodeId => !string.IsNullOrWhiteSpace(nodeId))
                     .Distinct(StringComparer.Ordinal))
        {
            await PushSnapshotAsync(nodeId, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<bool> RequestCertificateRenewalAsync(string nodeId, string requestedBy, CancellationToken cancellationToken)
    {
        var session = _nodeConnectionRegistry.GetSession(nodeId);
        if (session is null)
        {
            return false;
        }

        var payload = new CertificateRenewPayload
        {
            RequestedAt = DateTimeOffset.UtcNow,
            RequestedBy = requestedBy
        };

        var envelope = new ControlPlaneEnvelope
        {
            Type = ControlMessageTypes.CertificateRenew,
            NodeId = nodeId,
            Revision = 0,
            Payload = JsonSerializer.SerializeToElement(payload, ControlPlaneJsonSerializerContext.Default.CertificateRenewPayload)
        };

        if (!await session.SendAsync(envelope, cancellationToken).ConfigureAwait(false))
        {
            _logger.LogWarning("Failed to deliver certificate renewal request to node {NodeId}.", nodeId);
            return false;
        }

        return true;
    }
}

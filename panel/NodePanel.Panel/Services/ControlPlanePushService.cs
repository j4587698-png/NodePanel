using System.Text.Json;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class ControlPlanePushService
{
    private readonly ILogger<ControlPlanePushService> _logger;
    private readonly NodeConnectionRegistry _nodeConnectionRegistry;
    private readonly PanelSnapshotBuilder _snapshotBuilder;

    /// <summary>Queue drained by <see cref="ControlPlanePushBackgroundService"/>.</summary>
    public ControlPlanePushQueue Queue { get; } = new();

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
        if (_nodeConnectionRegistry.GetSession(nodeId) is null)
        {
            return;
        }

        var users = await _snapshotBuilder.LoadEnabledUsersAsync(cancellationToken).ConfigureAwait(false);
        await PushSnapshotAsync(nodeId, users, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Queues snapshot pushes for connected nodes and returns immediately. Use this
    /// from request paths so a slow node cannot delay the save response.
    /// </summary>
    public void EnqueueSnapshots(IEnumerable<string> nodeIds)
    {
        foreach (var nodeId in nodeIds
                     .Where(static nodeId => !string.IsNullOrWhiteSpace(nodeId))
                     .Distinct(StringComparer.Ordinal))
        {
            if (_nodeConnectionRegistry.GetSession(nodeId) is null)
            {
                continue;
            }

            Queue.TryEnqueue(nodeId);
        }
    }

    public async Task PushSnapshotsAsync(IEnumerable<string> nodeIds, CancellationToken cancellationToken)
    {
        var normalizedNodeIds = nodeIds
            .Where(static nodeId => !string.IsNullOrWhiteSpace(nodeId))
            .Distinct(StringComparer.Ordinal)
            .Where(nodeId => _nodeConnectionRegistry.GetSession(nodeId) is not null)
            .ToArray();
        if (normalizedNodeIds.Length == 0)
        {
            return;
        }

        var users = await _snapshotBuilder.LoadEnabledUsersAsync(cancellationToken).ConfigureAwait(false);
        await Task.WhenAll(normalizedNodeIds.Select(nodeId => PushSnapshotAsync(nodeId, users, cancellationToken)))
            .ConfigureAwait(false);
    }

    private async Task PushSnapshotAsync(string nodeId, IReadOnlyList<PanelUserRecord> users, CancellationToken cancellationToken)
    {
        var buildResult = await _snapshotBuilder.TryBuildAsync(nodeId, users, cancellationToken).ConfigureAwait(false);
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

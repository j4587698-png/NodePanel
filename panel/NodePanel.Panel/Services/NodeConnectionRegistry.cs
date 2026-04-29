using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class NodeConnectionRegistry
{
    private readonly object _sync = new();
    private readonly Dictionary<string, ConnectionEntry> _entries = new(StringComparer.Ordinal);

    public NodeControlPlaneSession? Register(string nodeId, NodeControlPlaneSession session)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(session);

        lock (_sync)
        {
            _entries.TryGetValue(nodeId, out var current);
            var runtime = (current?.Runtime ?? new NodeRuntimeSnapshot()) with
            {
                Connected = true,
                LastSeenAt = DateTimeOffset.UtcNow
            };

            _entries[nodeId] = new ConnectionEntry(session, runtime);
            return current?.Session;
        }
    }

    public void Unregister(string nodeId, NodeControlPlaneSession session)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(session);

        lock (_sync)
        {
            if (!_entries.TryGetValue(nodeId, out var current) || !ReferenceEquals(current.Session, session))
            {
                return;
            }

            _entries[nodeId] = current with
            {
                Session = null,
                Runtime = current.Runtime with
                {
                    Connected = false
                }
            };
        }
    }

    public NodeControlPlaneSession? GetSession(string nodeId)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(nodeId, out var current) ? current.Session : null;
        }
    }

    public bool IsConnected(string nodeId)
    {
        lock (_sync)
        {
            return _entries.TryGetValue(nodeId, out var current) && current.Runtime.Connected;
        }
    }

    public bool TryRemoveDisconnected(string nodeId)
    {
        lock (_sync)
        {
            if (_entries.TryGetValue(nodeId, out var current) && current.Runtime.Connected)
            {
                return false;
            }

            _entries.Remove(nodeId);
            return true;
        }
    }

    public IReadOnlyDictionary<string, NodeRuntimeSnapshot> GetAllRuntime()
    {
        lock (_sync)
        {
            return _entries.ToDictionary(
                static item => item.Key,
                static item => item.Value.Runtime,
                StringComparer.Ordinal);
        }
    }

    public void RecordHello(string nodeId, string version, int appliedRevision)
        => UpdateRuntime(
            nodeId,
            runtime => runtime with
            {
                Connected = true,
                AppliedRevision = Math.Max(runtime.AppliedRevision, appliedRevision),
                Version = string.IsNullOrWhiteSpace(version) ? runtime.Version : version.Trim(),
                LastSeenAt = DateTimeOffset.UtcNow
            });

    public void RecordHeartbeat(string nodeId, DateTimeOffset timestamp)
        => UpdateRuntime(
            nodeId,
            runtime => runtime with
            {
                Connected = true,
                LastSeenAt = timestamp
            });

    public void RecordApplyResult(string nodeId, ApplyResultPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        UpdateRuntime(
            nodeId,
            runtime => runtime with
            {
                AppliedRevision = payload.Success
                    ? Math.Max(runtime.AppliedRevision, payload.RequestedRevision)
                    : runtime.AppliedRevision,
                LastApplyError = payload.Success ? string.Empty : payload.Error ?? "Unknown apply failure.",
                LastSeenAt = DateTimeOffset.UtcNow
            });
    }

    public void RecordTelemetry(string nodeId, TelemetryBatchPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        UpdateRuntime(
            nodeId,
            runtime => runtime with
            {
                Connected = true,
                AppliedRevision = Math.Max(runtime.AppliedRevision, payload.AppliedRevision),
                LastSeenAt = payload.Status.Timestamp,
                LastStatus = payload.Status,
                TrafficTotals = MergeTraffic(runtime.TrafficTotals, payload.Traffic)
            });
    }

    private void UpdateRuntime(string nodeId, Func<NodeRuntimeSnapshot, NodeRuntimeSnapshot> update)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(update);

        lock (_sync)
        {
            _entries.TryGetValue(nodeId, out var current);
            _entries[nodeId] = new ConnectionEntry(
                current?.Session,
                update(current?.Runtime ?? new NodeRuntimeSnapshot()));
        }
    }

    private static IReadOnlyList<PanelUserTrafficTotal> MergeTraffic(
        IReadOnlyList<PanelUserTrafficTotal> current,
        IReadOnlyList<UserTrafficDelta> delta)
    {
        var totals = current.ToDictionary(GetTrafficKey, StringComparer.Ordinal);
        foreach (var item in delta)
        {
            var key = GetTrafficKey(item);
            if (totals.TryGetValue(key, out var existing))
            {
                totals[key] = existing with
                {
                    RuntimeKey = string.IsNullOrWhiteSpace(item.RuntimeKey) ? existing.RuntimeKey : item.RuntimeKey,
                    Protocol = string.IsNullOrWhiteSpace(item.Protocol) ? existing.Protocol : item.Protocol,
                    InboundTag = string.IsNullOrWhiteSpace(item.InboundTag) ? existing.InboundTag : item.InboundTag,
                    UserId = string.IsNullOrWhiteSpace(item.UserId) ? existing.UserId : item.UserId,
                    UploadBytes = existing.UploadBytes + item.UploadBytes,
                    DownloadBytes = existing.DownloadBytes + item.DownloadBytes
                };
            }
            else
            {
                totals[key] = new PanelUserTrafficTotal
                {
                    RuntimeKey = item.RuntimeKey,
                    Protocol = item.Protocol,
                    InboundTag = item.InboundTag,
                    UserId = item.UserId,
                    UploadBytes = item.UploadBytes,
                    DownloadBytes = item.DownloadBytes
                };
            }
        }

        return totals.Values
            .OrderBy(static item => item.UserId, StringComparer.Ordinal)
            .ThenBy(static item => item.RuntimeKey, StringComparer.Ordinal)
            .ToArray();
    }

    private static string GetTrafficKey(PanelUserTrafficTotal total)
        => string.IsNullOrWhiteSpace(total.RuntimeKey)
            ? total.UserId
            : total.RuntimeKey;

    private static string GetTrafficKey(UserTrafficDelta delta)
        => string.IsNullOrWhiteSpace(delta.RuntimeKey)
            ? delta.UserId
            : delta.RuntimeKey;

    private sealed record ConnectionEntry(NodeControlPlaneSession? Session, NodeRuntimeSnapshot Runtime);
}

using NodePanel.Core.Runtime;
using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Service.Runtime;

public sealed class TelemetryDeltaTracker
{
    private readonly object _sync = new();
    private Dictionary<string, UserTrafficSnapshot> _lastReported = new(StringComparer.Ordinal);

    public IReadOnlyList<UserTrafficDelta> CreateDelta(IReadOnlyList<UserTrafficSnapshot> snapshot)
    {
        lock (_sync)
        {
            var items = new List<UserTrafficDelta>(snapshot.Count);
            foreach (var item in snapshot)
            {
                _lastReported.TryGetValue(GetSnapshotKey(item), out var previous);

                var uploadDelta = previous is null || item.UploadBytes < previous.UploadBytes
                    ? item.UploadBytes
                    : item.UploadBytes - previous.UploadBytes;

                var downloadDelta = previous is null || item.DownloadBytes < previous.DownloadBytes
                    ? item.DownloadBytes
                    : item.DownloadBytes - previous.DownloadBytes;

                if (uploadDelta == 0 && downloadDelta == 0)
                {
                    continue;
                }

                items.Add(new UserTrafficDelta
                {
                    RuntimeKey = item.RuntimeKey,
                    Protocol = item.Protocol,
                    InboundTag = item.InboundTag,
                    UserId = item.UserId,
                    UploadBytes = uploadDelta,
                    DownloadBytes = downloadDelta
                });
            }

            return items;
        }
    }

    public void Commit(IReadOnlyList<UserTrafficSnapshot> snapshot)
    {
        lock (_sync)
        {
            var next = new Dictionary<string, UserTrafficSnapshot>(StringComparer.Ordinal);
            foreach (var item in snapshot)
            {
                next[GetSnapshotKey(item)] = item;
            }

            _lastReported = next;
        }
    }

    private static string GetSnapshotKey(UserTrafficSnapshot snapshot)
        => string.IsNullOrWhiteSpace(snapshot.RuntimeKey)
            ? snapshot.UserId.Trim()
            : snapshot.RuntimeKey.Trim();
}

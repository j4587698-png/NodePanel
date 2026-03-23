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
                _lastReported.TryGetValue(item.UserId, out var previous);

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
            _lastReported = snapshot.ToDictionary(static item => item.UserId, StringComparer.Ordinal);
        }
    }
}

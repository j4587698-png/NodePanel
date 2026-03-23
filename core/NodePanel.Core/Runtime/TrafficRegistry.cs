using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public sealed class TrafficRegistry
{
    private readonly ConcurrentDictionary<string, TrafficCounter> _counters = new(StringComparer.Ordinal);

    public void RecordUpload(string userId, int bytes)
    {
        if (bytes <= 0)
        {
            return;
        }

        _counters.GetOrAdd(userId, static _ => new TrafficCounter()).AddUpload(bytes);
    }

    public void RecordDownload(string userId, int bytes)
    {
        if (bytes <= 0)
        {
            return;
        }

        _counters.GetOrAdd(userId, static _ => new TrafficCounter()).AddDownload(bytes);
    }

    public IReadOnlyList<UserTrafficSnapshot> CreateSnapshot()
    {
        var items = new List<UserTrafficSnapshot>();
        foreach (var pair in _counters)
        {
            var (uploadBytes, downloadBytes) = pair.Value.GetTotals();
            if (uploadBytes == 0 && downloadBytes == 0)
            {
                continue;
            }

            items.Add(new UserTrafficSnapshot
            {
                UserId = pair.Key,
                UploadBytes = uploadBytes,
                DownloadBytes = downloadBytes
            });
        }

        return items;
    }

    private sealed class TrafficCounter
    {
        private long _downloadBytes;
        private long _uploadBytes;

        public void AddUpload(int bytes) => Interlocked.Add(ref _uploadBytes, bytes);

        public void AddDownload(int bytes) => Interlocked.Add(ref _downloadBytes, bytes);

        public (long UploadBytes, long DownloadBytes) GetTotals()
        {
            var upload = Interlocked.Read(ref _uploadBytes);
            var download = Interlocked.Read(ref _downloadBytes);
            return (upload, download);
        }
    }
}

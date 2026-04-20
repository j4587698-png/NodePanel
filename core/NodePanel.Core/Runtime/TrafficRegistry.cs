using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public interface IRuntimeTrafficRegistry
{
    void RecordUpload(IRuntimeUserDefinition user, int bytes);

    void RecordUpload(string userId, int bytes);

    void RecordDownload(IRuntimeUserDefinition user, int bytes);

    void RecordDownload(string userId, int bytes);

    IReadOnlyList<UserTrafficSnapshot> CreateSnapshot();
}

public sealed class TrafficRegistry : IRuntimeTrafficRegistry
{
    private readonly ConcurrentDictionary<string, TrafficEntry> _counters = new(StringComparer.Ordinal);

    public void RecordUpload(IRuntimeUserDefinition user, int bytes)
    {
        ArgumentNullException.ThrowIfNull(user);

        RecordUpload(RuntimeUserKeys.Get(user), user.UserId, bytes);
    }

    public void RecordUpload(string userId, int bytes)
        => RecordUpload(NormalizeUserId(userId), NormalizeUserId(userId), bytes);

    public void RecordDownload(IRuntimeUserDefinition user, int bytes)
    {
        ArgumentNullException.ThrowIfNull(user);

        RecordDownload(RuntimeUserKeys.Get(user), user.UserId, bytes);
    }

    public void RecordDownload(string userId, int bytes)
        => RecordDownload(NormalizeUserId(userId), NormalizeUserId(userId), bytes);

    private void RecordUpload(string runtimeKey, string userId, int bytes)
    {
        if (bytes <= 0 ||
            runtimeKey.Length == 0 ||
            userId.Length == 0)
        {
            return;
        }

        _counters.GetOrAdd(runtimeKey, static (key, state) => CreateEntry(key, state), userId).Counter.AddUpload(bytes);
    }

    private void RecordDownload(string runtimeKey, string userId, int bytes)
    {
        if (bytes <= 0 ||
            runtimeKey.Length == 0 ||
            userId.Length == 0)
        {
            return;
        }

        _counters.GetOrAdd(runtimeKey, static (key, state) => CreateEntry(key, state), userId).Counter.AddDownload(bytes);
    }

    public IReadOnlyList<UserTrafficSnapshot> CreateSnapshot()
    {
        var items = new List<UserTrafficSnapshot>(_counters.Count);
        foreach (var pair in _counters)
        {
            var (uploadBytes, downloadBytes) = pair.Value.Counter.GetTotals();
            if (uploadBytes == 0 && downloadBytes == 0)
            {
                continue;
            }

            items.Add(new UserTrafficSnapshot
            {
                RuntimeKey = pair.Key,
                Protocol = pair.Value.Protocol,
                InboundTag = pair.Value.InboundTag,
                UserId = pair.Value.UserId,
                UploadBytes = uploadBytes,
                DownloadBytes = downloadBytes
            });
        }

        items.Sort(static (left, right) => string.Compare(left.RuntimeKey, right.RuntimeKey, StringComparison.Ordinal));
        return items;
    }

    private static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();

    private static TrafficEntry CreateEntry(string runtimeKey, string userId)
    {
        var normalizedUserId = NormalizeUserId(userId);
        return RuntimeUserKeys.TryParse(runtimeKey, out var protocol, out var inboundTag, out var parsedUserId)
            ? new TrafficEntry(parsedUserId, protocol, inboundTag)
            : new TrafficEntry(normalizedUserId, string.Empty, string.Empty);
    }

    private sealed class TrafficEntry
    {
        public TrafficEntry(string userId, string protocol, string inboundTag)
        {
            UserId = userId;
            Protocol = protocol;
            InboundTag = inboundTag;
        }

        public string UserId { get; }

        public string Protocol { get; }

        public string InboundTag { get; }

        public TrafficCounter Counter { get; } = new();
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

using System.Diagnostics;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

internal sealed class UserActivityTracker
{
    private Dictionary<string, UserTrafficSnapshot> _previous = new(StringComparer.Ordinal);
    private long? _previousTimestamp;

    public (IReadOnlyList<UserActivityPayload> Users, bool RatesAvailable) Capture(
        IReadOnlyList<UserSessionSnapshot> sessions,
        IReadOnlyList<UserTrafficSnapshot> traffic,
        long timestamp)
    {
        var elapsed = _previousTimestamp.HasValue
            ? Stopwatch.GetElapsedTime(_previousTimestamp.Value, timestamp).TotalSeconds
            : 0;
        var ratesAvailable = elapsed > 0;
        var users = new Dictionary<string, Activity>(StringComparer.Ordinal);
        foreach (var session in sessions)
        {
            if (string.IsNullOrWhiteSpace(session.UserId)) continue;
            var user = GetUser(users, session.UserId);
            user.HasUnknownRemoteIp |= session.SessionsWithoutRemoteIp > 0;
            foreach (var ip in session.RemoteIps)
                if (!string.IsNullOrWhiteSpace(ip)) user.RemoteIps.Add(ip);
        }

        var next = new Dictionary<string, UserTrafficSnapshot>(StringComparer.Ordinal);
        foreach (var item in traffic)
        {
            if (string.IsNullOrWhiteSpace(item.UserId)) continue;
            var key = string.IsNullOrWhiteSpace(item.RuntimeKey) ? item.UserId : item.RuntimeKey;
            next[key] = item;
            if (!ratesAvailable) continue;

            _previous.TryGetValue(key, out var previous);
            var upload = previous is null || item.UploadBytes < previous.UploadBytes
                ? item.UploadBytes : item.UploadBytes - previous.UploadBytes;
            var download = previous is null || item.DownloadBytes < previous.DownloadBytes
                ? item.DownloadBytes : item.DownloadBytes - previous.DownloadBytes;
            if (upload <= 0 && download <= 0) continue;
            var user = GetUser(users, item.UserId);
            user.UploadBytes += Math.Max(0, upload);
            user.DownloadBytes += Math.Max(0, download);
        }

        _previous = next;
        _previousTimestamp = timestamp;
        return (users.Select(pair => new UserActivityPayload
        {
            UserId = pair.Key,
            RemoteIps = pair.Value.RemoteIps.OrderBy(ip => ip, StringComparer.Ordinal).ToArray(),
            HasUnknownRemoteIp = pair.Value.HasUnknownRemoteIp,
            UploadBytesPerSecond = ratesAvailable ? ToRate(pair.Value.UploadBytes, elapsed) : 0,
            DownloadBytesPerSecond = ratesAvailable ? ToRate(pair.Value.DownloadBytes, elapsed) : 0
        }).ToArray(), ratesAvailable);
    }

    private static Activity GetUser(Dictionary<string, Activity> users, string userId)
    {
        if (!users.TryGetValue(userId, out var activity))
            users[userId] = activity = new Activity();
        return activity;
    }

    private static long ToRate(double bytes, double seconds)
    {
        var rate = bytes / seconds;
        return rate >= long.MaxValue ? long.MaxValue : (long)rate;
    }

    private sealed class Activity
    {
        public HashSet<string> RemoteIps { get; } = new(StringComparer.Ordinal);
        public bool HasUnknownRemoteIp { get; set; }
        public double UploadBytes { get; set; }
        public double DownloadBytes { get; set; }
    }
}

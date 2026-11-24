using System.Net;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed record UserActivitySummary
{
    public required string UserId { get; init; }
    public bool HasData { get; init; }
    public bool IsPartial { get; init; }
    public int OnlineIpCount { get; init; }
    public long? UploadBytesPerSecond { get; init; }
    public long? DownloadBytesPerSecond { get; init; }
}

internal static class UserActivityAggregator
{
    public static IReadOnlyList<UserActivitySummary> Aggregate(
        IReadOnlyList<PanelUserRecord> users,
        IReadOnlyList<string> nodeIds,
        IReadOnlyDictionary<string, NodeRuntimeSnapshot> runtimes,
        DateTimeOffset now)
    {
        var availableNodes = new Dictionary<string, (NodeStatusPayload Status, ILookup<string, UserActivityPayload> Users)>(StringComparer.Ordinal);
        foreach (var nodeId in nodeIds)
        {
            if (!runtimes.TryGetValue(nodeId, out var runtime) ||
                !runtime.Connected || runtime.LastStatus?.UserActivity is null ||
                !runtime.LastTelemetryReceivedAt.HasValue)
                continue;

            var interval = Math.Clamp(runtime.LastStatus.UserActivityIntervalSeconds ?? 15, 1, 3600);
            var age = now - runtime.LastTelemetryReceivedAt.Value;
            if (age < TimeSpan.Zero || age > TimeSpan.FromSeconds(interval * 2 + 5)) continue;
            availableNodes[nodeId] = (runtime.LastStatus, runtime.LastStatus.UserActivity.ToLookup(item => item.UserId, StringComparer.Ordinal));
        }

        return users.Select(user =>
        {
            var ips = new HashSet<IPAddress>();
            var available = 0;
            var partial = false;
            var ratesAvailable = true;
            double upload = 0;
            double download = 0;
            var assignedNodes = nodeIds.Where(nodeId => user.NodeIds.Count == 0 || user.NodeIds.Contains(nodeId));
            foreach (var nodeId in assignedNodes)
            {
                if (!availableNodes.TryGetValue(nodeId, out var node))
                {
                    partial = true;
                    continue;
                }

                available++;
                ratesAvailable &= node.Status.UserActivityRatesAvailable;
                foreach (var item in node.Users[user.UserId])
                {
                    partial |= item.HasUnknownRemoteIp;
                    foreach (var value in item.RemoteIps)
                    {
                        if (!IPAddress.TryParse(value, out var ip))
                        {
                            partial = true;
                            continue;
                        }
                        ips.Add(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip);
                    }
                    if (item.UploadBytesPerSecond < 0 || item.DownloadBytesPerSecond < 0)
                    {
                        ratesAvailable = false;
                        continue;
                    }
                    upload += item.UploadBytesPerSecond;
                    download += item.DownloadBytesPerSecond;
                }
            }

            return new UserActivitySummary
            {
                UserId = user.UserId,
                HasData = available > 0,
                IsPartial = partial,
                OnlineIpCount = ips.Count,
                UploadBytesPerSecond = available > 0 && ratesAvailable ? ToLong(upload) : null,
                DownloadBytesPerSecond = available > 0 && ratesAvailable ? ToLong(download) : null
            };
        }).ToArray();
    }

    private static long ToLong(double value)
        => value >= long.MaxValue ? long.MaxValue : (long)value;
}

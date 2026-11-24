using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Runtime;
using System.Diagnostics;

namespace NodePanel.Service.Tests;

public sealed class TelemetryDeltaTrackerTests
{
    [Fact]
    public void User_activity_samples_raw_traffic_and_combines_session_ips()
    {
        var tracker = new UserActivityTracker();
        var sessions = new[]
        {
            new UserSessionSnapshot { UserId = "user", ActiveSessions = 2, RemoteIps = ["192.0.2.1"], SessionsWithoutRemoteIp = 1 },
            new UserSessionSnapshot { UserId = "user", ActiveSessions = 1, RemoteIps = ["192.0.2.1", "192.0.2.2"] }
        };
        var traffic = new[]
        {
            new UserTrafficSnapshot { UserId = "user", RuntimeKey = "a", UploadBytes = 100, DownloadBytes = 200 },
            new UserTrafficSnapshot { UserId = "user", RuntimeKey = "b", UploadBytes = 50, DownloadBytes = 100 }
        };
        var first = tracker.Capture(sessions, traffic, 0);
        Assert.False(first.RatesAvailable);
        Assert.Equal(2, Assert.Single(first.Users).RemoteIps.Count);
        Assert.True(first.Users[0].HasUnknownRemoteIp);

        var nextTraffic = new[] { traffic[0] with { UploadBytes = 200, DownloadBytes = 400 },
            traffic[1] with { UploadBytes = 100, DownloadBytes = 150 } };
        var next = tracker.Capture(sessions, nextTraffic, Stopwatch.Frequency * 10);
        Assert.True(next.RatesAvailable);
        Assert.Equal(15, Assert.Single(next.Users).UploadBytesPerSecond);
        Assert.Equal(25, next.Users[0].DownloadBytesPerSecond);
        var idle = tracker.Capture([], nextTraffic, Stopwatch.Frequency * 20);
        Assert.Empty(idle.Users);
    }

    [Fact]
    public void CreateDelta_tracks_same_user_across_multiple_runtime_keys_independently()
    {
        var tracker = new TelemetryDeltaTracker();
        var firstSnapshot = new UserTrafficSnapshot
        {
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Trojan, "in-a", "shared-user"),
            Protocol = InboundProtocols.Trojan,
            InboundTag = "in-a",
            UserId = "shared-user",
            UploadBytes = 100,
            DownloadBytes = 40
        };
        var secondSnapshot = new UserTrafficSnapshot
        {
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Vless, "in-b", "shared-user"),
            Protocol = InboundProtocols.Vless,
            InboundTag = "in-b",
            UserId = "shared-user",
            UploadBytes = 60,
            DownloadBytes = 20
        };

        var firstDelta = tracker.CreateDelta([firstSnapshot, secondSnapshot]);

        Assert.Equal(2, firstDelta.Count);
        Assert.Contains(firstDelta, static item => item is
        {
            RuntimeKey: not "",
            Protocol: "trojan",
            InboundTag: "in-a",
            UserId: "shared-user",
            UploadBytes: 100,
            DownloadBytes: 40
        });
        Assert.Contains(firstDelta, static item => item is
        {
            RuntimeKey: not "",
            Protocol: "vless",
            InboundTag: "in-b",
            UserId: "shared-user",
            UploadBytes: 60,
            DownloadBytes: 20
        });

        tracker.Commit([firstSnapshot, secondSnapshot]);

        var nextDelta = tracker.CreateDelta(
        [
            firstSnapshot with
            {
                UploadBytes = 160,
                DownloadBytes = 70
            },
            secondSnapshot
        ]);

        var delta = Assert.Single(nextDelta);
        Assert.Equal(firstSnapshot.RuntimeKey, delta.RuntimeKey);
        Assert.Equal("shared-user", delta.UserId);
        Assert.Equal(60, delta.UploadBytes);
        Assert.Equal(30, delta.DownloadBytes);
    }
}

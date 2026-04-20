using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Tests;

public sealed class TelemetryDeltaTrackerTests
{
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

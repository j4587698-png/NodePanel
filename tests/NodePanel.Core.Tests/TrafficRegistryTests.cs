using System.Reflection;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrafficRegistryTests
{
    [Fact]
    public void Record_scopes_snapshot_entries_by_runtime_key_and_preserves_scope_metadata()
    {
        var registry = new TrafficRegistry();
        var firstUser = CreateScopedUser("shared-user", "in-a");
        var secondUser = CreateScopedUser("shared-user", "in-b");

        registry.RecordUpload(firstUser, 120);
        registry.RecordUpload(secondUser, 80);
        registry.RecordDownload(secondUser, 40);

        var snapshot = registry.CreateSnapshot();

        Assert.Equal(2, snapshot.Count);
        Assert.Contains(snapshot, static item => item is
        {
            RuntimeKey: not "",
            Protocol: "trojan",
            InboundTag: "in-a",
            UserId: "shared-user",
            UploadBytes: 120,
            DownloadBytes: 0
        });
        Assert.Contains(snapshot, static item => item is
        {
            RuntimeKey: not "",
            Protocol: "trojan",
            InboundTag: "in-b",
            UserId: "shared-user",
            UploadBytes: 80,
            DownloadBytes: 40
        });
        Assert.Equal(2, GetInternalCounterCount(registry));
    }

    private static int GetInternalCounterCount(TrafficRegistry registry)
    {
        var field = typeof(TrafficRegistry).GetField("_counters", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);

        var counters = field.GetValue(registry);
        Assert.NotNull(counters);

        var countProperty = counters.GetType().GetProperty("Count", BindingFlags.Instance | BindingFlags.Public);
        Assert.NotNull(countProperty);

        return (int)(countProperty.GetValue(counters) ?? 0);
    }

    private static TrojanUser CreateScopedUser(string userId, string inboundTag)
        => new()
        {
            UserId = userId,
            PasswordHash = $"{userId}-{inboundTag}",
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Trojan, inboundTag, userId),
            BytesPerSecond = 0,
            DeviceLimit = 1
        };
}

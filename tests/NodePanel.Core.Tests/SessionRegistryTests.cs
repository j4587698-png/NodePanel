using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class SessionRegistryTests
{
    [Fact]
    public void TryOpenSession_allows_multiple_connections_from_same_ip_without_consuming_extra_slots()
    {
        var registry = new SessionRegistry();

        Assert.True(registry.TryOpenSession("user-a", "203.0.113.10", 1, out var firstLease));
        Assert.True(registry.TryOpenSession("user-a", "203.0.113.10", 1, out var secondLease));
        Assert.False(registry.TryOpenSession("user-a", "203.0.113.11", 1, out var rejectedLease));

        Assert.Equal(2, registry.ActiveSessions);
        Assert.NotNull(firstLease);
        Assert.NotNull(secondLease);
        Assert.Null(rejectedLease);

        secondLease!.Dispose();
        firstLease!.Dispose();

        Assert.Equal(0, registry.ActiveSessions);
    }

    [Fact]
    public void TryOpenSession_releases_ip_slot_after_last_connection_closes()
    {
        var registry = new SessionRegistry();

        Assert.True(registry.TryOpenSession("user-a", "203.0.113.10", 1, out var firstLease));
        Assert.True(registry.TryOpenSession("user-a", "203.0.113.10", 1, out var secondLease));

        secondLease!.Dispose();
        firstLease!.Dispose();

        Assert.True(registry.TryOpenSession("user-a", "203.0.113.11", 1, out var reopenedLease));
        Assert.NotNull(reopenedLease);

        reopenedLease!.Dispose();
        Assert.Equal(0, registry.ActiveSessions);
    }

    [Fact]
    public void TryOpenSession_skips_device_limit_when_remote_ip_is_unavailable()
    {
        var registry = new SessionRegistry();

        Assert.True(registry.TryOpenSession("user-a", remoteIp: null, deviceLimit: 1, out var firstLease));
        Assert.True(registry.TryOpenSession("user-a", remoteIp: null, deviceLimit: 1, out var secondLease));

        Assert.Equal(2, registry.ActiveSessions);

        secondLease!.Dispose();
        firstLease!.Dispose();

        Assert.Equal(0, registry.ActiveSessions);
    }

    [Fact]
    public void TryOpenSession_treats_runtime_scoped_keys_as_independent_users()
    {
        var registry = new SessionRegistry();
        var firstUser = CreateScopedUser("shared-user", "in-a");
        var secondUser = CreateScopedUser("shared-user", "in-b");

        Assert.True(registry.TryOpenSession(RuntimeUserKeys.Get(firstUser), "203.0.113.10", 1, out var firstLease));
        Assert.True(registry.TryOpenSession(RuntimeUserKeys.Get(secondUser), "203.0.113.11", 1, out var secondLease));
        Assert.False(registry.TryOpenSession(RuntimeUserKeys.Get(firstUser), "203.0.113.12", 1, out var rejectedLease));

        Assert.Equal(2, registry.ActiveSessions);
        Assert.NotNull(firstLease);
        Assert.NotNull(secondLease);
        Assert.Null(rejectedLease);

        secondLease!.Dispose();
        firstLease!.Dispose();

        Assert.Equal(0, registry.ActiveSessions);
    }

    [Fact]
    public void CreateSnapshot_returns_active_users_and_unique_remote_ips()
    {
        var registry = new SessionRegistry();
        var scopedUser = CreateScopedUser("shared-user", "in-a");

        Assert.True(registry.TryOpenSession(RuntimeUserKeys.Get(scopedUser), "203.0.113.10", 2, out var firstLease));
        Assert.True(registry.TryOpenSession(RuntimeUserKeys.Get(scopedUser), "203.0.113.10", 2, out var secondLease));
        Assert.True(registry.TryOpenSession(RuntimeUserKeys.Get(scopedUser), "203.0.113.11", 2, out var thirdLease));
        Assert.True(registry.TryOpenSession("plain-user", remoteIp: null, deviceLimit: 0, out var plainLease));

        var snapshots = registry.CreateSnapshot();

        var plainSnapshot = Assert.Single(snapshots, static snapshot => snapshot.UserId == "plain-user");
        Assert.Equal("plain-user", plainSnapshot.RuntimeKey);
        Assert.Equal(1, plainSnapshot.ActiveSessions);
        Assert.Equal(0, plainSnapshot.ActiveRemoteIpCount);
        Assert.Empty(plainSnapshot.RemoteIps);

        var scopedSnapshot = Assert.Single(snapshots, static snapshot => snapshot.UserId == "shared-user");
        Assert.Equal(RuntimeUserKeys.Get(scopedUser), scopedSnapshot.RuntimeKey);
        Assert.Equal(InboundProtocols.Trojan, scopedSnapshot.Protocol);
        Assert.Equal("in-a", scopedSnapshot.InboundTag);
        Assert.Equal(3, scopedSnapshot.ActiveSessions);
        Assert.Equal(2, scopedSnapshot.ActiveRemoteIpCount);
        Assert.Equal(["203.0.113.10", "203.0.113.11"], scopedSnapshot.RemoteIps);

        plainLease!.Dispose();
        thirdLease!.Dispose();
        secondLease!.Dispose();
        firstLease!.Dispose();
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

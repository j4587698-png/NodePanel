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
}

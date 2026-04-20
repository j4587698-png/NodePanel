using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeSplitHttpSessionRegistryTests
{
    [Fact]
    public void GetOrCreate_returns_existing_session_for_same_session_id()
    {
        using var registry = new RuntimeSplitHttpSessionRegistry(
            maxBufferedPosts: 4,
            pendingConnectionTtl: TimeSpan.FromSeconds(1));

        var first = registry.GetOrCreate("session-1");
        var second = registry.GetOrCreate("session-1");

        Assert.Same(first, second);
        Assert.Equal(1, registry.ActiveSessions);
        Assert.False(first.IsClosed);
        Assert.False(first.IsFullyConnected);
    }

    [Fact]
    public async Task Pending_session_is_reaped_after_ttl_and_upload_queue_is_closed()
    {
        using var registry = new RuntimeSplitHttpSessionRegistry(
            maxBufferedPosts: 4,
            pendingConnectionTtl: TimeSpan.FromMilliseconds(80));

        var session = registry.GetOrCreate("session-1");

        await Task.Delay(250);

        Assert.Equal(0, registry.ActiveSessions);
        Assert.True(session.IsClosed);
        await Assert.ThrowsAsync<InvalidOperationException>(() => session.UploadQueue
            .PushPayloadAsync(new byte[] { 0x01 }, sequence: 0)
            .AsTask());
    }

    [Fact]
    public async Task MarkFullyConnected_prevents_pending_reaper_until_session_is_removed()
    {
        using var registry = new RuntimeSplitHttpSessionRegistry(
            maxBufferedPosts: 4,
            pendingConnectionTtl: TimeSpan.FromMilliseconds(80));

        var session = registry.GetOrCreate("session-1");

        Assert.True(session.MarkFullyConnected());

        await Task.Delay(250);

        Assert.Equal(1, registry.ActiveSessions);
        Assert.True(registry.TryRemove("session-1"));
        Assert.Equal(0, registry.ActiveSessions);
        Assert.True(session.IsClosed);
    }

    [Fact]
    public async Task Stale_pending_reaper_does_not_remove_newer_session_with_same_id()
    {
        using var registry = new RuntimeSplitHttpSessionRegistry(
            maxBufferedPosts: 4,
            pendingConnectionTtl: TimeSpan.FromMilliseconds(80));

        var first = registry.GetOrCreate("session-1");
        Assert.True(registry.TryRemove("session-1"));

        var second = registry.GetOrCreate("session-1");
        Assert.True(second.MarkFullyConnected());

        await Task.Delay(250);

        Assert.True(first.IsClosed);
        Assert.False(second.IsClosed);
        Assert.Equal(1, registry.ActiveSessions);
        Assert.Same(second, registry.GetOrCreate("session-1"));
    }
}

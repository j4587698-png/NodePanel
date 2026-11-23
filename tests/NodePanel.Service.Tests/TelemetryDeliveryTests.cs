using Microsoft.Extensions.Logging.Abstractions;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Tests;

public sealed class TelemetryDeliveryTests
{
    [Fact]
    public async Task Outbox_recovers_in_order_and_removes_only_acknowledged_batch()
    {
        var root = Path.Combine(Path.GetTempPath(), "np-telemetry-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var options = CreateOptions(root);
            var first = CreateOutbox(options);
            await first.AppendAsync([new UserTrafficDelta { UserId = "a", UploadBytes = 1, DownloadBytes = 2 }], CancellationToken.None);
            await first.AppendAsync([new UserTrafficDelta { UserId = "b", UploadBytes = 3, DownloadBytes = 4 }], CancellationToken.None);
            var ids = first.Pending.Select(batch => batch.BatchId).ToArray();

            var reopened = CreateOutbox(options);
            Assert.Equal(ids, reopened.Pending.Select(batch => batch.BatchId));
            reopened.RemoveAcknowledged(ids[0]);
            var restored = CreateOutbox(options);
            Assert.Equal(ids[1], Assert.Single(restored.Pending).BatchId);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Outbox_rejects_a_different_node_or_panel()
    {
        var root = Path.Combine(Path.GetTempPath(), "np-telemetry-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var options = CreateOptions(root);
            await CreateOutbox(options).AppendAsync(
                [new UserTrafficDelta { UserId = "a", UploadBytes = 1, DownloadBytes = 2 }], CancellationToken.None);
            var other = CreateOptions(root, "other");
            Assert.Throws<InvalidOperationException>(() => CreateOutbox(other).Pending);
            var otherPanel = new NodePanelOptions
            {
                CachedConfigPath = options.CachedConfigPath,
                Identity = options.Identity,
                ControlPlane = new ControlPlaneOptions { Url = "ws://different-panel/control/ws" }
            };
            Assert.Throws<InvalidOperationException>(() => CreateOutbox(otherPanel).Pending);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Outbox_rejects_corrupted_persisted_batch()
    {
        var root = Path.Combine(Path.GetTempPath(), "np-telemetry-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var options = CreateOptions(root);
            await CreateOutbox(options).AppendAsync(
                [new UserTrafficDelta { UserId = "a", UploadBytes = 1, DownloadBytes = 2 }], CancellationToken.None);
            var file = Assert.Single(Directory.GetFiles(options.CachedConfigPath + ".telemetry", "*.json"));
            await File.WriteAllTextAsync(file, "{");
            Assert.Throws<System.Text.Json.JsonException>(() => CreateOutbox(options).Pending);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Only_matching_acknowledgment_completes_wait_and_disconnect_unblocks_it()
    {
        var state = new TelemetryDeliveryState();
        state.SetReady();
        var wait = state.BeginWait("batch-a");
        state.Acknowledge("batch-b");
        Assert.False(wait.IsCompleted);
        state.Acknowledge("batch-a");
        Assert.True(await wait);
        state.EndWait("batch-a");
        var next = state.BeginWait("batch-b");
        state.Disconnect();
        Assert.False(await next);
        Assert.False(state.IsReady);
        state.EndWait("batch-b");
    }

    private static NodePanelOptions CreateOptions(string root, string nodeId = "node")
        => new()
        {
            CachedConfigPath = Path.Combine(root, "node-runtime-config.json"),
            Identity = new NodeIdentityOptions { NodeId = nodeId },
            ControlPlane = new ControlPlaneOptions { Url = "ws://localhost/control/ws" }
        };

    private static TelemetryOutbox CreateOutbox(NodePanelOptions options)
        => new(options, new PersistedNodeConfigStore(options, NullLogger<PersistedNodeConfigStore>.Instance));
}

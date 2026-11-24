using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;
using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;

namespace NodePanel.Service.Tests;

public sealed class NodeConnectionRegistryTests
{
    [Fact]
    public async Task Activity_telemetry_roundtrips_and_is_cleared_on_disconnect()
    {
        var status = ActivityRuntime(DateTimeOffset.UtcNow, ["192.0.2.1"], 10, 20).LastStatus!;
        var json = JsonSerializer.Serialize(status, ControlPlaneJsonSerializerContext.Default.NodeStatusPayload);
        var restored = JsonSerializer.Deserialize(json, ControlPlaneJsonSerializerContext.Default.NodeStatusPayload)!;
        Assert.Equal("192.0.2.1", Assert.Single(Assert.Single(restored.UserActivity!).RemoteIps));

        var registry = new NodeConnectionRegistry();
        await using var session = new NodeControlPlaneSession(new ClientWebSocket(), NullLogger<NodeControlPlaneSession>.Instance);
        registry.Register("node", session);
        var payload = new TelemetryBatchPayload { NodeId = "node", AppliedRevision = 1, Traffic = [], Status = restored };
        registry.RecordTelemetry("node", payload);
        var receivedAt = registry.GetRuntime("node").LastTelemetryReceivedAt;
        Assert.NotNull(receivedAt);
        registry.RecordTelemetry("node", payload);
        Assert.Equal(receivedAt, registry.GetRuntime("node").LastTelemetryReceivedAt);
        registry.Unregister("node", session);
        Assert.False(registry.GetRuntime("node").Connected);
        Assert.Null(registry.GetRuntime("node").LastStatus!.UserActivity);
    }

    [Fact]
    public void User_activity_deduplicates_ips_and_marks_missing_or_stale_nodes()
    {
        var now = DateTimeOffset.UtcNow;
        var users = new[] { new PanelUserRecord { UserId = "user" } };
        var nodes = new[] { "a", "b" };
        var runtimes = new Dictionary<string, NodeRuntimeSnapshot>
        {
            ["a"] = ActivityRuntime(now, ["192.0.2.1", "192.0.2.2"], 10, 20),
            ["b"] = ActivityRuntime(now, ["::ffff:192.0.2.1"], 30, 40)
        };
        var result = Assert.Single(UserActivityAggregator.Aggregate(users, nodes, runtimes, now));
        Assert.True(result.HasData);
        Assert.False(result.IsPartial);
        Assert.Equal(2, result.OnlineIpCount);
        Assert.Equal(40, result.UploadBytesPerSecond);
        Assert.Equal(60, result.DownloadBytesPerSecond);

        runtimes["b"] = ActivityRuntime(now.AddMinutes(-2), ["192.0.2.3"], 30, 40);
        result = Assert.Single(UserActivityAggregator.Aggregate(users, nodes, runtimes, now));
        Assert.True(result.IsPartial);
        Assert.Equal(2, result.OnlineIpCount);
        Assert.Equal(10, result.UploadBytesPerSecond);

        users = [new PanelUserRecord { UserId = "user", NodeIds = ["a"] }];
        result = Assert.Single(UserActivityAggregator.Aggregate(users, nodes, runtimes, now));
        Assert.False(result.IsPartial);
        Assert.Equal(10, result.UploadBytesPerSecond);

        runtimes.Clear();
        result = Assert.Single(UserActivityAggregator.Aggregate(users, nodes, runtimes, now));
        Assert.False(result.HasData);
        Assert.Null(result.UploadBytesPerSecond);
    }

    [Fact]
    public void User_activity_handles_initial_sample_and_unknown_ips()
    {
        var now = DateTimeOffset.UtcNow;
        var runtime = ActivityRuntime(now, ["192.0.2.1"], 10, 20);
        runtime = runtime with { LastStatus = runtime.LastStatus! with
        {
            UserActivityRatesAvailable = false,
            UserActivity = [new UserActivityPayload { UserId = "user", HasUnknownRemoteIp = true }]
        } };
        var result = Assert.Single(UserActivityAggregator.Aggregate(
            [new PanelUserRecord { UserId = "user" }],
            ["a"],
            new Dictionary<string, NodeRuntimeSnapshot> { ["a"] = runtime }, now));
        Assert.True(result.HasData);
        Assert.True(result.IsPartial);
        Assert.Null(result.UploadBytesPerSecond);
    }

    private static NodeRuntimeSnapshot ActivityRuntime(DateTimeOffset now, string[] ips, long up, long down)
        => new()
        {
            Connected = true,
            LastTelemetryReceivedAt = now,
            LastStatus = new NodeStatusPayload
            {
                Timestamp = now, ActiveSessions = 1, KnownUsers = 1,
                Inbounds = [], Certificate = new CertificateStatusPayload { Mode = "", Available = false },
                UserActivityIntervalSeconds = 15, UserActivityRatesAvailable = true,
                UserActivity = [new UserActivityPayload { UserId = "user", RemoteIps = ips,
                    UploadBytesPerSecond = up, DownloadBytesPerSecond = down }]
            }
        };

    [Fact]
    public void BuildUserTrafficSummary_resolves_traffic_from_record()
    {
        var user = new PanelUserRecord
        {
            UserId = "shared-user",
            NodeIds = ["node-a"]
        };
        var record = new PanelUserTrafficRecord
        {
            UserId = "shared-user",
            UploadBytes = 10,
            DownloadBytes = 5
        };

        var summary = PanelQueryService.BuildUserTrafficSummary(user, record);

        Assert.Equal("shared-user", summary.UserId);
        Assert.Equal(10, summary.UploadBytes);
        Assert.Equal(5, summary.DownloadBytes);
    }

    [Fact]
    public void BuildUserTrafficSummary_returns_zero_for_missing_record()
    {
        var user = new PanelUserRecord { UserId = "missing-user" };

        var summary = PanelQueryService.BuildUserTrafficSummary(user, null);

        Assert.Equal("missing-user", summary.UserId);
        Assert.Equal(0, summary.UploadBytes);
        Assert.Equal(0, summary.DownloadBytes);
    }
}

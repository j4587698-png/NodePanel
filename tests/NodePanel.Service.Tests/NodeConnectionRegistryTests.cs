using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class NodeConnectionRegistryTests
{
    [Fact]
    public void RecordTelemetry_preserves_scoped_runtime_totals_for_the_same_user()
    {
        var registry = new NodeConnectionRegistry();

        registry.RecordTelemetry(
            "node-a",
            new TelemetryBatchPayload
            {
                NodeId = "node-a",
                AppliedRevision = 1,
                Traffic =
                [
                    new UserTrafficDelta
                    {
                        RuntimeKey = "trojan\u0000in-a\u0000shared-user",
                        Protocol = "trojan",
                        InboundTag = "in-a",
                        UserId = "shared-user",
                        UploadBytes = 100,
                        DownloadBytes = 40
                    },
                    new UserTrafficDelta
                    {
                        RuntimeKey = "vless\u0000in-b\u0000shared-user",
                        Protocol = "vless",
                        InboundTag = "in-b",
                        UserId = "shared-user",
                        UploadBytes = 60,
                        DownloadBytes = 20
                    }
                ],
                Status = new NodeStatusPayload
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    ActiveSessions = 0,
                    KnownUsers = 2,
                    Inbounds = Array.Empty<NodeInboundStatusPayload>(),
                    Certificate = new CertificateStatusPayload
                    {
                        Mode = string.Empty,
                        Available = false
                    }
                }
            });

        var runtime = Assert.Single(registry.GetAllRuntime());
        Assert.Equal(2, runtime.Value.TrafficTotals.Count);
        Assert.Contains(runtime.Value.TrafficTotals, static item => item is
        {
            RuntimeKey: "trojan\u0000in-a\u0000shared-user",
            Protocol: "trojan",
            InboundTag: "in-a",
            UserId: "shared-user",
            UploadBytes: 100,
            DownloadBytes: 40
        });
        Assert.Contains(runtime.Value.TrafficTotals, static item => item is
        {
            RuntimeKey: "vless\u0000in-b\u0000shared-user",
            Protocol: "vless",
            InboundTag: "in-b",
            UserId: "shared-user",
            UploadBytes: 60,
            DownloadBytes: 20
        });
    }

    [Fact]
    public void BuildUserTrafficSummary_sums_all_scoped_runtime_totals_for_the_same_user()
    {
        var user = new PanelUserRecord
        {
            UserId = "shared-user",
            NodeIds = ["node-a"]
        };
        var state = new PanelState
        {
            Nodes =
            [
                new PanelNodeRecord
                {
                    NodeId = "node-a"
                }
            ],
            TrafficRecords =
            [
                new PanelUserTrafficRecord
                {
                    UserId = "shared-user",
                    UploadBytes = 10,
                    DownloadBytes = 5
                }
            ]
        };
        var runtime = new Dictionary<string, NodeRuntimeSnapshot>(StringComparer.Ordinal)
        {
            ["node-a"] = new()
            {
                TrafficTotals =
                [
                    new PanelUserTrafficTotal
                    {
                        RuntimeKey = "trojan\u0000in-a\u0000shared-user",
                        Protocol = "trojan",
                        InboundTag = "in-a",
                        UserId = "shared-user",
                        UploadBytes = 100,
                        DownloadBytes = 40
                    },
                    new PanelUserTrafficTotal
                    {
                        RuntimeKey = "vless\u0000in-b\u0000shared-user",
                        Protocol = "vless",
                        InboundTag = "in-b",
                        UserId = "shared-user",
                        UploadBytes = 60,
                        DownloadBytes = 20
                    }
                ]
            }
        };

        var summary = PanelQueryService.BuildUserTrafficSummary(user, state, runtime);

        Assert.Equal("shared-user", summary.UserId);
        Assert.Equal(170, summary.UploadBytes);
        Assert.Equal(65, summary.DownloadBytes);
    }
}

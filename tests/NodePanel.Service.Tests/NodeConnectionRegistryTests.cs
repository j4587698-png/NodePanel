using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class NodeConnectionRegistryTests
{
    [Fact]
    public void BuildUserTrafficSummary_resolves_traffic_from_state_records()
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
        var runtime = new Dictionary<string, NodeRuntimeSnapshot>(StringComparer.Ordinal);

        var summary = PanelQueryService.BuildUserTrafficSummary(user, state, runtime);

        Assert.Equal("shared-user", summary.UserId);
        Assert.Equal(10, summary.UploadBytes);
        Assert.Equal(5, summary.DownloadBytes);
    }
}

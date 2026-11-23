using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class NodeConnectionRegistryTests
{
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

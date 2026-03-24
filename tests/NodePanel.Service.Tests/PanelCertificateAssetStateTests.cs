using NodePanel.Panel.Models;

namespace NodePanel.Service.Tests;

public sealed class PanelCertificateAssetStateTests
{
    [Fact]
    public void FromRecord_returns_unissued_when_no_asset_fields_exist()
    {
        var state = PanelCertificateAssetState.FromRecord(new PanelCertificateRecord());

        Assert.Equal("未签发", state.Label);
        Assert.Equal("badge badge--idle", state.BadgeClass);
        Assert.False(state.HasUsableAsset);
        Assert.Equal(string.Empty, state.Message);
    }

    [Fact]
    public void FromRecord_returns_issued_when_pfx_and_expiry_exist()
    {
        var state = PanelCertificateAssetState.FromRecord(
            CreateRecord(
                pfxBase64: Convert.ToBase64String([1, 2, 3]),
                thumbprint: "7DAC18B5D4850CC8C557AA06553D11D46E1A4A2F",
                notBefore: DateTimeOffset.UtcNow.AddDays(-1),
                notAfter: DateTimeOffset.UtcNow.AddDays(30),
                lastSuccessAt: DateTimeOffset.UtcNow.AddMinutes(-5)));

        Assert.Equal("已签发", state.Label);
        Assert.Equal("badge badge--ok", state.BadgeClass);
        Assert.True(state.HasUsableAsset);
        Assert.Equal(string.Empty, state.Message);
    }

    [Fact]
    public void FromRecord_returns_incomplete_when_only_thumbprint_exists()
    {
        var state = PanelCertificateAssetState.FromRecord(
            CreateRecord(thumbprint: "7DAC18B5D4850CC8C557AA06553D11D46E1A4A2F"));

        Assert.Equal("资产不完整", state.Label);
        Assert.Equal("badge badge--error", state.BadgeClass);
        Assert.False(state.HasUsableAsset);
        Assert.Contains("历史指纹", state.Message);
    }

    [Fact]
    public void FromRecord_keeps_issued_status_when_asset_is_usable_but_metadata_is_missing()
    {
        var state = PanelCertificateAssetState.FromRecord(
            CreateRecord(
                pfxBase64: Convert.ToBase64String([1, 2, 3]),
                thumbprint: "7DAC18B5D4850CC8C557AA06553D11D46E1A4A2F",
                notAfter: DateTimeOffset.UtcNow.AddDays(30)));

        Assert.Equal("已签发", state.Label);
        Assert.Equal("badge badge--warn", state.BadgeClass);
        Assert.True(state.HasUsableAsset);
        Assert.Contains("缺少上次成功时间", state.Message);
    }

    [Fact]
    public void RuntimeStatus_returns_running_when_progress_snapshot_exists()
    {
        var now = DateTimeOffset.UtcNow;
        var status = PanelCertificateRuntimeStatusView.FromRecord(
            CreateRecord(),
            new PanelCertificateProgressSnapshot
            {
                CertificateId = "panel-cert",
                IsRunning = true,
                TriggerSource = "auto",
                Stage = "等待 ACME 验证 panel.example.com。",
                CurrentStep = 5,
                TotalSteps = 8,
                UpdatedAt = now
            },
            now);

        Assert.Equal("签发中", status.Label);
        Assert.Equal("badge badge--warn", status.BadgeClass);
        Assert.True(status.IsRunning);
        Assert.True(status.ShouldAutoRefresh);
        Assert.Contains("等待 ACME 验证", status.Message);
        Assert.Contains("步骤 5/8", status.Detail);
    }

    [Fact]
    public void RuntimeStatus_returns_pending_when_no_usable_asset_exists()
    {
        var now = DateTimeOffset.UtcNow;
        var status = PanelCertificateRuntimeStatusView.FromRecord(
            CreateRecord(lastSuccessAt: now.AddMinutes(-30)),
            new PanelCertificateProgressSnapshot(),
            now);

        Assert.Equal("待签发", status.Label);
        Assert.Equal("badge badge--warn", status.BadgeClass);
        Assert.Contains("后台循环会尽快尝试", status.Message);
        Assert.NotNull(status.NextAutomaticRunAt);
    }

    [Fact]
    public void RuntimeStatus_returns_ready_when_asset_is_valid_and_not_due()
    {
        var now = DateTimeOffset.UtcNow;
        var status = PanelCertificateRuntimeStatusView.FromRecord(
            CreateRecord(
                pfxBase64: Convert.ToBase64String([1, 2, 3]),
                thumbprint: "7DAC18B5D4850CC8C557AA06553D11D46E1A4A2F",
                notBefore: now.AddDays(-1),
                notAfter: now.AddDays(45),
                lastSuccessAt: now.AddMinutes(-5)),
            new PanelCertificateProgressSnapshot(),
            now);

        Assert.Equal("已就绪", status.Label);
        Assert.Equal("badge badge--ok", status.BadgeClass);
        Assert.Contains("进入自动续签窗口", status.Message);
        Assert.NotNull(status.NextAutomaticRunAt);
        Assert.False(status.ShouldAutoRefresh);
    }

    [Fact]
    public void RuntimeStatus_returns_failed_when_last_attempt_failed()
    {
        var now = DateTimeOffset.UtcNow;
        var status = PanelCertificateRuntimeStatusView.FromRecord(
            CreateRecord(lastSuccessAt: now.AddHours(-2)) with
            {
                LastAttemptAt = now.AddMinutes(-2),
                LastError = "DNS challenge 验证失败。"
            },
            new PanelCertificateProgressSnapshot(),
            now);

        Assert.Equal("最近签发失败", status.Label);
        Assert.Equal("badge badge--error", status.BadgeClass);
        Assert.Contains("DNS challenge 验证失败", status.Message);
        Assert.NotNull(status.NextAutomaticRunAt);
    }

    private static PanelCertificateRecord CreateRecord(
        string pfxBase64 = "",
        string thumbprint = "",
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        DateTimeOffset? lastSuccessAt = null)
        => new()
        {
            CertificateId = "panel-cert",
            Domain = "panel.example.com",
            PfxBase64 = pfxBase64,
            Thumbprint = thumbprint,
            NotBefore = notBefore,
            NotAfter = notAfter,
            LastSuccessAt = lastSuccessAt
        };
}

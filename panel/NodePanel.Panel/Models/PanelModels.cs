using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Panel.Models;

public sealed record PanelState
{
    public IReadOnlyList<PanelNodeRecord> Nodes { get; init; } = Array.Empty<PanelNodeRecord>();

    public IReadOnlyList<PanelUserRecord> Users { get; init; } = Array.Empty<PanelUserRecord>();

    public IReadOnlyList<PanelPlanRecord> Plans { get; init; } = Array.Empty<PanelPlanRecord>();

    public IReadOnlyList<PanelOrderRecord> Orders { get; init; } = Array.Empty<PanelOrderRecord>();

    public IReadOnlyList<PanelUserTrafficRecord> TrafficRecords { get; init; } = Array.Empty<PanelUserTrafficRecord>();

    public IReadOnlyList<PanelSettingRecord> Settings { get; init; } = Array.Empty<PanelSettingRecord>();
}

public sealed record PanelSettingRecord
{
    public string Key { get; init; } = string.Empty;

    public string Value { get; init; } = string.Empty;
}

public sealed record PanelOrderRecord
{
    public string OrderId { get; init; } = string.Empty;

    public string UserId { get; init; } = string.Empty;

    public string PlanId { get; init; } = string.Empty;

    public string Cycle { get; init; } = string.Empty;

    public string TradeNo { get; init; } = string.Empty;

    public decimal TotalAmount { get; init; }

    public int Status { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? PaidAt { get; init; }
}

public sealed record PanelPlanRecord
{
    public string PlanId { get; init; } = string.Empty;

    public int GroupId { get; init; }

    public string Name { get; init; } = string.Empty;

    public long TransferEnableBytes { get; init; }

    public decimal? MonthPrice { get; init; }
    public decimal? QuarterPrice { get; init; }
    public decimal? HalfYearPrice { get; init; }
    public decimal? YearPrice { get; init; }
    public decimal? OneTimePrice { get; init; }
    public decimal? ResetPrice { get; init; }
}

public sealed record PanelUserTrafficRecord
{
    public string UserId { get; init; } = string.Empty;

    public long UploadBytes { get; init; }

    public long DownloadBytes { get; init; }

    public DateTimeOffset? LastResetAt { get; init; }
}

public sealed record PanelUserSubscriptionProfile
{
    public string PlanName { get; init; } = string.Empty;

    public string Cycle { get; init; } = string.Empty;

    public long TransferEnableBytes { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }

    public string PurchaseUrl { get; init; } = string.Empty;

    public string PortalNotice { get; init; } = string.Empty;
}

public sealed record PanelNodeRecord
{
    public string NodeId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string Protocol { get; init; } = "trojan";

    public IReadOnlyList<int> GroupIds { get; init; } = Array.Empty<int>();

    public decimal TrafficMultiplier { get; init; } = 1.0m;

    public bool Enabled { get; init; } = true;

    public int DesiredRevision { get; init; } = 1;

    public string SubscriptionHost { get; init; } = string.Empty;

    public string SubscriptionSni { get; init; } = string.Empty;

    public bool SubscriptionAllowInsecure { get; init; }

    public NodeServiceConfig Config { get; init; } = new();
}

public sealed record PanelUserRecord
{
    public string UserId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string SubscriptionToken { get; init; } = string.Empty;

    public string TrojanPassword { get; init; } = string.Empty;

    public string V2rayUuid { get; init; } = string.Empty;

    public string InviteUserId { get; init; } = string.Empty;

    public decimal CommissionBalance { get; init; }

    public int CommissionRate { get; init; }

    public int GroupId { get; init; }

    public bool Enabled { get; init; } = true;

    public long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }

    public PanelUserSubscriptionProfile Subscription { get; init; } = new();

    public IReadOnlyList<string> NodeIds { get; init; } = Array.Empty<string>();
}

public sealed record UpsertNodeRequest
{
    public string DisplayName { get; init; } = string.Empty;

    public string Protocol { get; init; } = "trojan";

    public IReadOnlyList<int> GroupIds { get; init; } = Array.Empty<int>();

    public decimal TrafficMultiplier { get; init; } = 1.0m;

    public bool Enabled { get; init; } = true;

    public string SubscriptionHost { get; init; } = string.Empty;

    public string SubscriptionSni { get; init; } = string.Empty;

    public bool SubscriptionAllowInsecure { get; init; }

    public NodeServiceConfig Config { get; init; } = new();
}

public sealed record UpsertUserRequest
{
    public string DisplayName { get; init; } = string.Empty;

    public string SubscriptionToken { get; init; } = string.Empty;

    public string TrojanPassword { get; init; } = string.Empty;

    public string V2rayUuid { get; init; } = string.Empty;

    public string InviteUserId { get; init; } = string.Empty;

    public decimal CommissionBalance { get; init; }

    public int CommissionRate { get; init; }

    public int GroupId { get; init; }

    public bool Enabled { get; init; } = true;

    public long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }

    public PanelUserSubscriptionProfile Subscription { get; init; } = new();

    public IReadOnlyList<string> NodeIds { get; init; } = Array.Empty<string>();
}

public sealed record UpsertPlanRequest
{
    public string Name { get; init; } = string.Empty;

    public int GroupId { get; init; }

    public long TransferEnableBytes { get; init; }

    public decimal? MonthPrice { get; init; }
    public decimal? QuarterPrice { get; init; }
    public decimal? HalfYearPrice { get; init; }
    public decimal? YearPrice { get; init; }
    public decimal? OneTimePrice { get; init; }
    public decimal? ResetPrice { get; init; }
}

public sealed record PanelMutationResult
{
    public required PanelState State { get; init; }

    public IReadOnlyList<string> AffectedNodeIds { get; init; } = Array.Empty<string>();
}

public sealed record PanelUserTrafficTotal
{
    public string UserId { get; init; } = string.Empty;

    public long UploadBytes { get; init; }

    public long DownloadBytes { get; init; }
}

public sealed record PanelUserTrafficSummary
{
    public string UserId { get; init; } = string.Empty;

    public long UploadBytes { get; init; }

    public long DownloadBytes { get; init; }

    public long TotalBytes => UploadBytes + DownloadBytes;
}

public sealed record NodeRuntimeSnapshot
{
    public bool Connected { get; init; }

    public int AppliedRevision { get; init; }

    public string Version { get; init; } = string.Empty;

    public string LastApplyError { get; init; } = string.Empty;

    public DateTimeOffset? LastSeenAt { get; init; }

    public NodeStatusPayload? LastStatus { get; init; }

    public IReadOnlyList<PanelUserTrafficTotal> TrafficTotals { get; init; } = Array.Empty<PanelUserTrafficTotal>();
}

public static class CertificateAlertSeverities
{
    public const string None = "none";
    public const string Warning = "warning";
    public const string Error = "error";
}

public sealed record PanelCertificateAlertView
{
    public bool IsActive { get; init; }

    public string Severity { get; init; } = CertificateAlertSeverities.None;

    public string Message { get; init; } = string.Empty;
}

public sealed record PanelNodeView
{
    public required PanelNodeRecord Definition { get; init; }

    public required NodeRuntimeSnapshot Runtime { get; init; }

    public bool CanRequestCertificateRenewal { get; init; }

    public PanelCertificateAlertView CertificateAlert { get; init; } = new();
}

public sealed record PanelStateView
{
    public required IReadOnlyList<PanelNodeView> Nodes { get; init; }

    public required IReadOnlyList<PanelUserRecord> Users { get; init; }

    public required IReadOnlyList<PanelPlanRecord> Plans { get; init; }

    public required IReadOnlyList<PanelOrderRecord> Orders { get; init; }

    public required IReadOnlyDictionary<string, string> Settings { get; init; }

    public required IReadOnlyDictionary<string, PanelUserTrafficSummary> TrafficSummaries { get; init; }
}

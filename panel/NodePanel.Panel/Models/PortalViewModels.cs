namespace NodePanel.Panel.Models;

public sealed class PortalPageViewModel
{
    public string AppName { get; init; } = string.Empty;

    public string StatusMessage { get; set; } = string.Empty;

    public string LookupToken { get; init; } = string.Empty;

    public bool IsResolved { get; init; }

    public string ErrorMessage { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string CurrentSubscriptionToken { get; init; } = string.Empty;

    public bool AllowSubscriptionReset { get; init; }

    public string ResetSubscriptionReturnTarget { get; init; } = "portal";

    public string PortalUrl { get; init; } = string.Empty;

    public string SubscriptionUrl { get; init; } = string.Empty;

    public string RawSubscriptionUrl { get; init; } = string.Empty;

    public string PlanName { get; init; } = "未设置套餐";

    public string ExpiresAtText { get; init; } = "长期有效";

    public string UsedTrafficText { get; init; } = "0 B";

    public string RemainingTrafficText { get; init; } = "未限制";

    public string TotalTrafficText { get; init; } = "未限制";

    public string Notice { get; init; } = string.Empty;

    public string PurchaseUrl { get; init; } = string.Empty;

    public string CurrencySymbol { get; init; } = "¥";

    public PortalReferralCenterViewModel Referral { get; init; } = new();

    public IReadOnlyList<PortalClientLinkViewModel> ImportLinks { get; init; } = Array.Empty<PortalClientLinkViewModel>();

    public IReadOnlyList<PortalNodeViewModel> Nodes { get; init; } = Array.Empty<PortalNodeViewModel>();

    public string RawSubscriptionContent { get; init; } = string.Empty;
}

public sealed record PortalClientLinkViewModel
{
    public required string Title { get; init; }

    public required string Description { get; init; }

    public required string Url { get; init; }
}

public sealed record PortalNodeViewModel
{
    public required string CopyId { get; init; }

    public required string Name { get; init; }

    public required string TransportLabel { get; init; }

    public required string Address { get; init; }

    public string Sni { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public required string ManualUri { get; init; }
}

public sealed class PortalReferralCenterViewModel
{
    public bool InviteOnlyRegistrationEnabled { get; init; }

    public int MaxInviteCodes { get; init; } = 1;

    public string MaxInviteCodesText { get; init; } = "1";

    public string RemainingInviteCodesText { get; init; } = "0";

    public bool CanGenerateInviteCode { get; init; }

    public int InviteCodeCount { get; init; }

    public int InvitedUserCount { get; init; }

    public decimal CommissionBalance { get; init; }

    public decimal CommissionTotal { get; init; }

    public int CommissionRate { get; init; }

    public IReadOnlyList<PortalInviteCodeViewModel> InviteCodes { get; init; } = Array.Empty<PortalInviteCodeViewModel>();

    public IReadOnlyList<PortalInviteeViewModel> Invitees { get; init; } = Array.Empty<PortalInviteeViewModel>();

    public IReadOnlyList<PortalCommissionLogItemViewModel> CommissionLogs { get; init; } = Array.Empty<PortalCommissionLogItemViewModel>();
}

public sealed record PortalInviteCodeViewModel
{
    public required string Code { get; init; }

    public required string CreatedAtText { get; init; }

    public int UsageCount { get; init; }

    public string LastUsedAtText { get; init; } = "-";
}

public sealed record PortalInviteeViewModel
{
    public required string UserId { get; init; }

    public required string DisplayName { get; init; }

    public required string Email { get; init; }

    public string AppliedInviteCode { get; init; } = "-";

    public required string CreatedAtText { get; init; }
}

public sealed record PortalCommissionLogItemViewModel
{
    public required string OrderId { get; init; }

    public decimal TradeAmount { get; init; }

    public decimal CommissionAmount { get; init; }

    public required string CreatedAtText { get; init; }
}

public sealed class PortalStoreViewModel
{
    public string AppName { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public IReadOnlyList<PanelPlanRecord> Plans { get; init; } = Array.Empty<PanelPlanRecord>();
    public string CurrencySymbol { get; init; } = "¥";
    public string StatusMessage { get; set; } = string.Empty;
}

public sealed class PortalOrdersViewModel
{
    public string AppName { get; init; } = string.Empty;
    public string DisplayName { get; init; } = string.Empty;
    public IReadOnlyList<PanelOrderRecord> Orders { get; init; } = Array.Empty<PanelOrderRecord>();
    public IReadOnlyList<PanelPlanRecord> Plans { get; init; } = Array.Empty<PanelPlanRecord>();
    public string CurrencySymbol { get; init; } = "¥";
    public string StatusMessage { get; set; } = string.Empty;
}

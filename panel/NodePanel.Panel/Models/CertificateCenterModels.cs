using System.ComponentModel.DataAnnotations;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Panel.Models;

public static class PanelSettingKeys
{
    public const string PanelHttpsEnabled = "panel_https_enabled";
    public const string PanelHttpsCertificateId = "panel_https_certificate_id";
    public const string PanelHttpsListenAddress = "panel_https_listen_address";
    public const string PanelHttpsPort = "panel_https_port";
    public const string PanelHttpsRedirectHttp = "panel_https_redirect_http";
}

public sealed record PanelCertificateRecord
{
    public string CertificateId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public string Domain { get; init; } = string.Empty;

    public IReadOnlyList<string> AltNames { get; init; } = Array.Empty<string>();

    public string Email { get; init; } = string.Empty;

    public string AcmeDirectoryUrl { get; init; } = string.Empty;

    public string ChallengeType { get; init; } = CertificateChallengeTypes.Http01;

    public int RenewBeforeDays { get; init; } = 30;

    public int CheckIntervalMinutes { get; init; } = 60;

    public bool UseStaging { get; init; }

    public string PfxPassword { get; init; } = string.Empty;

    public string DnsProvider { get; init; } = string.Empty;

    public string DnsZone { get; init; } = string.Empty;

    public string DnsApiToken { get; init; } = string.Empty;

    public string DnsAccessKeyId { get; init; } = string.Empty;

    public string DnsAccessKeySecret { get; init; } = string.Empty;

    public string DnsHookPresentCommand { get; init; } = string.Empty;

    public string DnsHookPresentArguments { get; init; } = string.Empty;

    public string DnsHookCleanupCommand { get; init; } = string.Empty;

    public string DnsHookCleanupArguments { get; init; } = string.Empty;

    public IReadOnlyList<CertificateEnvironmentVariable> EnvironmentVariables { get; init; } = Array.Empty<CertificateEnvironmentVariable>();

    public int AssetVersion { get; init; }

    public string PfxBase64 { get; init; } = string.Empty;

    public string Thumbprint { get; init; } = string.Empty;

    public DateTimeOffset? NotBefore { get; init; }

    public DateTimeOffset? NotAfter { get; init; }

    public DateTimeOffset? LastAttemptAt { get; init; }

    public DateTimeOffset? LastSuccessAt { get; init; }

    public string LastError { get; init; } = string.Empty;

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset UpdatedAt { get; init; }
}

public sealed record PanelCertificateView
{
    public required PanelCertificateRecord Definition { get; init; }

    public int BoundNodeCount { get; init; }

    public bool UsedByPanelHttps { get; init; }

    public PanelCertificateProgressSnapshot Progress { get; init; } = new();

    public DateTimeOffset SnapshotTime { get; init; } = DateTimeOffset.UtcNow;

    public PanelCertificateAssetState AssetState => PanelCertificateAssetState.FromRecord(Definition);

    public PanelCertificateRuntimeStatusView RuntimeStatus
        => PanelCertificateRuntimeStatusView.FromRecord(Definition, Progress, SnapshotTime);

    public bool ShouldAutoRefresh => RuntimeStatus.ShouldAutoRefresh;
}

public sealed record PanelCertificateProgressSnapshot
{
    public string CertificateId { get; init; } = string.Empty;

    public bool IsRunning { get; init; }

    public string TriggerSource { get; init; } = string.Empty;

    public string Stage { get; init; } = string.Empty;

    public int CurrentStep { get; init; }

    public int TotalSteps { get; init; }

    public DateTimeOffset StartedAt { get; init; }

    public DateTimeOffset UpdatedAt { get; init; }

    public string StepLabel
        => CurrentStep > 0 && TotalSteps > 0
            ? $"步骤 {CurrentStep}/{TotalSteps}"
            : string.Empty;
}

public sealed record PanelCertificateAssetState
{
    public string Label { get; init; } = "未签发";

    public string BadgeClass { get; init; } = "badge badge--idle";

    public string Message { get; init; } = string.Empty;

    public bool HasUsableAsset { get; init; }

    public static PanelCertificateAssetState FromRecord(PanelCertificateRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        var hasPfx = !string.IsNullOrWhiteSpace(record.PfxBase64);
        var hasThumbprint = !string.IsNullOrWhiteSpace(record.Thumbprint);
        var hasNotBefore = record.NotBefore is not null;
        var hasNotAfter = record.NotAfter is not null;
        var hasLastSuccess = record.LastSuccessAt is not null;

        if (!hasPfx && !hasThumbprint && !hasNotBefore && !hasNotAfter && !hasLastSuccess)
        {
            return new PanelCertificateAssetState();
        }

        if (hasPfx && hasNotAfter)
        {
            var warnings = new List<string>();
            if (!hasLastSuccess)
            {
                warnings.Add("缺少上次成功时间");
            }

            if (!hasThumbprint)
            {
                warnings.Add("缺少证书指纹");
            }

            if (!hasNotBefore)
            {
                warnings.Add("缺少生效时间");
            }

            return new PanelCertificateAssetState
            {
                Label = "已签发",
                BadgeClass = warnings.Count == 0 ? "badge badge--ok" : "badge badge--warn",
                Message = warnings.Count == 0 ? string.Empty : $"证书资产可用，但{string.Join("、", warnings)}。",
                HasUsableAsset = true
            };
        }

        var issues = new List<string>();
        if (hasThumbprint && !hasPfx && !hasNotAfter && !hasLastSuccess)
        {
            issues.Add("检测到历史指纹，但没有可用证书资产");
        }
        else
        {
            if (!hasPfx)
            {
                issues.Add("缺少 PFX 资产");
            }

            if (!hasNotAfter)
            {
                issues.Add("缺少有效期");
            }

            if (!hasLastSuccess)
            {
                issues.Add("缺少上次成功时间");
            }
        }

        if (!hasThumbprint)
        {
            issues.Add("缺少证书指纹");
        }

        if (!hasNotBefore && (hasPfx || hasNotAfter || hasLastSuccess))
        {
            issues.Add("缺少生效时间");
        }

        return new PanelCertificateAssetState
        {
            Label = "资产不完整",
            BadgeClass = "badge badge--error",
            Message = $"{string.Join("；", issues)}。",
            HasUsableAsset = false
        };
    }
}

public sealed record PanelCertificateRuntimeStatusView
{
    public string Label { get; init; } = "未调度";

    public string BadgeClass { get; init; } = "badge badge--idle";

    public string Message { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public DateTimeOffset? NextAutomaticRunAt { get; init; }

    public bool IsRunning { get; init; }

    public bool ShouldAutoRefresh { get; init; }

    public static PanelCertificateRuntimeStatusView FromRecord(
        PanelCertificateRecord record,
        PanelCertificateProgressSnapshot progress,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(progress);

        if (progress.IsRunning)
        {
            var detailParts = new List<string>();
            var triggerLabel = GetTriggerLabel(progress.TriggerSource);
            if (!string.IsNullOrWhiteSpace(triggerLabel))
            {
                detailParts.Add(triggerLabel);
            }

            if (!string.IsNullOrWhiteSpace(progress.StepLabel))
            {
                detailParts.Add(progress.StepLabel);
            }

            if (progress.UpdatedAt != default)
            {
                detailParts.Add($"更新于 {progress.UpdatedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
            }

            return new PanelCertificateRuntimeStatusView
            {
                Label = "签发中",
                BadgeClass = "badge badge--warn",
                Message = string.IsNullOrWhiteSpace(progress.Stage) ? "后台正在处理证书签发。" : progress.Stage,
                Detail = string.Join(" · ", detailParts),
                IsRunning = true,
                ShouldAutoRefresh = true
            };
        }

        if (!record.Enabled)
        {
            return new PanelCertificateRuntimeStatusView
            {
                Label = "已停用",
                BadgeClass = "badge badge--idle",
                Message = "自动续签已关闭。"
            };
        }

        var nextAutomaticRunAt = CalculateNextAutomaticRunAt(record, now);
        var hasUsableAsset = !string.IsNullOrWhiteSpace(record.PfxBase64) && record.NotAfter is not null;
        var lastAttemptFailed = !string.IsNullOrWhiteSpace(record.LastError) &&
                                record.LastAttemptAt is not null &&
                                (record.LastSuccessAt is null || record.LastAttemptAt >= record.LastSuccessAt);

        if (lastAttemptFailed)
        {
            return new PanelCertificateRuntimeStatusView
            {
                Label = hasUsableAsset ? "最近续签失败" : "最近签发失败",
                BadgeClass = hasUsableAsset ? "badge badge--warn" : "badge badge--error",
                Message = record.LastError,
                Detail = FormatNextAutomaticRunDetail(nextAutomaticRunAt, now),
                NextAutomaticRunAt = nextAutomaticRunAt
            };
        }

        if (!hasUsableAsset)
        {
            return new PanelCertificateRuntimeStatusView
            {
                Label = "待签发",
                BadgeClass = "badge badge--warn",
                Message = BuildPendingMessage("满足自动签发条件", nextAutomaticRunAt, now),
                Detail = FormatNextAutomaticRunDetail(nextAutomaticRunAt, now),
                NextAutomaticRunAt = nextAutomaticRunAt
            };
        }

        var renewWindowAt = record.NotAfter!.Value.AddDays(-Math.Max(1, record.RenewBeforeDays));
        if (renewWindowAt <= now)
        {
            return new PanelCertificateRuntimeStatusView
            {
                Label = "待续签",
                BadgeClass = "badge badge--warn",
                Message = BuildPendingMessage("已进入自动续签窗口", nextAutomaticRunAt, now),
                Detail = FormatNextAutomaticRunDetail(nextAutomaticRunAt, now),
                NextAutomaticRunAt = nextAutomaticRunAt
            };
        }

        return new PanelCertificateRuntimeStatusView
        {
            Label = "已就绪",
            BadgeClass = "badge badge--ok",
            Message = $"预计在 {renewWindowAt.ToLocalTime():yyyy-MM-dd HH:mm:ss} 进入自动续签窗口。",
            Detail = FormatNextAutomaticRunDetail(renewWindowAt, now),
            NextAutomaticRunAt = renewWindowAt
        };
    }

    private static DateTimeOffset? CalculateNextAutomaticRunAt(PanelCertificateRecord record, DateTimeOffset now)
    {
        if (!record.Enabled)
        {
            return null;
        }

        var retryAt = record.LastAttemptAt?.AddMinutes(Math.Max(1, record.CheckIntervalMinutes));
        var hasUsableAsset = !string.IsNullOrWhiteSpace(record.PfxBase64) && record.NotAfter is not null;
        if (!hasUsableAsset)
        {
            if (retryAt is null)
            {
                return now;
            }

            return retryAt > now ? retryAt : now;
        }

        var renewWindowAt = record.NotAfter!.Value.AddDays(-Math.Max(1, record.RenewBeforeDays));
        if (renewWindowAt > now)
        {
            return renewWindowAt;
        }

        if (retryAt is null)
        {
            return now;
        }

        return retryAt > now ? retryAt : now;
    }

    private static string BuildPendingMessage(string prefix, DateTimeOffset? nextAutomaticRunAt, DateTimeOffset now)
    {
        if (nextAutomaticRunAt is null || nextAutomaticRunAt <= now)
        {
            return $"{prefix}，后台循环会尽快尝试。";
        }

        return $"{prefix}，计划在 {nextAutomaticRunAt.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss} 自动处理。";
    }

    private static string FormatNextAutomaticRunDetail(DateTimeOffset? nextAutomaticRunAt, DateTimeOffset now)
    {
        if (nextAutomaticRunAt is null)
        {
            return string.Empty;
        }

        if (nextAutomaticRunAt <= now)
        {
            return "后台循环已满足处理条件。";
        }

        return $"下次自动处理 {nextAutomaticRunAt.Value.ToLocalTime():yyyy-MM-dd HH:mm:ss}";
    }

    private static string GetTriggerLabel(string triggerSource)
        => triggerSource.Trim().ToLowerInvariant() switch
        {
            "manual" => "手动触发",
            "auto" => "自动触发",
            _ => string.Empty
        };
}

public sealed record UpsertPanelCertificateRequest
{
    public string DisplayName { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public string Domain { get; init; } = string.Empty;

    public IReadOnlyList<string> AltNames { get; init; } = Array.Empty<string>();

    public string Email { get; init; } = string.Empty;

    public string AcmeDirectoryUrl { get; init; } = string.Empty;

    public string ChallengeType { get; init; } = CertificateChallengeTypes.Http01;

    public int RenewBeforeDays { get; init; } = 30;

    public int CheckIntervalMinutes { get; init; } = 60;

    public bool UseStaging { get; init; }

    public string PfxPassword { get; init; } = string.Empty;

    public string DnsProvider { get; init; } = string.Empty;

    public string DnsZone { get; init; } = string.Empty;

    public string DnsApiToken { get; init; } = string.Empty;

    public string DnsAccessKeyId { get; init; } = string.Empty;

    public string DnsAccessKeySecret { get; init; } = string.Empty;

    public string DnsHookPresentCommand { get; init; } = string.Empty;

    public string DnsHookPresentArguments { get; init; } = string.Empty;

    public string DnsHookCleanupCommand { get; init; } = string.Empty;

    public string DnsHookCleanupArguments { get; init; } = string.Empty;

    public IReadOnlyList<CertificateEnvironmentVariable> EnvironmentVariables { get; init; } = Array.Empty<CertificateEnvironmentVariable>();
}

public sealed class PanelCertificateFormInput
{
    [Required(ErrorMessage = "证书 ID 不能为空。")]
    public string CertificateId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    [Required(ErrorMessage = "主域名不能为空。")]
    public string Domain { get; set; } = string.Empty;

    public string AltNames { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string AcmeDirectoryUrl { get; set; } = string.Empty;

    public string ChallengeType { get; set; } = CertificateChallengeTypes.Http01;

    [Range(1, 365, ErrorMessage = "续签提前天数必须在 1 到 365 之间。")]
    public int RenewBeforeDays { get; set; } = 30;

    [Range(1, 1440, ErrorMessage = "检查间隔必须在 1 到 1440 分钟之间。")]
    public int CheckIntervalMinutes { get; set; } = 60;

    public bool UseStaging { get; set; }

    public string PfxPassword { get; set; } = string.Empty;

    public string DnsProvider { get; set; } = string.Empty;

    public string DnsZone { get; set; } = string.Empty;

    public string DnsApiToken { get; set; } = string.Empty;

    public string DnsAccessKeyId { get; set; } = string.Empty;

    public string DnsAccessKeySecret { get; set; } = string.Empty;

    public string DnsHookPresentCommand { get; set; } = string.Empty;

    public string DnsHookPresentArguments { get; set; } = string.Empty;

    public string DnsHookCleanupCommand { get; set; } = string.Empty;

    public string DnsHookCleanupArguments { get; set; } = string.Empty;

    public string EnvironmentVariables { get; set; } = string.Empty;

    public bool TryToRequest(out UpsertPanelCertificateRequest request, out string error)
    {
        if (!NodeFormValueCodec.TryParseEnvironmentVariables(EnvironmentVariables, out var variables, out error))
        {
            request = new UpsertPanelCertificateRequest();
            return false;
        }

        var challengeType = CertificateChallengeTypes.Normalize(ChallengeType);
        var dnsProvider = PanelDnsProviderTypes.Normalize(DnsProvider);
        var domains = NodeFormValueCodec.ParseCsv(AltNames)
            .Prepend(Domain)
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Select(static item => item.Trim())
            .ToArray();

        if (challengeType == CertificateChallengeTypes.TlsAlpn01)
        {
            request = new UpsertPanelCertificateRequest();
            error = "Panel 证书中心当前只支持 http-01 和 dns-01。";
            return false;
        }

        if (domains.Any(static item => item.StartsWith("*.", StringComparison.Ordinal)) &&
            challengeType != CertificateChallengeTypes.Dns01)
        {
            request = new UpsertPanelCertificateRequest();
            error = "泛域名证书必须使用 dns-01。";
            return false;
        }

        if (challengeType == CertificateChallengeTypes.Dns01 &&
            string.IsNullOrWhiteSpace(dnsProvider) &&
            string.IsNullOrWhiteSpace(DnsHookPresentCommand))
        {
            request = new UpsertPanelCertificateRequest();
            error = "DNS-01 模式需要选择 DNS 服务商 API，或在兼容模式中填写添加 TXT 记录命令。";
            return false;
        }

        if (challengeType == CertificateChallengeTypes.Dns01 &&
            !string.IsNullOrWhiteSpace(dnsProvider) &&
            string.IsNullOrWhiteSpace(DnsZone))
        {
            request = new UpsertPanelCertificateRequest();
            error = "DNS-01 API 模式需要填写根域名 / Zone。";
            return false;
        }

        if (challengeType == CertificateChallengeTypes.Dns01 &&
            PanelDnsProviderTypes.RequiresApiToken(dnsProvider) &&
            string.IsNullOrWhiteSpace(DnsApiToken))
        {
            request = new UpsertPanelCertificateRequest();
            error = "Cloudflare DNS-01 需要 API Token。";
            return false;
        }

        if (challengeType == CertificateChallengeTypes.Dns01 &&
            PanelDnsProviderTypes.RequiresAccessKeyPair(dnsProvider) &&
            (string.IsNullOrWhiteSpace(DnsAccessKeyId) || string.IsNullOrWhiteSpace(DnsAccessKeySecret)))
        {
            request = new UpsertPanelCertificateRequest();
            error = "AliDNS / DNSPod DNS-01 需要 AccessKey ID / SecretId 和 AccessKey Secret / SecretKey。";
            return false;
        }

        request = new UpsertPanelCertificateRequest
        {
            DisplayName = NodeFormValueCodec.TrimOrEmpty(DisplayName),
            Enabled = Enabled,
            Domain = NodeFormValueCodec.TrimOrEmpty(Domain),
            AltNames = domains.Skip(1).ToArray(),
            Email = NodeFormValueCodec.TrimOrEmpty(Email),
            AcmeDirectoryUrl = NodeFormValueCodec.TrimOrEmpty(AcmeDirectoryUrl),
            ChallengeType = challengeType,
            RenewBeforeDays = RenewBeforeDays,
            CheckIntervalMinutes = CheckIntervalMinutes,
            UseStaging = UseStaging,
            PfxPassword = NodeFormValueCodec.TrimOrEmpty(PfxPassword),
            DnsProvider = dnsProvider,
            DnsZone = NodeFormValueCodec.TrimOrEmpty(DnsZone),
            DnsApiToken = NodeFormValueCodec.TrimOrEmpty(DnsApiToken),
            DnsAccessKeyId = NodeFormValueCodec.TrimOrEmpty(DnsAccessKeyId),
            DnsAccessKeySecret = NodeFormValueCodec.TrimOrEmpty(DnsAccessKeySecret),
            DnsHookPresentCommand = NodeFormValueCodec.TrimOrEmpty(DnsHookPresentCommand),
            DnsHookPresentArguments = NodeFormValueCodec.TrimOrEmpty(DnsHookPresentArguments),
            DnsHookCleanupCommand = NodeFormValueCodec.TrimOrEmpty(DnsHookCleanupCommand),
            DnsHookCleanupArguments = NodeFormValueCodec.TrimOrEmpty(DnsHookCleanupArguments),
            EnvironmentVariables = variables
        };

        error = string.Empty;
        return true;
    }

    public static PanelCertificateFormInput FromRecord(PanelCertificateRecord record)
        => new()
        {
            CertificateId = record.CertificateId,
            DisplayName = record.DisplayName,
            Enabled = record.Enabled,
            Domain = record.Domain,
            AltNames = string.Join(", ", record.AltNames),
            Email = record.Email,
            AcmeDirectoryUrl = record.AcmeDirectoryUrl,
            ChallengeType = CertificateChallengeTypes.Normalize(record.ChallengeType),
            RenewBeforeDays = Math.Clamp(record.RenewBeforeDays, 1, 365),
            CheckIntervalMinutes = Math.Clamp(record.CheckIntervalMinutes, 1, 1440),
            UseStaging = record.UseStaging,
            PfxPassword = record.PfxPassword,
            DnsProvider = PanelDnsProviderTypes.Normalize(record.DnsProvider),
            DnsZone = record.DnsZone,
            DnsApiToken = record.DnsApiToken,
            DnsAccessKeyId = record.DnsAccessKeyId,
            DnsAccessKeySecret = record.DnsAccessKeySecret,
            DnsHookPresentCommand = record.DnsHookPresentCommand,
            DnsHookPresentArguments = record.DnsHookPresentArguments,
            DnsHookCleanupCommand = record.DnsHookCleanupCommand,
            DnsHookCleanupArguments = record.DnsHookCleanupArguments,
            EnvironmentVariables = NodeFormValueCodec.FormatEnvironmentVariables(record.EnvironmentVariables)
        };
}

public sealed class PanelHttpsSettingsFormInput
{
    public string CertificateId { get; set; } = string.Empty;

    public bool RedirectHttpToHttps { get; set; }

    public PanelHttpsSettingsFormInput Normalize()
        => new()
        {
            CertificateId = NodeFormValueCodec.TrimOrEmpty(CertificateId),
            RedirectHttpToHttps = RedirectHttpToHttps
        };

    public static PanelHttpsSettingsFormInput FromSettings(IReadOnlyDictionary<string, string> settings)
        => new()
        {
            CertificateId = settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsCertificateId) ?? string.Empty,
            RedirectHttpToHttps = bool.TryParse(settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsRedirectHttp), out var redirect) && redirect
        };

    public IReadOnlyDictionary<string, string> ToSettings()
    {
        var normalized = Normalize();
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [PanelSettingKeys.PanelHttpsCertificateId] = normalized.CertificateId,
            [PanelSettingKeys.PanelHttpsRedirectHttp] = normalized.RedirectHttpToHttps ? "true" : "false"
        };
    }
}

public sealed class CertificateListPageViewModel
{
    public IReadOnlyList<PanelCertificateView> Certificates { get; init; } = Array.Empty<PanelCertificateView>();

    public PanelHttpsSettingsFormInput PanelHttps { get; init; } = new();

    public string StatusMessage { get; init; } = string.Empty;

    public bool ShouldAutoRefresh => Certificates.Any(static certificate => certificate.ShouldAutoRefresh);
}

public sealed class CertificateEditorViewModel
{
    public required PanelCertificateFormInput Form { get; init; }

    public required bool IsEditMode { get; init; }

    public string StatusMessage { get; init; } = string.Empty;

    public PanelCertificateView? Certificate { get; init; }

    public bool ShouldAutoRefresh => Certificate?.ShouldAutoRefresh == true;
}

public sealed class PanelRestartingViewModel
{
    public string Title { get; init; } = "正在重启面板";

    public string Message { get; init; } = string.Empty;

    public string RedirectUrl { get; init; } = "/admin/certificates";
}

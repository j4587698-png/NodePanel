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
    public bool Enabled { get; set; }

    public string CertificateId { get; set; } = string.Empty;

    public string ListenAddress { get; set; } = "0.0.0.0";

    [Range(1, 65535, ErrorMessage = "Panel HTTPS 端口必须在 1 到 65535 之间。")]
    public int Port { get; set; } = 443;

    public bool RedirectHttpToHttps { get; set; }

    public PanelHttpsSettingsFormInput Normalize()
        => new()
        {
            Enabled = Enabled,
            CertificateId = NodeFormValueCodec.TrimOrEmpty(CertificateId),
            ListenAddress = string.IsNullOrWhiteSpace(ListenAddress) ? "0.0.0.0" : NodeFormValueCodec.TrimOrEmpty(ListenAddress),
            Port = Port is > 0 and <= 65535 ? Port : 443,
            RedirectHttpToHttps = RedirectHttpToHttps
        };

    public bool RequiresProcessRestart(PanelHttpsSettingsFormInput previous)
    {
        ArgumentNullException.ThrowIfNull(previous);

        var current = Normalize();
        var before = previous.Normalize();
        if (current.Enabled != before.Enabled)
        {
            return true;
        }

        if (!current.Enabled)
        {
            return false;
        }

        return !string.Equals(current.ListenAddress, before.ListenAddress, StringComparison.OrdinalIgnoreCase) ||
               current.Port != before.Port;
    }

    public static PanelHttpsSettingsFormInput FromSettings(IReadOnlyDictionary<string, string> settings)
        => new()
        {
            Enabled = bool.TryParse(settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsEnabled), out var enabled) && enabled,
            CertificateId = settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsCertificateId) ?? string.Empty,
            ListenAddress = string.IsNullOrWhiteSpace(settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsListenAddress))
                ? "0.0.0.0"
                : settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsListenAddress)!.Trim(),
            Port = int.TryParse(settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsPort), out var port) && port is > 0 and <= 65535
                ? port
                : 443,
            RedirectHttpToHttps = bool.TryParse(settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsRedirectHttp), out var redirect) && redirect
        };

    public IReadOnlyDictionary<string, string> ToSettings()
    {
        var normalized = Normalize();
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [PanelSettingKeys.PanelHttpsEnabled] = normalized.Enabled ? "true" : "false",
            [PanelSettingKeys.PanelHttpsCertificateId] = normalized.CertificateId,
            [PanelSettingKeys.PanelHttpsListenAddress] = normalized.ListenAddress,
            [PanelSettingKeys.PanelHttpsPort] = normalized.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [PanelSettingKeys.PanelHttpsRedirectHttp] = normalized.RedirectHttpToHttps ? "true" : "false"
        };
    }
}

public sealed class CertificateListPageViewModel
{
    public IReadOnlyList<PanelCertificateView> Certificates { get; init; } = Array.Empty<PanelCertificateView>();

    public PanelHttpsSettingsFormInput PanelHttps { get; init; } = new();

    public string StatusMessage { get; init; } = string.Empty;
}

public sealed class CertificateEditorViewModel
{
    public required PanelCertificateFormInput Form { get; init; }

    public required bool IsEditMode { get; init; }

    public string StatusMessage { get; init; } = string.Empty;
}

public sealed class PanelRestartingViewModel
{
    public string Title { get; init; } = "正在重启面板";

    public string Message { get; init; } = string.Empty;

    public string RedirectUrl { get; init; } = "/admin/certificates";
}

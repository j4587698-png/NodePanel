using System.Text.Json;
using FreeSql.DataAnnotations;
using NodePanel.ControlPlane.Configuration;
using ColumnAttribute = FreeSql.DataAnnotations.ColumnAttribute;
using TableAttribute = FreeSql.DataAnnotations.TableAttribute;

namespace NodePanel.Panel.Models;

[Table(Name = "np_certificates")]
public sealed class PanelCertificateEntity
{
    [Column(IsPrimary = true)]
    public string CertificateId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public string Domain { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string AltNamesJson { get; set; } = "[]";

    public string Email { get; set; } = string.Empty;

    public string AcmeDirectoryUrl { get; set; } = string.Empty;

    [Column(DbType = "varchar(32)")]
    public string ChallengeType { get; set; } = CertificateChallengeTypes.Http01;

    public int RenewBeforeDays { get; set; } = 30;

    public int CheckIntervalMinutes { get; set; } = 60;

    public bool UseStaging { get; set; }

    public string PfxPassword { get; set; } = string.Empty;

    [Column(DbType = "varchar(32)")]
    public string DnsProvider { get; set; } = string.Empty;

    public string DnsZone { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string DnsApiToken { get; set; } = string.Empty;

    public string DnsAccessKeyId { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string DnsAccessKeySecret { get; set; } = string.Empty;

    public string DnsHookPresentCommand { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string DnsHookPresentArguments { get; set; } = string.Empty;

    public string DnsHookCleanupCommand { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string DnsHookCleanupArguments { get; set; } = string.Empty;

    [Column(StringLength = -1)]
    public string EnvironmentVariablesJson { get; set; } = "[]";

    [Column(StringLength = -1)]
    public string AcmeAccountKeyPem { get; set; } = string.Empty;

    public int AssetVersion { get; set; }

    [Column(StringLength = -1)]
    public string PfxBase64 { get; set; } = string.Empty;

    public string Thumbprint { get; set; } = string.Empty;

    public DateTimeOffset? NotBefore { get; set; }

    public DateTimeOffset? NotAfter { get; set; }

    public DateTimeOffset? LastAttemptAt { get; set; }

    public DateTimeOffset? LastSuccessAt { get; set; }

    [Column(StringLength = -1)]
    public string LastError { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public IReadOnlyList<string> AltNames
    {
        get => string.IsNullOrWhiteSpace(AltNamesJson)
            ? Array.Empty<string>()
            : JsonSerializer.Deserialize<string[]>(AltNamesJson) ?? Array.Empty<string>();
        set => AltNamesJson = JsonSerializer.Serialize(value ?? Array.Empty<string>());
    }

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public IReadOnlyList<CertificateEnvironmentVariable> EnvironmentVariables
    {
        get => string.IsNullOrWhiteSpace(EnvironmentVariablesJson)
            ? Array.Empty<CertificateEnvironmentVariable>()
            : JsonSerializer.Deserialize<CertificateEnvironmentVariable[]>(EnvironmentVariablesJson) ?? Array.Empty<CertificateEnvironmentVariable>();
        set => EnvironmentVariablesJson = JsonSerializer.Serialize(value ?? Array.Empty<CertificateEnvironmentVariable>());
    }

    public PanelCertificateRecord ToRecord() => new()
    {
        CertificateId = CertificateId,
        DisplayName = DisplayName,
        Enabled = Enabled,
        Domain = Domain,
        AltNames = AltNames,
        Email = Email,
        AcmeDirectoryUrl = AcmeDirectoryUrl,
        ChallengeType = ChallengeType,
        RenewBeforeDays = RenewBeforeDays,
        CheckIntervalMinutes = CheckIntervalMinutes,
        UseStaging = UseStaging,
        PfxPassword = PfxPassword,
        DnsProvider = DnsProvider,
        DnsZone = DnsZone,
        DnsApiToken = DnsApiToken,
        DnsAccessKeyId = DnsAccessKeyId,
        DnsAccessKeySecret = DnsAccessKeySecret,
        DnsHookPresentCommand = DnsHookPresentCommand,
        DnsHookPresentArguments = DnsHookPresentArguments,
        DnsHookCleanupCommand = DnsHookCleanupCommand,
        DnsHookCleanupArguments = DnsHookCleanupArguments,
        EnvironmentVariables = EnvironmentVariables,
        AssetVersion = AssetVersion,
        PfxBase64 = PfxBase64,
        Thumbprint = Thumbprint,
        NotBefore = NotBefore,
        NotAfter = NotAfter,
        LastAttemptAt = LastAttemptAt,
        LastSuccessAt = LastSuccessAt,
        LastError = LastError,
        CreatedAt = CreatedAt,
        UpdatedAt = UpdatedAt
    };

    public void ApplyRecord(PanelCertificateRecord record)
    {
        DisplayName = record.DisplayName;
        Enabled = record.Enabled;
        Domain = record.Domain;
        AltNames = record.AltNames;
        Email = record.Email;
        AcmeDirectoryUrl = record.AcmeDirectoryUrl;
        ChallengeType = record.ChallengeType;
        RenewBeforeDays = record.RenewBeforeDays;
        CheckIntervalMinutes = record.CheckIntervalMinutes;
        UseStaging = record.UseStaging;
        PfxPassword = record.PfxPassword;
        DnsProvider = record.DnsProvider;
        DnsZone = record.DnsZone;
        DnsApiToken = record.DnsApiToken;
        DnsAccessKeyId = record.DnsAccessKeyId;
        DnsAccessKeySecret = record.DnsAccessKeySecret;
        DnsHookPresentCommand = record.DnsHookPresentCommand;
        DnsHookPresentArguments = record.DnsHookPresentArguments;
        DnsHookCleanupCommand = record.DnsHookCleanupCommand;
        DnsHookCleanupArguments = record.DnsHookCleanupArguments;
        EnvironmentVariables = record.EnvironmentVariables;
        AssetVersion = record.AssetVersion;
        PfxBase64 = record.PfxBase64;
        Thumbprint = record.Thumbprint;
        NotBefore = record.NotBefore;
        NotAfter = record.NotAfter;
        LastAttemptAt = record.LastAttemptAt;
        LastSuccessAt = record.LastSuccessAt;
        LastError = record.LastError;
        UpdatedAt = record.UpdatedAt;
    }
}

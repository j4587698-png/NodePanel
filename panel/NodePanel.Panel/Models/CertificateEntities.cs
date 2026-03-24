using System.Security.Cryptography.X509Certificates;
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

    [Column(Name = "NotBefore")]
    public DateTimeOffset? LegacyNotBefore { get; set; }

    public long? NotBeforeUnixMilliseconds { get; set; }

    [Column(Name = "NotAfter")]
    public DateTimeOffset? LegacyNotAfter { get; set; }

    public long? NotAfterUnixMilliseconds { get; set; }

    [Column(Name = "LastAttemptAt")]
    public DateTimeOffset? LegacyLastAttemptAt { get; set; }

    public long? LastAttemptAtUnixMilliseconds { get; set; }

    [Column(Name = "LastSuccessAt")]
    public DateTimeOffset? LegacyLastSuccessAt { get; set; }

    public long? LastSuccessAtUnixMilliseconds { get; set; }

    [Column(StringLength = -1)]
    public string LastError { get; set; } = string.Empty;

    [Column(Name = "CreatedAt")]
    public DateTimeOffset LegacyCreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public long? CreatedAtUnixMilliseconds { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    [Column(Name = "UpdatedAt")]
    public DateTimeOffset LegacyUpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public long? UpdatedAtUnixMilliseconds { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

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

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset? NotBefore
    {
        get => ReadNullableDateTimeOffset(NotBeforeUnixMilliseconds, LegacyNotBefore);
        set
        {
            LegacyNotBefore = value;
            NotBeforeUnixMilliseconds = value?.ToUnixTimeMilliseconds();
        }
    }

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset? NotAfter
    {
        get => ReadNullableDateTimeOffset(NotAfterUnixMilliseconds, LegacyNotAfter);
        set
        {
            LegacyNotAfter = value;
            NotAfterUnixMilliseconds = value?.ToUnixTimeMilliseconds();
        }
    }

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset? LastAttemptAt
    {
        get => ReadNullableDateTimeOffset(LastAttemptAtUnixMilliseconds, LegacyLastAttemptAt);
        set
        {
            LegacyLastAttemptAt = value;
            LastAttemptAtUnixMilliseconds = value?.ToUnixTimeMilliseconds();
        }
    }

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset? LastSuccessAt
    {
        get => ReadNullableDateTimeOffset(LastSuccessAtUnixMilliseconds, LegacyLastSuccessAt);
        set
        {
            LegacyLastSuccessAt = value;
            LastSuccessAtUnixMilliseconds = value?.ToUnixTimeMilliseconds();
        }
    }

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset CreatedAt
    {
        get => ReadRequiredDateTimeOffset(CreatedAtUnixMilliseconds, LegacyCreatedAt);
        set
        {
            LegacyCreatedAt = value;
            CreatedAtUnixMilliseconds = value.ToUnixTimeMilliseconds();
        }
    }

    [System.ComponentModel.DataAnnotations.Schema.NotMapped]
    public DateTimeOffset UpdatedAt
    {
        get => ReadRequiredDateTimeOffset(UpdatedAtUnixMilliseconds, LegacyUpdatedAt);
        set
        {
            LegacyUpdatedAt = value;
            UpdatedAtUnixMilliseconds = value.ToUnixTimeMilliseconds();
        }
    }

    public PanelCertificateRecord ToRecord()
    {
        var thumbprint = Thumbprint;
        var notBefore = NotBefore;
        var notAfter = NotAfter;

        if (TryReadCertificateMetadataFromPfx(PfxBase64, PfxPassword, out var assetMetadata))
        {
            thumbprint = string.IsNullOrWhiteSpace(thumbprint) ? assetMetadata.Thumbprint : thumbprint;
            notBefore ??= assetMetadata.NotBefore;
            notAfter ??= assetMetadata.NotAfter;
        }

        return new PanelCertificateRecord
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
            Thumbprint = thumbprint,
            NotBefore = notBefore,
            NotAfter = notAfter,
            LastAttemptAt = LastAttemptAt,
            LastSuccessAt = LastSuccessAt,
            LastError = LastError,
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt
        };
    }

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

    private static DateTimeOffset? ReadNullableDateTimeOffset(long? unixMilliseconds, DateTimeOffset? legacyValue)
        => unixMilliseconds is long value
            ? DateTimeOffset.FromUnixTimeMilliseconds(value)
            : legacyValue;

    private static DateTimeOffset ReadRequiredDateTimeOffset(long? unixMilliseconds, DateTimeOffset legacyValue)
        => unixMilliseconds is long value
            ? DateTimeOffset.FromUnixTimeMilliseconds(value)
            : legacyValue;

    private static bool TryReadCertificateMetadataFromPfx(string pfxBase64, string pfxPassword, out PersistedCertificateMetadata metadata)
    {
        metadata = default;
        if (string.IsNullOrWhiteSpace(pfxBase64))
        {
            return false;
        }

        try
        {
            var rawBytes = Convert.FromBase64String(pfxBase64);
            using var certificate = X509CertificateLoader.LoadPkcs12(
                rawBytes,
                pfxPassword,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

            metadata = new PersistedCertificateMetadata(
                certificate.Thumbprint ?? string.Empty,
                new DateTimeOffset(certificate.NotBefore),
                new DateTimeOffset(certificate.NotAfter));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private readonly record struct PersistedCertificateMetadata(
        string Thumbprint,
        DateTimeOffset NotBefore,
        DateTimeOffset NotAfter);
}

using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public sealed record NodeServiceConfig
{
    public IReadOnlyList<InboundConfig> Inbounds { get; init; } = Array.Empty<InboundConfig>();

    public IReadOnlyList<OutboundConfig> Outbounds { get; init; } = Array.Empty<OutboundConfig>();

    public IReadOnlyList<RoutingRuleConfig> RoutingRules { get; init; } = Array.Empty<RoutingRuleConfig>();

    public CertificateOptions Certificate { get; init; } = new();

    public TrojanInboundLimits Limits { get; init; } = new();

    public DnsOptions Dns { get; init; } = new();

    public TelemetryOptions Telemetry { get; init; } = new();

    public IReadOnlyList<TrojanUserConfig> Users { get; init; } = Array.Empty<TrojanUserConfig>();

    public IReadOnlyList<TrojanFallbackConfig> Fallbacks { get; init; } = Array.Empty<TrojanFallbackConfig>();
}

public sealed record CertificateOptions
{
    public string Mode { get; init; } = CertificateModes.ManualPfx;

    public string PfxPath { get; init; } = string.Empty;

    public string PfxPassword { get; init; } = string.Empty;

    public string PanelCertificateId { get; init; } = string.Empty;

    public DistributedCertificateAsset DistributedAsset { get; init; } = new();

    public string Domain { get; init; } = string.Empty;

    public IReadOnlyList<string> AltNames { get; init; } = Array.Empty<string>();

    public string Email { get; init; } = string.Empty;

    public string AcmeDirectoryUrl { get; init; } = string.Empty;

    public string ChallengeType { get; init; } = CertificateChallengeTypes.Http01;

    public int RenewBeforeDays { get; init; } = 30;

    public int CheckIntervalMinutes { get; init; } = 60;

    public string HttpChallengeListenAddress { get; init; } = "0.0.0.0";

    public int HttpChallengePort { get; init; } = 80;

    public int ExternalTimeoutSeconds { get; init; } = 300;

    public bool UseStaging { get; init; }

    public bool RejectUnknownSni { get; init; }

    public TlsClientHelloPolicyConfig ClientHelloPolicy { get; init; } = new();

    public string ExternalToolPath { get; init; } = string.Empty;

    public string ExternalArguments { get; init; } = string.Empty;

    public string WorkingDirectory { get; init; } = string.Empty;

    public IReadOnlyList<CertificateEnvironmentVariable> EnvironmentVariables { get; init; } = Array.Empty<CertificateEnvironmentVariable>();
}

public sealed record DistributedCertificateAsset
{
    public int Version { get; init; }

    public string PfxBase64 { get; init; } = string.Empty;

    public string Thumbprint { get; init; } = string.Empty;

    public DateTimeOffset? NotBefore { get; init; }

    public DateTimeOffset? NotAfter { get; init; }
}

public sealed record TlsClientHelloPolicyConfig : ITrojanClientHelloPolicyDefinition
{
    public bool Enabled { get; init; }

    public IReadOnlyList<string> AllowedServerNames { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> BlockedServerNames { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> AllowedApplicationProtocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> BlockedApplicationProtocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> AllowedJa3 { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> BlockedJa3 { get; init; } = Array.Empty<string>();
}

public sealed record TelemetryOptions
{
    public int FlushIntervalSeconds { get; init; } = 15;
}

public sealed record DnsOptions
{
    public string Mode { get; init; } = DnsModes.System;

    public int TimeoutSeconds { get; init; } = 5;

    public int CacheTtlSeconds { get; init; } = 30;

    public IReadOnlyList<DnsHttpServerConfig> Servers { get; init; } = Array.Empty<DnsHttpServerConfig>();
}

public sealed record DnsHttpServerConfig
{
    public string Url { get; init; } = string.Empty;

    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

public sealed record CertificateEnvironmentVariable
{
    public string Name { get; init; } = string.Empty;

    public string Value { get; init; } = string.Empty;
}

public static class CertificateModes
{
    public const string Disabled = "disabled";
    public const string ManualPfx = "manual-pfx";
    public const string AcmeManaged = "acme-managed";
    public const string AcmeExternal = "acme-external";
    public const string PanelDistributed = "panel-distributed";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return ManualPfx;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            Disabled => Disabled,
            ManualPfx => ManualPfx,
            AcmeManaged => AcmeManaged,
            AcmeExternal => AcmeExternal,
            PanelDistributed => PanelDistributed,
            _ => ManualPfx
        };
    }
}

public static class CertificateChallengeTypes
{
    public const string Http01 = "http-01";
    public const string Dns01 = "dns-01";
    public const string TlsAlpn01 = "tls-alpn-01";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Http01;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            Http01 => Http01,
            Dns01 => Dns01,
            TlsAlpn01 => TlsAlpn01,
            _ => Http01
        };
    }
}

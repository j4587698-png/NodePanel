using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Panel.Models;

public sealed class DashboardPageViewModel
{
    public required PanelStateView State { get; init; }

    public string StatusMessage { get; init; } = string.Empty;
}

public sealed class NodeEditorViewModel
{
    public required NodeFormInput Form { get; init; }

    public required bool IsEditMode { get; init; }

    public NodeRuntimeSnapshot Runtime { get; init; } = new();

    public string StatusMessage { get; init; } = string.Empty;

    public IReadOnlyList<ServerGroupViewModel> AvailableGroups { get; init; } = Array.Empty<ServerGroupViewModel>();

    public IReadOnlyList<PanelCertificateRecord> AvailableCertificates { get; init; } = Array.Empty<PanelCertificateRecord>();
}

public sealed class UserEditorViewModel
{
    public required UserFormInput Form { get; init; }

    public required bool IsEditMode { get; init; }

    public string PortalUrl { get; init; } = string.Empty;

    public string SubscriptionUrl { get; init; } = string.Empty;

    public string StatusMessage { get; init; } = string.Empty;

    public IReadOnlyList<PanelPlanRecord> Plans { get; init; } = Array.Empty<PanelPlanRecord>();

    public IReadOnlyList<ServerGroupViewModel> AvailableGroups { get; init; } = Array.Empty<ServerGroupViewModel>();
}

public sealed class NodeFormInput
{
    [Required]
    public string NodeId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Protocol { get; set; } = "trojan";

    public string GroupIds { get; set; } = string.Empty;

    [Range(0.01, 100)]
    public decimal TrafficMultiplier { get; set; } = 1.0m;

    public bool Enabled { get; set; } = true;

    public string SubscriptionHost { get; set; } = string.Empty;

    public string SubscriptionSni { get; set; } = string.Empty;

    public bool SubscriptionAllowInsecure { get; set; }

    public List<TrojanInboundFormInput> Inbounds { get; set; } =
    [
        TrojanInboundFormInput.CreateDefault(InboundProtocols.Trojan, InboundTransports.Tls),
        TrojanInboundFormInput.CreateDefault(InboundProtocols.Trojan, InboundTransports.Wss)
    ];

    public string CertificateMode { get; set; } = CertificateModes.ManualPfx;

    public string CertificatePfxPath { get; set; } = string.Empty;

    public string CertificatePfxPassword { get; set; } = string.Empty;

    public string PanelCertificateId { get; set; } = string.Empty;

    public string CertificateDomain { get; set; } = string.Empty;

    public string CertificateAltNames { get; set; } = string.Empty;

    public string CertificateEmail { get; set; } = string.Empty;

    public string CertificateAcmeDirectoryUrl { get; set; } = string.Empty;

    public string CertificateChallengeType { get; set; } = CertificateChallengeTypes.Http01;

    [Range(1, 365)]
    public int CertificateRenewBeforeDays { get; set; } = 30;

    [Range(1, 1440)]
    public int CertificateCheckIntervalMinutes { get; set; } = 60;

    public string CertificateHttpChallengeListenAddress { get; set; } = "0.0.0.0";

    [Range(1, 65535)]
    public int CertificateHttpChallengePort { get; set; } = 80;

    [Range(1, 3600)]
    public int CertificateExternalTimeoutSeconds { get; set; } = 300;

    public bool CertificateUseStaging { get; set; }

    public string CertificateExternalToolPath { get; set; } = string.Empty;

    public string CertificateExternalArguments { get; set; } = string.Empty;

    public string CertificateWorkingDirectory { get; set; } = string.Empty;

    public string CertificateEnvironmentVariables { get; set; } = string.Empty;

    [Range(0, long.MaxValue)]
    public long GlobalBytesPerSecond { get; set; }

    [Range(1, 600)]
    public int ConnectTimeoutSeconds { get; set; } = 10;

    [Range(1, 3600)]
    public int TelemetryFlushIntervalSeconds { get; set; } = 15;

    public bool CertificateRejectUnknownSni { get; set; }

    public ClientHelloPolicyFormInput CertificateClientHelloPolicy { get; set; } = new();

    [Range(1, 86400)]
    public int ConnectionIdleSeconds { get; set; } = 300;

    [Range(1, 3600)]
    public int UplinkOnlySeconds { get; set; } = 1;

    [Range(1, 3600)]
    public int DownlinkOnlySeconds { get; set; } = 1;

    public DnsFormInput Dns { get; set; } = new();

    public List<OutboundFormInput> Outbounds { get; set; } = [];

    public List<RoutingRuleFormInput> RoutingRules { get; set; } = [];

    public string AdvancedConfigJson { get; set; } = string.Empty;

    public void PrepareForEditView()
    {
        EnsureCollections();
        GetOrderedTrojanInbounds();

        foreach (var inbound in Inbounds)
        {
            inbound.EnsureCollections();
            if (inbound.Fallbacks.Count == 0)
            {
                inbound.Fallbacks.Add(new TrojanFallbackFormInput());
            }
        }

        if (Dns.Servers.Count == 0)
        {
            Dns.Servers.Add(new DnsServerFormInput());
        }

        if (Outbounds.Count == 0)
        {
            Outbounds.Add(new OutboundFormInput());
        }

        if (RoutingRules.Count == 0)
        {
            RoutingRules.Add(new RoutingRuleFormInput());
        }
    }

    public bool TryToRequest(out UpsertNodeRequest request, out string error)
    {
        EnsureCollections();

        if (!NodeFormValueCodec.TryParseEnvironmentVariables(CertificateEnvironmentVariables, out var environmentVariables, out error))
        {
            request = new UpsertNodeRequest();
            return false;
        }

        if (!TryBuildDns(out var dns, out error))
        {
            request = new UpsertNodeRequest();
            return false;
        }

        if (!TryBuildOutbounds(out var outbounds, out error))
        {
            request = new UpsertNodeRequest();
            return false;
        }

        if (!NodeAdvancedConfigInput.TryParse(AdvancedConfigJson, out var advancedConfig, out error))
        {
            request = new UpsertNodeRequest();
            return false;
        }

        var normalizedCertificateMode = CertificateModes.Normalize(CertificateMode);
        if (normalizedCertificateMode == CertificateModes.PanelDistributed &&
            string.IsNullOrWhiteSpace(PanelCertificateId))
        {
            request = new UpsertNodeRequest();
            error = "面板下发证书模式必须选择一张面板证书。";
            return false;
        }

        var config = MergeAdvancedConfig(
            new NodeServiceConfig
            {
                Inbounds = BuildInbounds(),
                Outbounds = outbounds,
                RoutingRules = BuildRoutingRules(),
                Certificate = new CertificateOptions
                {
                    Mode = normalizedCertificateMode,
                    PfxPath = NodeFormValueCodec.TrimOrEmpty(CertificatePfxPath),
                    PfxPassword = NodeFormValueCodec.TrimOrEmpty(CertificatePfxPassword),
                    PanelCertificateId = normalizedCertificateMode == CertificateModes.PanelDistributed
                        ? NodeFormValueCodec.TrimOrEmpty(PanelCertificateId)
                        : string.Empty,
                    Domain = NodeFormValueCodec.TrimOrEmpty(CertificateDomain),
                    AltNames = NodeFormValueCodec.ParseCsv(CertificateAltNames),
                    Email = NodeFormValueCodec.TrimOrEmpty(CertificateEmail),
                    AcmeDirectoryUrl = NodeFormValueCodec.TrimOrEmpty(CertificateAcmeDirectoryUrl),
                    ChallengeType = CertificateChallengeType,
                    RenewBeforeDays = CertificateRenewBeforeDays,
                    CheckIntervalMinutes = CertificateCheckIntervalMinutes,
                    HttpChallengeListenAddress = NodeFormValueCodec.TrimOrEmpty(CertificateHttpChallengeListenAddress),
                    HttpChallengePort = CertificateHttpChallengePort,
                    ExternalTimeoutSeconds = CertificateExternalTimeoutSeconds,
                    RejectUnknownSni = CertificateRejectUnknownSni,
                    ClientHelloPolicy = CertificateClientHelloPolicy.ToConfig(),
                    UseStaging = CertificateUseStaging,
                    ExternalToolPath = NodeFormValueCodec.TrimOrEmpty(CertificateExternalToolPath),
                    ExternalArguments = NodeFormValueCodec.TrimOrEmpty(CertificateExternalArguments),
                    WorkingDirectory = NodeFormValueCodec.TrimOrEmpty(CertificateWorkingDirectory),
                    EnvironmentVariables = environmentVariables
                },
                Limits = new TrojanInboundLimits
                {
                    GlobalBytesPerSecond = GlobalBytesPerSecond,
                    ConnectTimeoutSeconds = ConnectTimeoutSeconds,
                    ConnectionIdleSeconds = ConnectionIdleSeconds,
                    UplinkOnlySeconds = UplinkOnlySeconds,
                    DownlinkOnlySeconds = DownlinkOnlySeconds
                },
                Dns = dns,
                Telemetry = new TelemetryOptions
                {
                    FlushIntervalSeconds = TelemetryFlushIntervalSeconds
                }
            },
            advancedConfig);

        request = new UpsertNodeRequest
        {
            DisplayName = NodeFormValueCodec.TrimOrEmpty(DisplayName),
            Protocol = Protocol,
            GroupIds = ParseGroupIds(GroupIds),
            TrafficMultiplier = TrafficMultiplier,
            Enabled = Enabled,
            SubscriptionHost = NodeFormValueCodec.TrimOrEmpty(SubscriptionHost),
            SubscriptionSni = NodeFormValueCodec.TrimOrEmpty(SubscriptionSni),
            SubscriptionAllowInsecure = SubscriptionAllowInsecure,
            Config = config
        };

        error = string.Empty;
        return true;
    }

    public UpsertNodeRequest ToRequest()
    {
        if (TryToRequest(out var request, out var error))
        {
            return request;
        }

        throw new InvalidOperationException(error);
    }

    public static NodeFormInput FromRecord(PanelNodeRecord record)
    {
        var normalizedProtocol = InboundProtocols.Normalize(record.Protocol);
        var tcpTls = NodeServiceConfigInbounds.GetProtocolTransportInbound(record.Config, normalizedProtocol, InboundTransports.Tls);
        var wss = NodeServiceConfigInbounds.GetProtocolTransportInbound(record.Config, normalizedProtocol, InboundTransports.Wss);

        return new NodeFormInput
        {
            NodeId = record.NodeId,
            DisplayName = record.DisplayName,
            Protocol = record.Protocol,
            GroupIds = string.Join(", ", record.GroupIds),
            TrafficMultiplier = record.TrafficMultiplier,
            Enabled = record.Enabled,
            SubscriptionHost = record.SubscriptionHost,
            SubscriptionSni = record.SubscriptionSni,
            SubscriptionAllowInsecure = record.SubscriptionAllowInsecure,
            Inbounds =
            [
                TrojanInboundFormInput.FromInbound(tcpTls),
                TrojanInboundFormInput.FromInbound(wss)
            ],
            CertificateMode = CertificateModes.Normalize(record.Config.Certificate.Mode),
            CertificatePfxPath = record.Config.Certificate.PfxPath,
            CertificatePfxPassword = record.Config.Certificate.PfxPassword,
            PanelCertificateId = record.Config.Certificate.PanelCertificateId,
            CertificateDomain = record.Config.Certificate.Domain,
            CertificateAltNames = string.Join(", ", record.Config.Certificate.AltNames),
            CertificateEmail = record.Config.Certificate.Email,
            CertificateAcmeDirectoryUrl = record.Config.Certificate.AcmeDirectoryUrl,
            CertificateChallengeType = CertificateChallengeTypes.Normalize(record.Config.Certificate.ChallengeType),
            CertificateRenewBeforeDays = Math.Max(1, record.Config.Certificate.RenewBeforeDays),
            CertificateCheckIntervalMinutes = Math.Max(1, record.Config.Certificate.CheckIntervalMinutes),
            CertificateHttpChallengeListenAddress = record.Config.Certificate.HttpChallengeListenAddress,
            CertificateHttpChallengePort = record.Config.Certificate.HttpChallengePort is > 0 and <= 65535 ? record.Config.Certificate.HttpChallengePort : 80,
            CertificateExternalTimeoutSeconds = Math.Max(1, record.Config.Certificate.ExternalTimeoutSeconds),
            CertificateUseStaging = false,
            CertificateExternalToolPath = record.Config.Certificate.ExternalToolPath,
            CertificateExternalArguments = record.Config.Certificate.ExternalArguments,
            CertificateWorkingDirectory = record.Config.Certificate.WorkingDirectory,
            CertificateEnvironmentVariables = NodeFormValueCodec.FormatEnvironmentVariables(record.Config.Certificate.EnvironmentVariables),
            CertificateRejectUnknownSni = record.Config.Certificate.RejectUnknownSni,
            CertificateClientHelloPolicy = ClientHelloPolicyFormInput.FromConfig(record.Config.Certificate.ClientHelloPolicy),
            GlobalBytesPerSecond = record.Config.Limits.GlobalBytesPerSecond,
            ConnectTimeoutSeconds = Math.Max(1, record.Config.Limits.ConnectTimeoutSeconds),
            ConnectionIdleSeconds = Math.Max(1, record.Config.Limits.ConnectionIdleSeconds),
            UplinkOnlySeconds = Math.Max(1, record.Config.Limits.UplinkOnlySeconds),
            DownlinkOnlySeconds = Math.Max(1, record.Config.Limits.DownlinkOnlySeconds),
            TelemetryFlushIntervalSeconds = Math.Max(1, record.Config.Telemetry.FlushIntervalSeconds),
            Dns = DnsFormInput.FromConfig(record.Config.Dns),
            Outbounds = record.Config.Outbounds.Select(OutboundFormInput.FromConfig).ToList(),
            RoutingRules = record.Config.RoutingRules.Select(RoutingRuleFormInput.FromConfig).ToList(),
            AdvancedConfigJson = string.Empty
        };
    }

    public IReadOnlyList<TrojanInboundFormInput> GetOrderedTrojanInbounds()
    {
        EnsureCollections();
        var tls = GetOrCreateInbound(InboundTransports.Tls);
        var wss = GetOrCreateInbound(InboundTransports.Wss);
        Inbounds =
        [
            tls,
            wss
        ];
        return Inbounds;
    }

    private void EnsureCollections()
    {
        CertificateClientHelloPolicy ??= new ClientHelloPolicyFormInput();
        Dns ??= new DnsFormInput();
        Dns.Servers ??= [];
        Outbounds ??= [];
        RoutingRules ??= [];
        Inbounds ??= [];

        foreach (var inbound in Inbounds)
        {
            inbound.EnsureCollections();
        }
    }

    private TrojanInboundFormInput GetOrCreateInbound(string transport)
    {
        Inbounds ??= [];
        var normalizedTransport = InboundTransports.Normalize(transport);
        var existing = Inbounds.FirstOrDefault(item =>
            string.Equals(InboundTransports.Normalize(item.Transport), normalizedTransport, StringComparison.Ordinal));
        if (existing is not null)
        {
            existing.EnsureCollections();
            existing.Protocol = NormalizeInboundProtocol(Protocol);
            existing.Transport = normalizedTransport;
            existing.Tag = string.IsNullOrWhiteSpace(existing.Tag)
                ? TrojanInboundFormInput.GetDefaultTag(existing.Protocol, normalizedTransport)
                : existing.Tag.Trim();
            return existing;
        }

        var created = TrojanInboundFormInput.CreateDefault(NormalizeInboundProtocol(Protocol), normalizedTransport);
        Inbounds.Add(created);
        return created;
    }

    private bool TryBuildDns(out DnsOptions dns, out string error)
    {
        var servers = new List<DnsHttpServerConfig>(Dns.Servers.Count);
        for (var index = 0; index < Dns.Servers.Count; index++)
        {
            var server = Dns.Servers[index];
            if (server.IsEmpty())
            {
                continue;
            }

            if (!server.TryToConfig(out var config, out error))
            {
                dns = new DnsOptions();
                error = $"DNS 服务器 #{index + 1}: {error}";
                return false;
            }

            servers.Add(config);
        }

        dns = new DnsOptions
        {
            Mode = Dns.Mode,
            TimeoutSeconds = Dns.TimeoutSeconds,
            CacheTtlSeconds = Dns.CacheTtlSeconds,
            Servers = servers
        };
        error = string.Empty;
        return true;
    }

    private bool TryBuildOutbounds(out IReadOnlyList<OutboundConfig> outbounds, out string error)
    {
        var configs = new List<OutboundConfig>(Outbounds.Count);
        for (var index = 0; index < Outbounds.Count; index++)
        {
            var outbound = Outbounds[index];
            if (outbound.IsEmpty())
            {
                continue;
            }

            if (!outbound.TryToConfig(out var config, out error))
            {
                outbounds = Array.Empty<OutboundConfig>();
                error = $"出站 #{index + 1}: {error}";
                return false;
            }

            configs.Add(config);
        }

        outbounds = configs;
        error = string.Empty;
        return true;
    }

    private IReadOnlyList<RoutingRuleConfig> BuildRoutingRules()
        => RoutingRules
            .Where(static rule => !rule.IsEmpty())
            .Select(static rule => rule.ToConfig())
            .ToArray();

    private static IReadOnlyList<int> ParseGroupIds(string? value)
        => NodeFormValueCodec.ParseCsv(value)
            .Select(static item => int.TryParse(item, out var groupId) ? groupId : 0)
            .Where(static groupId => groupId > 0)
            .Distinct()
            .ToArray();

    private IReadOnlyList<InboundConfig> BuildInbounds()
    {
        var tlsInbound = GetOrCreateInbound(InboundTransports.Tls);
        var wssInbound = GetOrCreateInbound(InboundTransports.Wss);
        return
        [
            tlsInbound.ToInboundConfig(),
            wssInbound.ToInboundConfig()
        ];
    }

    private static NodeServiceConfig MergeAdvancedConfig(
        NodeServiceConfig config,
        NodeAdvancedConfigInput advancedConfig)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(advancedConfig);

        var certificate = config.Certificate;
        if (advancedConfig.Certificate is not null)
        {
            certificate = certificate with
            {
                RejectUnknownSni = certificate.RejectUnknownSni || advancedConfig.Certificate.RejectUnknownSni,
                ClientHelloPolicy = HasConfiguredClientHelloPolicy(certificate.ClientHelloPolicy) ||
                                    advancedConfig.Certificate.ClientHelloPolicy is null
                    ? certificate.ClientHelloPolicy
                    : advancedConfig.Certificate.ClientHelloPolicy
            };
        }

        var limits = config.Limits;
        if (advancedConfig.Limits is not null)
        {
            limits = limits with
            {
                ConnectionIdleSeconds = limits.ConnectionIdleSeconds != 300
                    ? limits.ConnectionIdleSeconds
                    : Math.Max(1, advancedConfig.Limits.ConnectionIdleSeconds),
                UplinkOnlySeconds = limits.UplinkOnlySeconds != 1
                    ? limits.UplinkOnlySeconds
                    : Math.Max(1, advancedConfig.Limits.UplinkOnlySeconds),
                DownlinkOnlySeconds = limits.DownlinkOnlySeconds != 1
                    ? limits.DownlinkOnlySeconds
                    : Math.Max(1, advancedConfig.Limits.DownlinkOnlySeconds)
            };
        }

        return config with
        {
            Inbounds = MergeAdvancedInbounds(config.Inbounds, advancedConfig.Inbounds),
            Certificate = certificate,
            Limits = limits,
            Dns = HasConfiguredDns(config.Dns) || advancedConfig.Dns is null
                ? config.Dns
                : advancedConfig.Dns,
            Outbounds = config.Outbounds.Count > 0
                ? config.Outbounds
                : advancedConfig.Outbounds ?? Array.Empty<OutboundConfig>(),
            RoutingRules = config.RoutingRules.Count > 0
                ? config.RoutingRules
                : advancedConfig.RoutingRules ?? Array.Empty<RoutingRuleConfig>()
        };
    }

    private static IReadOnlyList<InboundConfig> MergeAdvancedInbounds(
        IReadOnlyList<InboundConfig> inbounds,
        IReadOnlyList<AdvancedInboundConfigInput>? advancedInbounds)
    {
        if (advancedInbounds is null || advancedInbounds.Count == 0)
        {
            return inbounds;
        }

        var advancedLookup = advancedInbounds.ToDictionary(
            static inbound => InboundTransports.Normalize(inbound.Transport),
            StringComparer.Ordinal);

        return inbounds
            .Select(inbound =>
            {
                var transport = InboundTransports.Normalize(inbound.Transport);
                if (!advancedLookup.TryGetValue(transport, out var advancedInbound))
                {
                    return inbound;
                }

                return inbound with
                {
                    ApplicationProtocols = inbound.ApplicationProtocols.Count > 0
                        ? inbound.ApplicationProtocols
                        : advancedInbound.ApplicationProtocols ?? Array.Empty<string>(),
                    Sniffing = HasConfiguredSniffing(inbound.Sniffing) || advancedInbound.Sniffing is null
                        ? inbound.Sniffing
                        : advancedInbound.Sniffing,
                    Fallbacks = inbound.Fallbacks.Count > 0
                        ? inbound.Fallbacks
                        : advancedInbound.Fallbacks ?? Array.Empty<TrojanFallbackConfig>()
                };
            })
            .ToArray();
    }

    private static bool HasConfiguredClientHelloPolicy(TlsClientHelloPolicyConfig policy)
        => policy.Enabled ||
           policy.AllowedServerNames.Count > 0 ||
           policy.BlockedServerNames.Count > 0 ||
           policy.AllowedApplicationProtocols.Count > 0 ||
           policy.BlockedApplicationProtocols.Count > 0 ||
           policy.AllowedJa3.Count > 0 ||
           policy.BlockedJa3.Count > 0;

    private static bool HasConfiguredDns(DnsOptions dns)
    {
        var defaults = new DnsOptions();
        return !string.Equals(DnsModes.Normalize(dns.Mode), DnsModes.Normalize(defaults.Mode), StringComparison.Ordinal) ||
               dns.TimeoutSeconds != defaults.TimeoutSeconds ||
               dns.CacheTtlSeconds != defaults.CacheTtlSeconds ||
               dns.Servers.Count > 0;
    }

    private static bool HasConfiguredSniffing(InboundSniffingConfig sniffing)
        => sniffing.Enabled ||
           sniffing.DestinationOverride.Count > 0 ||
           sniffing.DomainsExcluded.Count > 0 ||
           sniffing.MetadataOnly ||
           sniffing.RouteOnly;

    private static string NormalizeInboundProtocol(string? value)
        => InboundProtocols.Normalize(value);
}

public sealed record NodeAdvancedConfigInput
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public AdvancedCertificateConfigInput? Certificate { get; init; }

    public AdvancedLimitConfigInput? Limits { get; init; }

    public DnsOptions? Dns { get; init; }

    public IReadOnlyList<AdvancedInboundConfigInput>? Inbounds { get; init; }

    public IReadOnlyList<OutboundConfig>? Outbounds { get; init; }

    public IReadOnlyList<RoutingRuleConfig>? RoutingRules { get; init; }

    public static bool TryParse(string json, out NodeAdvancedConfigInput input, out string error)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            input = new NodeAdvancedConfigInput();
            error = string.Empty;
            return true;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<NodeAdvancedConfigInput>(json, JsonOptions) ?? new NodeAdvancedConfigInput();
            if (!TryNormalizeInbounds(parsed.Inbounds, out var normalizedInbounds, out error))
            {
                input = new NodeAdvancedConfigInput();
                return false;
            }

            input = parsed with
            {
                Inbounds = normalizedInbounds
            };
            error = string.Empty;
            return true;
        }
        catch (JsonException ex)
        {
            input = new NodeAdvancedConfigInput();
            error = $"高级配置 JSON 无法解析: {ex.Message}";
            return false;
        }
    }

    public static string Serialize(NodeAdvancedConfigInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        return input.IsEmpty()
            ? string.Empty
            : JsonSerializer.Serialize(input, JsonOptions);
    }

    public static NodeAdvancedConfigInput FromConfig(string protocol, NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var normalizedProtocol = InboundProtocols.Normalize(protocol);
        var advancedInbounds = config.Inbounds
            .Where(inbound => string.Equals(InboundProtocols.Normalize(inbound.Protocol), normalizedProtocol, StringComparison.Ordinal))
            .Select(CreateAdvancedInbound)
            .Where(static inbound => inbound is not null)
            .Cast<AdvancedInboundConfigInput>()
            .OrderBy(static inbound => inbound.Transport, StringComparer.Ordinal)
            .ToArray();

        return new NodeAdvancedConfigInput
        {
            Certificate = HasAdvancedCertificate(config.Certificate)
                ? new AdvancedCertificateConfigInput
                {
                    RejectUnknownSni = config.Certificate.RejectUnknownSni,
                    ClientHelloPolicy = HasClientHelloPolicy(config.Certificate.ClientHelloPolicy)
                        ? config.Certificate.ClientHelloPolicy
                        : null
                }
                : null,
            Limits = HasAdvancedLimits(config.Limits)
                ? new AdvancedLimitConfigInput
                {
                    ConnectionIdleSeconds = config.Limits.ConnectionIdleSeconds,
                    UplinkOnlySeconds = config.Limits.UplinkOnlySeconds,
                    DownlinkOnlySeconds = config.Limits.DownlinkOnlySeconds
                }
                : null,
            Dns = HasAdvancedDns(config.Dns) ? config.Dns : null,
            Inbounds = advancedInbounds.Length > 0 ? advancedInbounds : null,
            Outbounds = config.Outbounds.Count > 0 ? config.Outbounds : null,
            RoutingRules = config.RoutingRules.Count > 0 ? config.RoutingRules : null
        };
    }

    private bool IsEmpty()
        => Certificate is null &&
           Limits is null &&
           Dns is null &&
           (Inbounds is null || Inbounds.Count == 0) &&
           (Outbounds is null || Outbounds.Count == 0) &&
           (RoutingRules is null || RoutingRules.Count == 0);

    private static AdvancedInboundConfigInput? CreateAdvancedInbound(InboundConfig inbound)
    {
        var applicationProtocols = inbound.ApplicationProtocols.Count > 0 ? inbound.ApplicationProtocols : null;
        var sniffing = HasAdvancedSniffing(inbound.Sniffing) ? inbound.Sniffing : null;
        var fallbacks = inbound.Fallbacks.Count > 0 ? inbound.Fallbacks : null;
        if (applicationProtocols is null && sniffing is null && fallbacks is null)
        {
            return null;
        }

        return new AdvancedInboundConfigInput
        {
            Transport = InboundTransports.Normalize(inbound.Transport),
            ApplicationProtocols = applicationProtocols,
            Sniffing = sniffing,
            Fallbacks = fallbacks
        };
    }

    private static bool TryNormalizeInbounds(
        IReadOnlyList<AdvancedInboundConfigInput>? inbounds,
        out IReadOnlyList<AdvancedInboundConfigInput>? normalizedInbounds,
        out string error)
    {
        if (inbounds is null || inbounds.Count == 0)
        {
            normalizedInbounds = null;
            error = string.Empty;
            return true;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var normalized = new List<AdvancedInboundConfigInput>(inbounds.Count);
        foreach (var inbound in inbounds)
        {
            var transport = InboundTransports.Normalize(inbound.Transport);
            if (transport is not (InboundTransports.Tls or InboundTransports.Wss))
            {
                normalizedInbounds = null;
                error = $"高级配置中的 inbounds.transport 仅支持 '{InboundTransports.Tls}' 或 '{InboundTransports.Wss}'。";
                return false;
            }

            if (!seen.Add(transport))
            {
                normalizedInbounds = null;
                error = $"高级配置中的 inbounds.transport '{transport}' 重复。";
                return false;
            }

            normalized.Add(inbound with { Transport = transport });
        }

        normalizedInbounds = normalized;
        error = string.Empty;
        return true;
    }

    private static bool HasAdvancedCertificate(CertificateOptions options)
        => options.RejectUnknownSni || HasClientHelloPolicy(options.ClientHelloPolicy);

    private static bool HasClientHelloPolicy(TlsClientHelloPolicyConfig options)
        => options.Enabled ||
           options.AllowedServerNames.Count > 0 ||
           options.BlockedServerNames.Count > 0 ||
           options.AllowedApplicationProtocols.Count > 0 ||
           options.BlockedApplicationProtocols.Count > 0 ||
           options.AllowedJa3.Count > 0 ||
           options.BlockedJa3.Count > 0;

    private static bool HasAdvancedLimits(TrojanInboundLimits options)
        => options.ConnectionIdleSeconds != 300 ||
           options.UplinkOnlySeconds != 1 ||
           options.DownlinkOnlySeconds != 1;

    private static bool HasAdvancedDns(DnsOptions options)
    {
        var defaults = new DnsOptions();
        return !string.Equals(DnsModes.Normalize(options.Mode), DnsModes.Normalize(defaults.Mode), StringComparison.Ordinal) ||
               options.TimeoutSeconds != defaults.TimeoutSeconds ||
               options.CacheTtlSeconds != defaults.CacheTtlSeconds ||
               options.Servers.Count > 0;
    }

    private static bool HasAdvancedSniffing(InboundSniffingConfig options)
        => options.Enabled ||
           options.DestinationOverride.Count > 0 ||
           options.DomainsExcluded.Count > 0 ||
           options.MetadataOnly ||
           options.RouteOnly;
}

public sealed record AdvancedCertificateConfigInput
{
    public bool RejectUnknownSni { get; init; }

    public TlsClientHelloPolicyConfig? ClientHelloPolicy { get; init; }
}

public sealed record AdvancedLimitConfigInput
{
    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public sealed record AdvancedInboundConfigInput
{
    public string Transport { get; init; } = string.Empty;

    public IReadOnlyList<string>? ApplicationProtocols { get; init; }

    public InboundSniffingConfig? Sniffing { get; init; }

    public IReadOnlyList<TrojanFallbackConfig>? Fallbacks { get; init; }
}

public sealed class TrojanInboundFormInput
{
    public string Tag { get; set; } = string.Empty;

    public string Protocol { get; set; } = InboundProtocols.Trojan;

    public string Transport { get; set; } = InboundTransports.Tls;

    public bool Enabled { get; set; }

    public string ListenAddress { get; set; } = "0.0.0.0";

    [Range(0, 65535)]
    public int Port { get; set; } = 443;

    [Range(1, 600)]
    public int HandshakeTimeoutSeconds { get; set; } = 10;

    public bool AcceptProxyProtocol { get; set; }

    public string Host { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    [Range(0, 65535)]
    public int EarlyDataBytes { get; set; }

    [Range(0, 3600)]
    public int HeartbeatPeriodSeconds { get; set; }

    public string ApplicationProtocols { get; set; } = string.Empty;

    public bool ReceiveOriginalDestination { get; set; }

    public InboundSniffingFormInput Sniffing { get; set; } = new();

    public List<TrojanFallbackFormInput> Fallbacks { get; set; } = [];

    public void EnsureCollections()
    {
        Sniffing ??= new InboundSniffingFormInput();
        Fallbacks ??= [];
    }

    public static TrojanInboundFormInput CreateDefault(string transport)
        => CreateDefault(InboundProtocols.Trojan, transport);

    public static TrojanInboundFormInput CreateDefault(string protocol, string transport)
    {
        var normalizedProtocol = InboundProtocols.Normalize(protocol);
        var normalizedTransport = InboundTransports.Normalize(transport);
        var form = normalizedTransport == InboundTransports.Wss
            ? new TrojanInboundFormInput
            {
                Tag = GetDefaultTag(normalizedProtocol, normalizedTransport),
                Protocol = normalizedProtocol,
                Transport = normalizedTransport,
                ListenAddress = "0.0.0.0",
                Port = 8443,
                HandshakeTimeoutSeconds = 10,
                Path = "/ws"
            }
            : new TrojanInboundFormInput
            {
                Tag = GetDefaultTag(normalizedProtocol, normalizedTransport),
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Tls,
                ListenAddress = "0.0.0.0",
                Port = 443,
                HandshakeTimeoutSeconds = 10
            };
        form.EnsureCollections();
        return form;
    }

    public static TrojanInboundFormInput FromInbound(InboundConfig inbound)
    {
        var normalizedTransport = InboundTransports.Normalize(inbound.Transport);
        var form = new TrojanInboundFormInput
        {
            Tag = string.IsNullOrWhiteSpace(inbound.Tag) ? GetDefaultTag(normalizedTransport) : inbound.Tag,
            Enabled = inbound.Enabled,
            Protocol = InboundProtocols.Normalize(inbound.Protocol),
            Transport = normalizedTransport,
            ListenAddress = inbound.ListenAddress,
            Port = inbound.Port,
            HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds,
            AcceptProxyProtocol = inbound.AcceptProxyProtocol,
            Host = inbound.Host,
            Path = normalizedTransport == InboundTransports.Wss ? inbound.Path : string.Empty,
            EarlyDataBytes = normalizedTransport == InboundTransports.Wss ? Math.Max(0, inbound.EarlyDataBytes) : 0,
            HeartbeatPeriodSeconds = normalizedTransport == InboundTransports.Wss ? Math.Max(0, inbound.HeartbeatPeriodSeconds) : 0,
            ApplicationProtocols = NodeFormValueCodec.JoinCsv(inbound.ApplicationProtocols),
            ReceiveOriginalDestination = inbound.ReceiveOriginalDestination,
            Sniffing = InboundSniffingFormInput.FromConfig(inbound.Sniffing),
            Fallbacks = inbound.Fallbacks.Select(TrojanFallbackFormInput.FromConfig).ToList()
        };
        form.EnsureCollections();
        return form;
    }

    public InboundConfig ToInboundConfig()
    {
        EnsureCollections();
        var normalizedTransport = InboundTransports.Normalize(Transport);
        return new InboundConfig
        {
            Tag = string.IsNullOrWhiteSpace(Tag) ? GetDefaultTag(Protocol, normalizedTransport) : Tag.Trim(),
            Enabled = Enabled,
            Protocol = InboundProtocols.Normalize(Protocol),
            Transport = normalizedTransport,
            ListenAddress = NodeFormValueCodec.TrimOrEmpty(ListenAddress),
            Port = Port,
            HandshakeTimeoutSeconds = HandshakeTimeoutSeconds,
            AcceptProxyProtocol = AcceptProxyProtocol,
            Host = normalizedTransport == InboundTransports.Wss ? NodeFormValueCodec.TrimOrEmpty(Host) : string.Empty,
            Path = normalizedTransport == InboundTransports.Wss ? NodeFormValueCodec.TrimOrEmpty(Path) : string.Empty,
            EarlyDataBytes = normalizedTransport == InboundTransports.Wss ? Math.Max(0, EarlyDataBytes) : 0,
            HeartbeatPeriodSeconds = normalizedTransport == InboundTransports.Wss ? Math.Max(0, HeartbeatPeriodSeconds) : 0,
            ApplicationProtocols = NodeFormValueCodec.ParseCsv(ApplicationProtocols),
            ReceiveOriginalDestination = ReceiveOriginalDestination,
            Sniffing = Sniffing.ToConfig(),
            Fallbacks = Fallbacks
                .Where(static fallback => !fallback.IsEmpty())
                .Select(static fallback => fallback.ToConfig())
                .ToArray()
        };
    }

    public static string GetDefaultTag(string transport)
        => GetDefaultTag(InboundProtocols.Trojan, transport);

    public static string GetDefaultTag(string protocol, string transport)
        => InboundTransports.Normalize(transport) == InboundTransports.Wss
            ? $"{InboundProtocols.Normalize(protocol)}-wss"
            : $"{InboundProtocols.Normalize(protocol)}-tcp-tls";
}

public sealed class UserFormInput
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string SubscriptionToken { get; set; } = string.Empty;

    public string TrojanPassword { get; set; } = string.Empty;

    public string V2rayUuid { get; set; } = string.Empty;

    [Range(0, int.MaxValue)]
    public int GroupId { get; set; }

    public string InviteUserId { get; set; } = string.Empty;

    public decimal CommissionBalance { get; set; }

    [Range(0, 100)]
    public int CommissionRate { get; set; }

    public bool Enabled { get; set; } = true;

    [Range(0, long.MaxValue)]
    public long BytesPerSecond { get; set; }

    [Range(0, int.MaxValue)]
    public int DeviceLimit { get; set; }

    public string PlanName { get; set; } = string.Empty;

    [Range(0, long.MaxValue)]
    public long TransferEnableBytes { get; set; }

    public string ExpiresAt { get; set; } = string.Empty;

    public string PurchaseUrl { get; set; } = string.Empty;

    public string PortalNotice { get; set; } = string.Empty;

    public string NodeIds { get; set; } = string.Empty;

    public UpsertUserRequest ToRequest()
        => new()
        {
            DisplayName = NodeFormValueCodec.TrimOrEmpty(DisplayName),
            SubscriptionToken = NodeFormValueCodec.TrimOrEmpty(SubscriptionToken),
            TrojanPassword = NodeFormValueCodec.TrimOrEmpty(TrojanPassword),
            V2rayUuid = NodeFormValueCodec.TrimOrEmpty(V2rayUuid),
            InviteUserId = NodeFormValueCodec.TrimOrEmpty(InviteUserId),
            CommissionBalance = CommissionBalance,
            CommissionRate = CommissionRate,
            GroupId = GroupId,
            Enabled = Enabled,
            BytesPerSecond = BytesPerSecond,
            DeviceLimit = Math.Max(0, DeviceLimit),
            Subscription = new PanelUserSubscriptionProfile
            {
                PlanName = NodeFormValueCodec.TrimOrEmpty(PlanName),
                TransferEnableBytes = Math.Max(0, TransferEnableBytes),
                ExpiresAt = ParseOptionalDateTimeOffset(ExpiresAt),
                PurchaseUrl = NodeFormValueCodec.TrimOrEmpty(PurchaseUrl),
                PortalNotice = NodeFormValueCodec.TrimOrEmpty(PortalNotice)
            },
            NodeIds = NodeFormValueCodec.ParseCsv(NodeIds)
        };

    public static UserFormInput FromRecord(PanelUserRecord record)
        => new()
        {
            UserId = record.UserId,
            DisplayName = record.DisplayName,
            SubscriptionToken = record.SubscriptionToken,
            TrojanPassword = record.TrojanPassword,
            V2rayUuid = record.V2rayUuid,
            InviteUserId = record.InviteUserId,
            CommissionBalance = record.CommissionBalance,
            CommissionRate = record.CommissionRate,
            GroupId = record.GroupId,
            Enabled = record.Enabled,
            BytesPerSecond = record.BytesPerSecond,
            DeviceLimit = record.DeviceLimit,
            PlanName = record.Subscription.PlanName,
            TransferEnableBytes = record.Subscription.TransferEnableBytes,
            ExpiresAt = FormatOptionalDateTimeOffset(record.Subscription.ExpiresAt),
            PurchaseUrl = record.Subscription.PurchaseUrl,
            PortalNotice = record.Subscription.PortalNotice,
            NodeIds = string.Join(", ", record.NodeIds)
        };

    private static string FormatOptionalDateTimeOffset(DateTimeOffset? value)
        => value?.ToLocalTime().ToString("yyyy-MM-ddTHH:mm", CultureInfo.InvariantCulture) ?? string.Empty;

    private static DateTimeOffset? ParseOptionalDateTimeOffset(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsedOffset))
        {
            return parsedOffset;
        }

        if (DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsedDateTime))
        {
            return new DateTimeOffset(parsedDateTime);
        }

        return null;
    }
}

public sealed class PlanEditorViewModel
{
    public required PlanFormInput Form { get; init; }

    public required bool IsEditMode { get; init; }

    public string StatusMessage { get; init; } = string.Empty;

    public IReadOnlyList<ServerGroupViewModel> AvailableGroups { get; init; } = Array.Empty<ServerGroupViewModel>();
}

public sealed class PlanFormInput
{
    [Required]
    public string PlanId { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    [Range(0, int.MaxValue)]
    public int GroupId { get; set; }

    [Range(0, long.MaxValue)]
    public long TransferEnableBytes { get; set; }

    public decimal? MonthPrice { get; set; }
    public decimal? QuarterPrice { get; set; }
    public decimal? HalfYearPrice { get; set; }
    public decimal? YearPrice { get; set; }
    public decimal? OneTimePrice { get; set; }
    public decimal? ResetPrice { get; set; }

    public UpsertPlanRequest ToRequest()
        => new()
        {
            Name = NodeFormValueCodec.TrimOrEmpty(Name),
            GroupId = GroupId,
            TransferEnableBytes = Math.Max(0, TransferEnableBytes),
            MonthPrice = MonthPrice,
            QuarterPrice = QuarterPrice,
            HalfYearPrice = HalfYearPrice,
            YearPrice = YearPrice,
            OneTimePrice = OneTimePrice,
            ResetPrice = ResetPrice
        };

    public static PlanFormInput FromRecord(PanelPlanRecord record)
        => new()
        {
            PlanId = record.PlanId,
            Name = record.Name,
            GroupId = record.GroupId,
            TransferEnableBytes = record.TransferEnableBytes,
            MonthPrice = record.MonthPrice,
            QuarterPrice = record.QuarterPrice,
            HalfYearPrice = record.HalfYearPrice,
            YearPrice = record.YearPrice,
            OneTimePrice = record.OneTimePrice,
            ResetPrice = record.ResetPrice
        };
}

public sealed class TicketViewModel
{
    public string TicketId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public int Level { get; set; }
    public int Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class CommissionLogViewModel
{
    public string LogId { get; set; } = string.Empty;
    public string InviteUserId { get; set; } = string.Empty;
    public string OrderId { get; set; } = string.Empty;
    public decimal TradeAmount { get; set; }
    public decimal CommissionAmount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class ServerGroupsPageViewModel
{
    public IReadOnlyList<ServerGroupViewModel> Groups { get; init; } = Array.Empty<ServerGroupViewModel>();
    public string StatusMessage { get; init; } = string.Empty;
}

public sealed class ServerGroupViewModel
{
    public int GroupId { get; set; }
    public string Name { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class ServerGroupEditorViewModel
{
    public required ServerGroupFormInput Form { get; init; }
    public required bool IsEditMode { get; init; }
    public string StatusMessage { get; init; } = string.Empty;
}

public sealed class ServerGroupFormInput
{
    public int GroupId { get; set; }
    
    [Required]
    public string Name { get; set; } = string.Empty;

    public static ServerGroupFormInput FromEntity(ServerGroupEntity entity)
        => new()
        {
            GroupId = entity.GroupId,
            Name = entity.Name
        };
}

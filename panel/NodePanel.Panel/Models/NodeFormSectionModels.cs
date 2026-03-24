using System.ComponentModel.DataAnnotations;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Panel.Models;

public sealed class InboundSniffingFormInput
{
    public bool Enabled { get; set; }

    public string DestinationOverride { get; set; } = string.Empty;

    public string DomainsExcluded { get; set; } = string.Empty;

    public bool MetadataOnly { get; set; }

    public bool RouteOnly { get; set; }

    public InboundSniffingConfig ToConfig()
        => new()
        {
            Enabled = Enabled,
            DestinationOverride = NodeFormValueCodec.ParseCsv(DestinationOverride),
            DomainsExcluded = NodeFormValueCodec.ParseCsv(DomainsExcluded),
            MetadataOnly = MetadataOnly,
            RouteOnly = RouteOnly
        };

    public static InboundSniffingFormInput FromConfig(InboundSniffingConfig config)
        => new()
        {
            Enabled = config.Enabled,
            DestinationOverride = NodeFormValueCodec.JoinCsv(config.DestinationOverride),
            DomainsExcluded = NodeFormValueCodec.JoinCsv(config.DomainsExcluded),
            MetadataOnly = config.MetadataOnly,
            RouteOnly = config.RouteOnly
        };
}

public sealed class TrojanFallbackFormInput
{
    public string Name { get; set; } = string.Empty;

    public string Alpn { get; set; } = string.Empty;

    public string Path { get; set; } = string.Empty;

    public string Type { get; set; } = "tcp";

    public string Dest { get; set; } = string.Empty;

    [Range(0, 2)]
    public int ProxyProtocolVersion { get; set; }

    public bool IsEmpty()
        => string.IsNullOrWhiteSpace(Name) &&
           string.IsNullOrWhiteSpace(Alpn) &&
           string.IsNullOrWhiteSpace(Path) &&
           string.IsNullOrWhiteSpace(Dest) &&
           string.Equals(Type, "tcp", StringComparison.OrdinalIgnoreCase) &&
           ProxyProtocolVersion == 0;

    public TrojanFallbackConfig ToConfig()
        => new()
        {
            Name = NodeFormValueCodec.TrimOrEmpty(Name),
            Alpn = NodeFormValueCodec.TrimOrEmpty(Alpn),
            Path = NodeFormValueCodec.TrimOrEmpty(Path),
            Type = NodeFormValueCodec.TrimOrEmpty(Type),
            Dest = NodeFormValueCodec.TrimOrEmpty(Dest),
            ProxyProtocolVersion = ProxyProtocolVersion
        };

    public static TrojanFallbackFormInput FromConfig(TrojanFallbackConfig config)
        => new()
        {
            Name = config.Name,
            Alpn = config.Alpn,
            Path = config.Path,
            Type = config.Type,
            Dest = config.Dest,
            ProxyProtocolVersion = Math.Clamp(config.ProxyProtocolVersion, 0, 2)
        };
}

public sealed class ClientHelloPolicyFormInput
{
    public bool Enabled { get; set; }

    public string AllowedServerNames { get; set; } = string.Empty;

    public string BlockedServerNames { get; set; } = string.Empty;

    public string AllowedApplicationProtocols { get; set; } = string.Empty;

    public string BlockedApplicationProtocols { get; set; } = string.Empty;

    public string AllowedJa3 { get; set; } = string.Empty;

    public string BlockedJa3 { get; set; } = string.Empty;

    public TlsClientHelloPolicyConfig ToConfig()
        => new()
        {
            Enabled = Enabled,
            AllowedServerNames = NodeFormValueCodec.ParseCsv(AllowedServerNames),
            BlockedServerNames = NodeFormValueCodec.ParseCsv(BlockedServerNames),
            AllowedApplicationProtocols = NodeFormValueCodec.ParseCsv(AllowedApplicationProtocols),
            BlockedApplicationProtocols = NodeFormValueCodec.ParseCsv(BlockedApplicationProtocols),
            AllowedJa3 = NodeFormValueCodec.ParseCsv(AllowedJa3),
            BlockedJa3 = NodeFormValueCodec.ParseCsv(BlockedJa3)
        };

    public static ClientHelloPolicyFormInput FromConfig(TlsClientHelloPolicyConfig config)
        => new()
        {
            Enabled = config.Enabled,
            AllowedServerNames = NodeFormValueCodec.JoinCsv(config.AllowedServerNames),
            BlockedServerNames = NodeFormValueCodec.JoinCsv(config.BlockedServerNames),
            AllowedApplicationProtocols = NodeFormValueCodec.JoinCsv(config.AllowedApplicationProtocols),
            BlockedApplicationProtocols = NodeFormValueCodec.JoinCsv(config.BlockedApplicationProtocols),
            AllowedJa3 = NodeFormValueCodec.JoinCsv(config.AllowedJa3),
            BlockedJa3 = NodeFormValueCodec.JoinCsv(config.BlockedJa3)
        };
}

public sealed class DnsFormInput
{
    public string Mode { get; set; } = DnsModes.System;

    [Range(1, 300)]
    public int TimeoutSeconds { get; set; } = 5;

    [Range(0, 86400)]
    public int CacheTtlSeconds { get; set; } = 30;

    public List<DnsServerFormInput> Servers { get; set; } = [];

    public static DnsFormInput FromConfig(DnsOptions config)
        => new()
        {
            Mode = DnsModes.Normalize(config.Mode),
            TimeoutSeconds = config.TimeoutSeconds > 0 ? Math.Clamp(config.TimeoutSeconds, 1, 300) : 5,
            CacheTtlSeconds = Math.Clamp(config.CacheTtlSeconds, 0, 86400),
            Servers = config.Servers.Select(DnsServerFormInput.FromConfig).ToList()
        };
}

public sealed class DnsServerFormInput
{
    public string Url { get; set; } = string.Empty;

    public string HeadersText { get; set; } = string.Empty;

    public bool IsEmpty()
        => string.IsNullOrWhiteSpace(Url) && string.IsNullOrWhiteSpace(HeadersText);

    public bool TryToConfig(out DnsHttpServerConfig config, out string error)
    {
        if (string.IsNullOrWhiteSpace(Url))
        {
            config = new DnsHttpServerConfig { Url = string.Empty };
            error = "URL 不能为空。";
            return false;
        }

        if (!NodeFormValueCodec.TryParseHeaderLines(HeadersText, out var headers, out error))
        {
            config = new DnsHttpServerConfig { Url = string.Empty };
            return false;
        }

        config = new DnsHttpServerConfig
        {
            Url = NodeFormValueCodec.TrimOrEmpty(Url),
            Headers = headers
        };
        error = string.Empty;
        return true;
    }

    public static DnsServerFormInput FromConfig(DnsHttpServerConfig config)
        => new()
        {
            Url = config.Url,
            HeadersText = NodeFormValueCodec.FormatHeaderLines(config.Headers)
        };
}

public sealed class RoutingRuleFormInput
{
    public bool Enabled { get; set; } = true;

    public string InboundTags { get; set; } = string.Empty;

    public string Protocols { get; set; } = string.Empty;

    public string Networks { get; set; } = string.Empty;

    public string UserIds { get; set; } = string.Empty;

    public string Domains { get; set; } = string.Empty;

    public string SourceCidrs { get; set; } = string.Empty;

    public string DestinationPorts { get; set; } = string.Empty;

    public string OutboundTag { get; set; } = string.Empty;

    public bool IsEmpty()
        => string.IsNullOrWhiteSpace(InboundTags) &&
           string.IsNullOrWhiteSpace(Protocols) &&
           string.IsNullOrWhiteSpace(Networks) &&
           string.IsNullOrWhiteSpace(UserIds) &&
           string.IsNullOrWhiteSpace(Domains) &&
           string.IsNullOrWhiteSpace(SourceCidrs) &&
           string.IsNullOrWhiteSpace(DestinationPorts) &&
           string.IsNullOrWhiteSpace(OutboundTag);

    public RoutingRuleConfig ToConfig()
        => new()
        {
            Enabled = Enabled,
            InboundTags = NodeFormValueCodec.ParseCsv(InboundTags),
            Protocols = NodeFormValueCodec.ParseCsv(Protocols),
            Networks = NodeFormValueCodec.ParseCsv(Networks),
            UserIds = NodeFormValueCodec.ParseCsv(UserIds),
            Domains = NodeFormValueCodec.ParseCsv(Domains),
            SourceCidrs = NodeFormValueCodec.ParseCsv(SourceCidrs),
            DestinationPorts = NodeFormValueCodec.ParseCsv(DestinationPorts),
            OutboundTag = NodeFormValueCodec.TrimOrEmpty(OutboundTag)
        };

    public static RoutingRuleFormInput FromConfig(RoutingRuleConfig config)
        => new()
        {
            Enabled = config.Enabled,
            InboundTags = NodeFormValueCodec.JoinCsv(config.InboundTags),
            Protocols = NodeFormValueCodec.JoinCsv(config.Protocols),
            Networks = NodeFormValueCodec.JoinCsv(config.Networks),
            UserIds = NodeFormValueCodec.JoinCsv(config.UserIds),
            Domains = NodeFormValueCodec.JoinCsv(config.Domains),
            SourceCidrs = NodeFormValueCodec.JoinCsv(config.SourceCidrs),
            DestinationPorts = NodeFormValueCodec.JoinCsv(config.DestinationPorts),
            OutboundTag = config.OutboundTag
        };
}

using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public sealed record InboundSniffingConfig : ITrojanSniffingDefinition
{
    public bool Enabled { get; init; }

    public IReadOnlyList<string> DestinationOverride { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DomainsExcluded { get; init; } = Array.Empty<string>();

    public bool MetadataOnly { get; init; }

    public bool RouteOnly { get; init; }
}

public sealed record InboundConfig : ITrojanInboundDefinition, ITrojanInboundScopeDefinition, IVlessInboundDefinition, IVlessInboundScopeDefinition, IVmessInboundDefinition, IVmessInboundScopeDefinition
{
    public string Tag { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public string Protocol { get; init; } = InboundProtocols.Trojan;

    public string Transport { get; init; } = InboundTransports.Tls;

    public string ListenAddress { get; init; } = "0.0.0.0";

    public int Port { get; init; } = 443;

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public bool AcceptProxyProtocol { get; init; }

    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public int EarlyDataBytes { get; init; }

    public int HeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public bool ReceiveOriginalDestination { get; init; }

    public InboundSniffingConfig Sniffing { get; init; } = new();

    public IReadOnlyList<TrojanUserConfig> Users { get; init; } = Array.Empty<TrojanUserConfig>();

    public IReadOnlyList<TrojanFallbackConfig> Fallbacks { get; init; } = Array.Empty<TrojanFallbackConfig>();

    public IReadOnlyList<ITrojanUserDefinition> GetUsers() => Users;

    public IReadOnlyList<IVlessUserDefinition> GetVlessUsers() => Users;

    public IReadOnlyList<IVmessUserDefinition> GetVmessUsers() => Users;

    public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Fallbacks;

    public ITrojanSniffingDefinition GetSniffing() => Sniffing;

    public bool GetReceiveOriginalDestination() => ReceiveOriginalDestination;
}

public sealed record LocalInboundConfig
{
    public string Tag { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public string Protocol { get; init; } = LocalInboundProtocols.Socks;

    public string ListenAddress { get; init; } = "127.0.0.1";

    public int Port { get; init; } = 10808;

    public int HandshakeTimeoutSeconds { get; init; } = 10;
}

public sealed record OutboundConfig : IOutboundDefinition
    , IOutboundSenderDefinition
    , IStrategyOutboundDefinition
{
    public string Tag { get; init; } = "direct";

    public bool Enabled { get; init; } = true;

    public string Protocol { get; init; } = OutboundProtocols.Freedom;

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string TargetStrategy { get; init; } = OutboundTargetStrategies.AsIs;

    public string ProxyOutboundTag { get; init; } = string.Empty;

    public OutboundMultiplexConfig MultiplexSettings { get; init; } = new();

    public string Transport { get; init; } = TrojanOutboundTransports.Tls;

    public string ServerHost { get; init; } = string.Empty;

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketEarlyDataBytes { get; init; }

    public int WebSocketHeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public string Password { get; init; } = string.Empty;

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }

    public bool SkipCertificateValidation { get; init; }

    public IReadOnlyList<string> CandidateTags { get; init; } = Array.Empty<string>();

    public string SelectedTag { get; init; } = string.Empty;

    public string ProbeUrl { get; init; } = StrategyOutboundDefaults.ProbeUrl;

    public int ProbeIntervalSeconds { get; init; } = StrategyOutboundDefaults.ProbeIntervalSeconds;

    public int ProbeTimeoutSeconds { get; init; } = StrategyOutboundDefaults.ProbeTimeoutSeconds;

    public int ToleranceMilliseconds { get; init; } = StrategyOutboundDefaults.ToleranceMilliseconds;

    public IOutboundMultiplexDefinition GetMultiplexSettings() => MultiplexSettings;
}

public sealed record OutboundMultiplexConfig : IOutboundMultiplexDefinition
{
    public bool Enabled { get; init; }

    public int Concurrency { get; init; }

    public int XudpConcurrency { get; init; }

    public string XudpProxyUdp443 { get; init; } = OutboundXudpProxyModes.Reject;
}

public sealed record RoutingRuleConfig : IRoutingRuleDefinition
{
    public bool Enabled { get; init; } = true;

    public IReadOnlyList<string> InboundTags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Protocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Networks { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> UserIds { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> SourceCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DestinationPorts { get; init; } = Array.Empty<string>();

    public string OutboundTag { get; init; } = string.Empty;
}

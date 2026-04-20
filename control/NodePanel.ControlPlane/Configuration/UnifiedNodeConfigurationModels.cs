using System.Text.Json.Serialization;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public sealed record InboundSniffingConfig : IRuntimeSniffingDefinition
{
    public bool Enabled { get; init; }

    public IReadOnlyList<string> DestinationOverride { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DomainsExcluded { get; init; } = Array.Empty<string>();

    public bool MetadataOnly { get; init; }

    public bool RouteOnly { get; init; }
}

public sealed record InboundConfig : ITrojanInboundDefinition, ITrojanInboundScopeDefinition, IShadowsocksInboundDefinition, IShadowsocksInboundScopeDefinition, IShadowsocks2022InboundScopeDefinition, IVlessInboundDefinition, IVlessInboundScopeDefinition, IVmessInboundDefinition, IVmessInboundScopeDefinition, IDokodemoInboundDefinition, IInboundInternetDefinition, IInboundGrpcDefinition, IInboundSplitHttpDefinition, IInboundQuicDefinition
{
    public string Tag { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public string Protocol { get; init; } = InboundProtocols.Trojan;

    public string Transport { get; init; } = string.Empty;

    public string TransportProtocol { get; init; } = string.Empty;

    public string TransportSecurity { get; init; } = string.Empty;

    public string ListenAddress { get; init; } = "0.0.0.0";

    public int Port { get; init; } = 443;

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public bool AcceptProxyProtocol { get; init; }

    public string Security { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string Flow { get; init; } = string.Empty;

    public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

    public string Decryption { get; init; } = string.Empty;

    public uint XorMode { get; init; }

    public int SecondsFrom { get; init; }

    public int SecondsTo { get; init; }

    public string Padding { get; init; } = string.Empty;

    public IReadOnlyList<string> Networks { get; init; } = Array.Empty<string>();

    public string DestinationHost { get; init; } = string.Empty;

    public int DestinationPort { get; init; }

    public IReadOnlyDictionary<string, string> PortMap { get; init; }
        = new Dictionary<string, string>(StringComparer.Ordinal);

    public int UserLevel { get; init; }

    public int Mark { get; init; }

    public bool FollowRedirect { get; init; }

    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public string SplitHttpMode { get; init; } = string.Empty;

    public bool SplitHttpNoSseHeader { get; init; }

    public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

    public bool SplitHttpXPaddingObfsMode { get; init; }

    public string SplitHttpXPaddingKey { get; init; } = string.Empty;

    public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

    public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

    public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

    public string SplitHttpSessionPlacement { get; init; } = string.Empty;

    public string SplitHttpSessionKey { get; init; } = string.Empty;

    public string SplitHttpSeqPlacement { get; init; } = string.Empty;

    public string SplitHttpSeqKey { get; init; } = string.Empty;

    public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

    public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

    public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

    public int SplitHttpScMaxBufferedPosts { get; init; }

    public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

    public int SplitHttpServerMaxHeaderBytes { get; init; }

    public int EarlyDataBytes { get; init; }

    public int HeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

    public string GrpcServiceName { get; init; } = string.Empty;

    public string GrpcAuthority { get; init; } = string.Empty;

    public bool GrpcMultiMode { get; init; }

    public string GrpcUserAgent { get; init; } = string.Empty;

    public int GrpcIdleTimeoutSeconds { get; init; }

    public int GrpcHealthCheckTimeoutSeconds { get; init; }

    public bool GrpcPermitWithoutStream { get; init; }

    public int GrpcInitialWindowSize { get; init; }

    public bool ReceiveOriginalDestination { get; init; }

    public InboundSniffingConfig Sniffing { get; init; } = new();

    public IReadOnlyList<TrojanUserConfig> Users { get; init; } = Array.Empty<TrojanUserConfig>();

    public IReadOnlyList<ShadowsocksUserConfig> ShadowsocksUsers { get; init; } = Array.Empty<ShadowsocksUserConfig>();

    public IReadOnlyList<TrojanFallbackConfig> Fallbacks { get; init; } = Array.Empty<TrojanFallbackConfig>();

    public IReadOnlyList<ITrojanUserDefinition> GetUsers() => Users;

    public IReadOnlyList<IShadowsocksUserDefinition> GetShadowsocksUsers() => ShadowsocksUsers.Count > 0 ? ShadowsocksUsers : Users;

    public IReadOnlyList<IShadowsocks2022UserDefinition> GetShadowsocks2022Users() => ShadowsocksUsers;

    public IReadOnlyList<IVlessUserDefinition> GetVlessUsers() => Users;

    public string GetVlessFlow() => Flow;

    public IReadOnlyList<uint> GetVlessTestSeed() => TestSeed;

    public string GetVlessDecryption() => Decryption;

    public uint GetVlessXorMode() => XorMode;

    public int GetVlessSecondsFrom() => SecondsFrom;

    public int GetVlessSecondsTo() => SecondsTo;

    public string GetVlessPadding() => Padding;

    public IReadOnlyList<IVmessUserDefinition> GetVmessUsers() => Users;

    public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Fallbacks;

    IRuntimeSniffingDefinition IDokodemoInboundDefinition.Sniffing => Sniffing;

    public IRuntimeSniffingDefinition GetSniffing() => Sniffing;

    public bool GetReceiveOriginalDestination() => ReceiveOriginalDestination;
}

public sealed record ProxyInboundConfig
{
    public string Tag { get; init; } = string.Empty;

    public bool Enabled { get; init; } = true;

    public string Protocol { get; init; } = ProxyInboundProtocols.Socks;

    public string ListenAddress { get; init; } = "127.0.0.1";

    public int Port { get; init; } = 10808;

    public int UserLevel { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public bool AllowTransparent { get; init; }

    public IReadOnlyList<LocalSocksUserConfig> SocksUsers { get; init; } = Array.Empty<LocalSocksUserConfig>();

    public IReadOnlyList<LocalSocksUserConfig> HttpUsers { get; init; } = Array.Empty<LocalSocksUserConfig>();
}

public sealed record LocalSocksUserConfig
{
    public string Username { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;
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

    public string Transport { get; init; } = string.Empty;

    public string TransportSecurity { get; init; } = string.Empty;

    public string ServerHost { get; init; } = string.Empty;

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, string> HttpHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketEarlyDataBytes { get; init; }

    public int WebSocketHeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public string GrpcServiceName { get; init; } = string.Empty;

    public string GrpcAuthority { get; init; } = string.Empty;

    public bool GrpcMultiMode { get; init; }

    public string GrpcUserAgent { get; init; } = string.Empty;

    public int GrpcIdleTimeoutSeconds { get; init; }

    public int GrpcHealthCheckTimeoutSeconds { get; init; }

    public bool GrpcPermitWithoutStream { get; init; }

    public int GrpcInitialWindowSize { get; init; }

    public string Uuid { get; init; } = string.Empty;

    public string Flow { get; init; } = string.Empty;

    public string Encryption { get; init; } = string.Empty;

    public uint XorMode { get; init; }

    public int Seconds { get; init; }

    public string Padding { get; init; } = string.Empty;

    public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

    public int TestPre { get; init; }

    public string ReverseTag { get; init; } = string.Empty;

    public string Username { get; init; } = string.Empty;

    public string Security { get; init; } = VmessOutboundSecurityTypes.Auto;

    public bool AuthenticatedLength { get; init; } = true;

    public bool NoTerminationSignal { get; init; }

    public string Password { get; init; } = string.Empty;

    public bool UdpOverTcp { get; init; }

    public int UdpOverTcpVersion { get; init; }

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

    public string RuleTag { get; init; } = string.Empty;

    public IReadOnlyList<string> InboundTags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Protocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Networks { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> UserIds { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Processes { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> SourceCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DestinationCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DestinationPorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> SourcePorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> LocalCidrs { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> LocalPorts { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> VlessRoutes { get; init; } = Array.Empty<string>();

    public IReadOnlyDictionary<string, string> Attributes { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string OutboundTag { get; init; } = string.Empty;
}

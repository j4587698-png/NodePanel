namespace NodePanel.Core.Runtime;

public static class VlessOutboundTransports
{
    public const string Tcp = TrojanOutboundTransports.Tcp;
    public const string Tls = TrojanOutboundTransports.Tls;
    public const string Ws = TrojanOutboundTransports.Ws;
    public const string Wss = TrojanOutboundTransports.Wss;
    public const string HttpUpgrade = TrojanOutboundTransports.HttpUpgrade;
    public const string HttpUpgradeTls = TrojanOutboundTransports.HttpUpgradeTls;
    public const string Grpc = TrojanOutboundTransports.Grpc;
    public const string SplitHttp = TrojanOutboundTransports.SplitHttp;

    public static string Normalize(string? value)
        => TrojanOutboundTransports.Normalize(value);
}

public sealed record VlessOutboundSettings
{
    public required string Tag { get; init; }

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string TargetStrategy { get; init; } = OutboundTargetStrategies.AsIs;

    public string ProxyOutboundTag { get; init; } = string.Empty;

    public OutboundMultiplexRuntime MultiplexSettings { get; init; } = OutboundMultiplexRuntime.Disabled;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public string Transport { get; init; } = VlessOutboundTransports.Tls;

    public string TransportSecurity { get; init; } = string.Empty;

    public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketEarlyDataBytes { get; init; }

    public int WebSocketHeartbeatPeriodSeconds { get; init; }

    public string SplitHttpHost { get; init; } = string.Empty;

    public string SplitHttpPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string SplitHttpMode { get; init; } = string.Empty;

    public bool SplitHttpNoGrpcHeader { get; init; }

    public bool SplitHttpNoSseHeader { get; init; }

    public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

    public bool SplitHttpXPaddingObfsMode { get; init; }

    public string SplitHttpXPaddingKey { get; init; } = string.Empty;

    public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

    public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

    public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

    public string SplitHttpUplinkHttpMethod { get; init; } = string.Empty;

    public string SplitHttpSessionPlacement { get; init; } = string.Empty;

    public string SplitHttpSessionKey { get; init; } = string.Empty;

    public string SplitHttpSeqPlacement { get; init; } = string.Empty;

    public string SplitHttpSeqKey { get; init; } = string.Empty;

    public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

    public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

    public RuntimeInt32Range SplitHttpUplinkChunkSize { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range SplitHttpScMinPostsIntervalMs { get; init; } = RuntimeInt32Range.Empty;

    public int SplitHttpScMaxBufferedPosts { get; init; }

    public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

    public int SplitHttpServerMaxHeaderBytes { get; init; }

    public RuntimeSplitHttpXmuxOptions SplitHttpXmux { get; init; } = RuntimeSplitHttpXmuxOptions.Empty;

    public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings { get; init; }

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

    public byte Version { get; init; }

    public required string UserUuid { get; init; }

    public string Flow { get; init; } = string.Empty;

    public string Encryption { get; init; } = string.Empty;

    public uint XorMode { get; init; }

    public int Seconds { get; init; }

    public string Padding { get; init; } = string.Empty;

    public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

    public int TestPre { get; init; }

    public string ReverseTag { get; init; } = string.Empty;

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }

    public bool EnableTlsSessionResumption { get; init; }

    public bool SkipCertificateValidation { get; init; }

    public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider { get; init; }
}

public interface IVlessOutboundSettingsProvider
{
    bool TryResolve(DispatchContext context, out VlessOutboundSettings settings);
}

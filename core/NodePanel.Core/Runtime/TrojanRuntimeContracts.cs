namespace NodePanel.Core.Runtime;

public interface ITrojanUserDefinition : IRuntimeUserDefinition
{
    string Password { get; }
}

public interface ITrojanFallbackDefinition : IRuntimeFallbackDefinition
{
}

public interface ITrojanInboundConnectionOptions : IRuntimeFallbackConnectionOptions
{
    bool TryAuthenticate(string passwordHash, out TrojanUser? user);
}

public static class TrojanOutboundTransports
{
    public const string Tcp = "tcp";
    public const string Tls = "tls";
    public const string Ws = "ws";
    public const string Wss = "wss";
    public const string HttpUpgrade = "httpupgrade";
    public const string HttpUpgradeTls = "httpupgrades";
    public const string Grpc = "grpc";
    public const string SplitHttp = RuntimeInternetTransportProtocols.SplitHttp;

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Tls
            : value.Trim().ToLowerInvariant() switch
            {
                "raw" => Tcp,
                "websocket" => Ws,
                HttpUpgrade or "http-upgrade" => HttpUpgrade,
                HttpUpgradeTls or "httpupgrade+tls" or "httpupgrade-tls" => HttpUpgradeTls,
                SplitHttp or "xhttp" or "split-http" => SplitHttp,
                "kcp" or RuntimeInternetTransportProtocols.Mkcp => RuntimeInternetTransportProtocols.Mkcp,
                RuntimeInternetTransportProtocols.Hysteria => RuntimeInternetTransportProtocols.Hysteria,
                Grpc => Grpc,
                _ => value.Trim().ToLowerInvariant()
            };
}

public sealed record TrojanOutboundSettings
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

    public string Transport { get; init; } = TrojanOutboundTransports.Tls;

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

    public required string Password { get; init; }

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }

    public bool EnableTlsSessionResumption { get; init; }

    public bool SkipCertificateValidation { get; init; }

    public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider { get; init; }
}

public interface ITrojanOutboundSettingsProvider
{
    bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings);
}

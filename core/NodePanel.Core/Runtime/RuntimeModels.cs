using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

public interface IRuntime : IAsyncDisposable
{
    RuntimeState State { get; }

    IRuntimeUserStore Users { get; }

    Task StartAsync(RuntimePlan plan, CancellationToken cancellationToken = default);

    Task ReloadAsync(RuntimePlan plan, CancellationToken cancellationToken = default);

    Task StopAsync(CancellationToken cancellationToken = default);

    RuntimeStatusSnapshot GetStatus();

    IReadOnlyList<UserTrafficSnapshot> GetTrafficSnapshot();

    IReadOnlyList<UserSessionSnapshot> GetSessionSnapshot();

    ValueTask<IReadOnlyList<RuntimeStrategyStatus>> RefreshStrategyStatusesAsync(CancellationToken cancellationToken = default);

    IAsyncEnumerable<RuntimeEvent> GetEventsAsync(CancellationToken cancellationToken = default);
}

public enum RuntimeState
{
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Faulted = 4
}

public record RuntimePlan
{
    public static RuntimePlan Empty { get; } = new();

    public int Revision { get; init; }

    public NodeRuntimePlan Plan { get; init; } = NodeRuntimePlan.Empty;

    public RuntimeTransportLimits TransportLimits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public DnsRuntimeSettings Dns { get; init; } = DnsRuntimeSettings.Default;

    public RuntimeTlsOptions? Tls { get; init; }

    public RuntimeRealityServerOptions? Reality { get; init; }

    public bool UseCone { get; init; } = true;

    public ProxyInboundRuntimePlan ProxyInbounds { get; init; } = ProxyInboundRuntimePlan.Empty;

    public RuntimeOutboundSettingsCatalog OutboundSettings { get; init; } = RuntimeOutboundSettingsCatalog.Empty;

    public IReadOnlyList<IRuntimeUserDefinition> ActiveUsers { get; init; } = Array.Empty<IRuntimeUserDefinition>();
}

public sealed record RuntimeTransportLimits : IRuntimeInboundLimits
{
    public long GlobalBytesPerSecond { get; init; }

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public sealed record RuntimeInt32Range
{
    public static RuntimeInt32Range Empty { get; } = new();

    public int From { get; init; }

    public int To { get; init; }
}

public sealed record RuntimeSplitHttpDownloadOptions
{
    public string? ServerHost { get; init; }

    public int? ServerPort { get; init; }

    public string? ServerName { get; init; }

    public string? Fingerprint { get; init; }

    public string? TransportSecurity { get; init; }

    public RuntimeRealityOptions? RealityOptions { get; init; }

    public string? Host { get; init; }

    public string? Path { get; init; }

    public IReadOnlyDictionary<string, string>? Headers { get; init; }

    public int? ConnectTimeoutSeconds { get; init; }

    public int? HandshakeTimeoutSeconds { get; init; }

    public bool? SkipCertificateValidation { get; init; }
}

public sealed record RuntimeSplitHttpXmuxOptions
{
    public static RuntimeSplitHttpXmuxOptions Empty { get; } = new();

    public RuntimeInt32Range MaxConcurrency { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range MaxConnections { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range CMaxReuseTimes { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range HMaxRequestTimes { get; init; } = RuntimeInt32Range.Empty;

    public RuntimeInt32Range HMaxReusableSecs { get; init; } = RuntimeInt32Range.Empty;

    public int HKeepAlivePeriodSeconds { get; init; }
}

public sealed record RuntimeUdpHopOptions
{
    public static RuntimeUdpHopOptions Empty { get; } = new();

    public IReadOnlyList<int> Ports { get; init; } = Array.Empty<int>();

    public long IntervalMinSeconds { get; init; }

    public long IntervalMaxSeconds { get; init; }
}

public sealed record RuntimeQuicOptions
{
    public static RuntimeQuicOptions Empty { get; } = new();

    public string Congestion { get; init; } = string.Empty;

    public long BrutalUp { get; init; }

    public long BrutalDown { get; init; }

    public RuntimeUdpHopOptions UdpHop { get; init; } = RuntimeUdpHopOptions.Empty;

    public long InitStreamReceiveWindow { get; init; }

    public long MaxStreamReceiveWindow { get; init; }

    public long InitConnReceiveWindow { get; init; }

    public long MaxConnReceiveWindow { get; init; }

    public long MaxIdleTimeoutSeconds { get; init; }

    public long KeepAlivePeriodSeconds { get; init; }

    public bool DisablePathMtuDiscovery { get; init; }

    public long MaxIncomingStreams { get; init; }
}

public sealed record RuntimeTlsOptions
{
    public required X509Certificate2 Certificate { get; init; }

    public IReadOnlyList<X509Certificate2> AdditionalCertificates { get; init; } = Array.Empty<X509Certificate2>();

    public RuntimeTlsServerNamePolicyOptions ServerNamePolicy { get; init; } = new();

    public RuntimeTlsClientHelloPolicyOptions ClientHelloPolicy { get; init; } = RuntimeTlsClientHelloPolicyOptions.Disabled;

    public bool EnableTlsSessionResumption { get; init; }
}

public sealed record RuntimeRealityServerOptions
{
    public static RuntimeRealityServerOptions Empty { get; } = new();

    public bool Show { get; init; }

    public string MasterKeyLog { get; init; } = string.Empty;

    public string Dest { get; init; } = string.Empty;

    public string Type { get; init; } = string.Empty;

    public int Xver { get; init; }

    public IReadOnlyList<string> ServerNames { get; init; } = Array.Empty<string>();

    public string PrivateKey { get; init; } = string.Empty;

    public string MinClientVersion { get; init; } = string.Empty;

    public string MaxClientVersion { get; init; } = string.Empty;

    public long MaxTimeDiffMilliseconds { get; init; }

    public IReadOnlyList<string> ShortIds { get; init; } = Array.Empty<string>();

    public string Mldsa65Seed { get; init; } = string.Empty;

    public RuntimeFallbackLimitOptions LimitFallbackUpload { get; init; } = RuntimeFallbackLimitOptions.Empty;

    public RuntimeFallbackLimitOptions LimitFallbackDownload { get; init; } = RuntimeFallbackLimitOptions.Empty;

    public RuntimeTlsClientHelloPolicyOptions ClientHelloPolicy { get; init; } = RuntimeTlsClientHelloPolicyOptions.Disabled;
}

public sealed record RuntimeFallbackLimitOptions
{
    public static RuntimeFallbackLimitOptions Empty { get; } = new();

    public long AfterBytes { get; init; }

    public long BytesPerSecond { get; init; }

    public long BurstBytesPerSecond { get; init; }

    public bool IsEmpty => AfterBytes <= 0 && BytesPerSecond <= 0 && BurstBytesPerSecond <= 0;

    public bool IsEnabled => BytesPerSecond > 0;
}

public sealed record ProxyInboundRuntimePlan
{
    public static ProxyInboundRuntimePlan Empty { get; } = new();

    public IReadOnlyList<ProxyInboundListenerDefinition> SocksListeners { get; init; } = Array.Empty<ProxyInboundListenerDefinition>();

    public IReadOnlyList<ProxyInboundListenerDefinition> HttpListeners { get; init; } = Array.Empty<ProxyInboundListenerDefinition>();

    public IReadOnlyDictionary<string, Socks5LocalAuthenticationOptions> SocksAuthenticationsByTag { get; init; }
        = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, Socks5LocalAuthenticationOptions> HttpAuthenticationsByTag { get; init; }
        = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);

    public bool HasListeners => SocksListeners.Count > 0 || HttpListeners.Count > 0;

    public IReadOnlyList<ProxyInboundListenerDefinition> GetListeners(string? protocol)
        => ProxyInboundProtocols.Normalize(protocol) switch
        {
            ProxyInboundProtocols.Http => HttpListeners,
            _ => SocksListeners
        };
}

public sealed record RuntimeTrojanOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Trojan;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public string Transport { get; init; } = TrojanOutboundTransports.Tls;

    public string TransportSecurity { get; init; } = string.Empty;

    public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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
}

public sealed record RuntimeSocksOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Socks;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 1080;

    public string Username { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }
}

public sealed record RuntimeShadowsocksOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Shadowsocks;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 8388;

    public string Cipher { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public bool UdpOverTcp { get; init; }

    public int UdpOverTcpVersion { get; init; }

    public int ConnectTimeoutSeconds { get; init; }
}

public sealed record RuntimeShadowsocks2022OutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Shadowsocks;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 8388;

    public string Method { get; init; } = string.Empty;

    public string Key { get; init; } = string.Empty;

    public bool UdpOverTcp { get; init; }

    public int UdpOverTcpVersion { get; init; }

    public int ConnectTimeoutSeconds { get; init; }
}

public sealed record RuntimeHttpOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Http;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 8080;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public string Transport { get; init; } = HttpOutboundTransports.Tcp;

    public string Username { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public IReadOnlyDictionary<string, string> Headers { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }

    public bool EnableTlsSessionResumption { get; init; }

    public bool SkipCertificateValidation { get; init; }
}

public sealed record RuntimeLoopbackOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Loopback;

    public string InboundTag { get; init; } = string.Empty;
}

public sealed record RuntimeVlessOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Vless;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public string Transport { get; init; } = VlessOutboundTransports.Tls;

    public string TransportSecurity { get; init; } = string.Empty;

    public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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
}

public sealed record RuntimeVmessOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Vmess;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 443;

    public string ServerName { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public string Transport { get; init; } = VmessOutboundTransports.Tls;

    public string TransportSecurity { get; init; } = string.Empty;

    public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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

    public required string UserUuid { get; init; }

    public string Security { get; init; } = VmessOutboundSecurityTypes.Auto;

    public bool AuthenticatedLength { get; init; } = true;

    public bool NoTerminationSignal { get; init; }

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }

    public bool EnableTlsSessionResumption { get; init; }

    public bool SkipCertificateValidation { get; init; }
}

public sealed record RuntimeOutboundSettingsCatalog
{
    public static RuntimeOutboundSettingsCatalog Empty { get; } = new();

    public IReadOnlyDictionary<string, IRuntimeOutboundOptions> SettingsByTag { get; init; }
        = new Dictionary<string, IRuntimeOutboundOptions>(StringComparer.OrdinalIgnoreCase);

    public bool TryGet(string? tag, out IRuntimeOutboundOptions settings)
    {
        if (!string.IsNullOrWhiteSpace(tag) &&
            SettingsByTag.TryGetValue(tag.Trim(), out var resolved))
        {
            settings = resolved;
            return true;
        }

        settings = default!;
        return false;
    }

    public bool TryGet<TOptions>(string? tag, out TOptions settings)
        where TOptions : class, IRuntimeOutboundOptions
    {
        if (TryGet(tag, out var resolved) &&
            resolved is TOptions typed)
        {
            settings = typed;
            return true;
        }

        settings = default!;
        return false;
    }

    public bool TryGetTrojan(string? tag, out RuntimeTrojanOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetSocks(string? tag, out RuntimeSocksOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetShadowsocks(string? tag, out RuntimeShadowsocksOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetShadowsocks2022(string? tag, out RuntimeShadowsocks2022OutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetHttp(string? tag, out RuntimeHttpOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetLoopback(string? tag, out RuntimeLoopbackOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetDns(string? tag, out RuntimeDnsOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetVless(string? tag, out RuntimeVlessOutboundOptions settings)
        => TryGet(tag, out settings);

    public bool TryGetVmess(string? tag, out RuntimeVmessOutboundOptions settings)
        => TryGet(tag, out settings);

    public static RuntimeOutboundSettingsCatalog Create(IEnumerable<IRuntimeOutboundOptions> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var byTag = new Dictionary<string, IRuntimeOutboundOptions>(StringComparer.OrdinalIgnoreCase);
        foreach (var option in settings)
        {
            if (option is null || string.IsNullOrWhiteSpace(option.Tag))
            {
                continue;
            }

            var normalized = Normalize(option);
            byTag[normalized.Tag.Trim()] = normalized;
        }

        return new RuntimeOutboundSettingsCatalog
        {
            SettingsByTag = byTag
        };
    }

    public static RuntimeOutboundSettingsCatalog Create(
        IEnumerable<RuntimeTrojanOutboundOptions> trojanSettings,
        IEnumerable<RuntimeVlessOutboundOptions>? vlessSettings = null,
        IEnumerable<RuntimeVmessOutboundOptions>? vmessSettings = null)
    {
        ArgumentNullException.ThrowIfNull(trojanSettings);
        return Create(
            trojanSettings.Cast<IRuntimeOutboundOptions>()
                .Concat(vlessSettings ?? Array.Empty<RuntimeVlessOutboundOptions>())
                .Concat(vmessSettings ?? Array.Empty<RuntimeVmessOutboundOptions>()));
    }

    private static IRuntimeOutboundOptions Normalize(IRuntimeOutboundOptions option)
        => option switch
        {
            RuntimeTrojanOutboundOptions settings => NormalizeTrojan(settings),
            RuntimeSocksOutboundOptions settings => NormalizeSocks(settings),
            RuntimeShadowsocksOutboundOptions settings => ShadowsocksOutboundOptionsCompiler.Compile(settings),
            RuntimeShadowsocks2022OutboundOptions settings => ShadowsocksOutboundOptionsCompiler.Compile(settings),
            RuntimeHttpOutboundOptions settings => NormalizeHttp(settings),
            RuntimeLoopbackOutboundOptions settings => NormalizeLoopback(settings),
            RuntimeDnsOutboundOptions settings => NormalizeDns(settings),
            RuntimeVlessOutboundOptions settings => NormalizeVless(settings),
            RuntimeVmessOutboundOptions settings => NormalizeVmess(settings),
            _ => option
        };

    private static RuntimeTrojanOutboundOptions NormalizeTrojan(RuntimeTrojanOutboundOptions settings)
        => ProxyOutboundOptionsCompiler.CompileTrojan(settings);

    private static RuntimeSocksOutboundOptions NormalizeSocks(RuntimeSocksOutboundOptions settings)
        => new()
        {
            Tag = settings.Tag.Trim(),
            ServerHost = settings.ServerHost.Trim(),
            ServerPort = settings.ServerPort > 0 ? settings.ServerPort : 1080,
            Username = settings.Username.Trim(),
            Password = settings.Password.Trim(),
            ConnectTimeoutSeconds = Math.Max(0, settings.ConnectTimeoutSeconds),
            HandshakeTimeoutSeconds = Math.Max(0, settings.HandshakeTimeoutSeconds)
        };

    private static RuntimeHttpOutboundOptions NormalizeHttp(RuntimeHttpOutboundOptions settings)
    {
        var transport = HttpOutboundTransports.Normalize(settings.Transport);
        return new RuntimeHttpOutboundOptions
        {
            Tag = settings.Tag.Trim(),
            ServerHost = settings.ServerHost.Trim(),
            ServerPort = settings.ServerPort > 0 ? settings.ServerPort : 8080,
            ServerName = settings.ServerName.Trim(),
            Fingerprint = NormalizeOptionalLowerValue(settings.Fingerprint),
            Transport = transport,
            Username = settings.Username.Trim(),
            Password = settings.Password.Trim(),
            Headers = CloneHeaders(settings.Headers),
            ApplicationProtocols = NormalizeHttpApplicationProtocols(transport, settings.ApplicationProtocols),
            ConnectTimeoutSeconds = Math.Max(0, settings.ConnectTimeoutSeconds),
            HandshakeTimeoutSeconds = Math.Max(0, settings.HandshakeTimeoutSeconds),
            EnableTlsSessionResumption = settings.EnableTlsSessionResumption,
            SkipCertificateValidation = settings.SkipCertificateValidation
        };
    }

    private static RuntimeLoopbackOutboundOptions NormalizeLoopback(RuntimeLoopbackOutboundOptions settings)
        => new()
        {
            Tag = settings.Tag.Trim(),
            InboundTag = settings.InboundTag.Trim()
        };

    private static RuntimeDnsOutboundOptions NormalizeDns(RuntimeDnsOutboundOptions settings)
        => new()
        {
            Tag = settings.Tag.Trim(),
            ServerNetwork = NormalizeDnsServerNetwork(settings.ServerNetwork),
            ServerHost = settings.ServerHost.Trim(),
            ServerPort = settings.ServerPort is > 0 and <= 65535 ? settings.ServerPort : 0,
            NonIpQuery = DnsOutboundNonIpQueryModes.Normalize(settings.NonIpQuery),
            BlockTypes = settings.BlockTypes
                .Where(static value => value > 0)
                .Distinct()
                .ToArray()
        };

    private static RuntimeVlessOutboundOptions NormalizeVless(RuntimeVlessOutboundOptions settings)
        => ProxyOutboundOptionsCompiler.CompileVless(settings);

    private static RuntimeVmessOutboundOptions NormalizeVmess(RuntimeVmessOutboundOptions settings)
        => ProxyOutboundOptionsCompiler.CompileVmess(settings);

    private static IReadOnlyDictionary<string, string> CloneHeaders(IReadOnlyDictionary<string, string> headers)
        => headers.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value,
            StringComparer.OrdinalIgnoreCase);

    private static IReadOnlyList<string> NormalizeApplicationProtocols(IReadOnlyList<string> values)
        => values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> NormalizeSenderApplicationProtocols(
        string transport,
        IReadOnlyList<string> values)
        => TrojanOutboundTransports.Normalize(transport) switch
        {
            TrojanOutboundTransports.Tls => NormalizeApplicationProtocols(values),
            TrojanOutboundTransports.Grpc => ["h2"],
            TrojanOutboundTransports.Wss or TrojanOutboundTransports.HttpUpgradeTls => ["http/1.1"],
            _ => Array.Empty<string>()
        };

    private static IReadOnlyList<string> NormalizeHttpApplicationProtocols(
        string transport,
        IReadOnlyList<string> values)
        => HttpOutboundTransports.Normalize(transport) switch
        {
            HttpOutboundTransports.Tls => NormalizeApplicationProtocols(values),
            _ => Array.Empty<string>()
        };

    private static string NormalizeDnsServerNetwork(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return RoutingNetworks.Normalize(value) switch
        {
            RoutingNetworks.Tcp => RoutingNetworks.Tcp,
            RoutingNetworks.Udp => RoutingNetworks.Udp,
            _ => string.Empty
        };
    }

    private static string NormalizeSenderWebSocketPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : $"/{normalized}";
    }

    private static string NormalizeOptionalLowerValue(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();

}

public sealed record RuntimeStatusSnapshot
{
    public int Revision { get; init; }

    public RuntimeState State { get; init; } = RuntimeState.Stopped;

    public string Message { get; init; } = string.Empty;

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;

    public int ActiveSessions { get; init; }

    public int KnownUsers { get; init; }

    public IReadOnlyList<RuntimeListenerStatus> Listeners { get; init; } = Array.Empty<RuntimeListenerStatus>();

    public IReadOnlyList<RuntimeStrategyStatus> Strategies { get; init; } = Array.Empty<RuntimeStrategyStatus>();
}

public sealed record RuntimeListenerStatus
{
    public required string Tag { get; init; }

    public required string Protocol { get; init; }

    public string Transport { get; init; } = string.Empty;

    public required ListenerBinding Binding { get; init; }

    public bool IsProxyInbound { get; init; }

    public RuntimeState State { get; init; } = RuntimeState.Stopped;

    public string Message { get; init; } = string.Empty;

    public DateTimeOffset? LastStartedAt { get; init; }

    public DateTimeOffset UpdatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed record RuntimeStrategyStatus
{
    public required string Tag { get; init; }

    public required string Protocol { get; init; }

    public string SelectedTag { get; init; } = string.Empty;

    public string ProbeUrl { get; init; } = StrategyOutboundDefaults.ProbeUrl;

    public IReadOnlyList<string> CandidateTags { get; init; } = Array.Empty<string>();

    public IReadOnlyList<StrategyCandidateProbeResult> ProbeResults { get; init; } = Array.Empty<StrategyCandidateProbeResult>();
}

public abstract record RuntimeEvent
{
    public int Revision { get; init; }

    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    public string Message { get; init; } = string.Empty;
}

public sealed record RuntimeConnectionAccessedEvent : RuntimeEvent
{
    public required string Protocol { get; init; }

    public string Tag { get; init; } = string.Empty;

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; }

    public string Network { get; init; } = string.Empty;
}

public sealed record RuntimeStateChangedEvent : RuntimeEvent
{
    public RuntimeState State { get; init; } = RuntimeState.Stopped;
}

public sealed record RuntimeListenerStartedEvent : RuntimeEvent
{
    public required RuntimeListenerStatus Listener { get; init; }
}

public sealed record RuntimeListenerFaultedEvent : RuntimeEvent
{
    public required string TaskName { get; init; }

    public IReadOnlyList<RuntimeListenerStatus> Listeners { get; init; } = Array.Empty<RuntimeListenerStatus>();
}

public sealed record RuntimeConnectionErrorEvent : RuntimeEvent
{
    public required string Protocol { get; init; }

    public string Tag { get; init; } = string.Empty;

    public bool IsProxyInbound { get; init; }

    public string? RemoteEndPoint { get; init; }

    public Exception? Exception { get; init; }
}

public sealed record RuntimeClientHelloRejectedEvent : RuntimeEvent
{
    public required string Protocol { get; init; }

    public string? RemoteEndPoint { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public string Ja3Hash { get; init; } = string.Empty;

    public string Reason { get; init; } = string.Empty;
}

public sealed record RuntimeUnknownServerNameRejectedEvent : RuntimeEvent
{
    public required string Protocol { get; init; }

    public string? RemoteEndPoint { get; init; }

    public string RequestedServerName { get; init; } = string.Empty;
}

public sealed record RuntimeFaultedEvent : RuntimeEvent
{
    public required string TaskName { get; init; }

    public Exception? Exception { get; init; }
}

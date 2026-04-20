namespace NodePanel.Core.Runtime;

public sealed record Shadowsocks2022OutboundSettings
{
    public required string Tag { get; init; }

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string TargetStrategy { get; init; } = OutboundTargetStrategies.AsIs;

    public string ProxyOutboundTag { get; init; } = string.Empty;

    public required string ServerHost { get; init; }

    public int ServerPort { get; init; } = 8388;

    public string Method { get; init; } = string.Empty;

    public string Key { get; init; } = string.Empty;

    public bool UdpOverTcp { get; init; }

    public int UdpOverTcpVersion { get; init; }

    public int ConnectTimeoutSeconds { get; init; }
}

public interface IShadowsocks2022OutboundSettingsProvider
{
    bool TryResolve(DispatchContext context, out Shadowsocks2022OutboundSettings settings);
}

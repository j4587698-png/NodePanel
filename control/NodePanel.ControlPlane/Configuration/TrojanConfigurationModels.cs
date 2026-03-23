using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public sealed record TrojanInboundLimits : ITrojanInboundLimits
{
    public long GlobalBytesPerSecond { get; init; }

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public sealed record TrojanUserConfig : ITrojanUserDefinition, IVlessUserDefinition, IVmessUserDefinition
{
    public string UserId { get; init; } = string.Empty;

    public string Uuid { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

public sealed record TrojanFallbackConfig : ITrojanFallbackDefinition
{
    public string Name { get; init; } = string.Empty;

    public string Alpn { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public string Type { get; init; } = "tcp";

    public string Dest { get; init; } = string.Empty;

    public int ProxyProtocolVersion { get; init; }
}

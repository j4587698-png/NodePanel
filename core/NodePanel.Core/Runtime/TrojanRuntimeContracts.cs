using System.Net;

namespace NodePanel.Core.Runtime;

public interface ITrojanInboundLimits
{
    long GlobalBytesPerSecond { get; }

    int ConnectTimeoutSeconds { get; }

    int ConnectionIdleSeconds { get; }

    int UplinkOnlySeconds { get; }

    int DownlinkOnlySeconds { get; }
}

public interface ITrojanUserDefinition : IRuntimeUserDefinition
{
    string Password { get; }
}

public interface ITrojanFallbackDefinition
{
    string Name { get; }

    string Alpn { get; }

    string Path { get; }

    string Type { get; }

    string Dest { get; }

    int ProxyProtocolVersion { get; }
}

public interface ITrojanInboundConnectionOptions
{
    string InboundTag { get; }

    int HandshakeTimeoutSeconds { get; }

    int ConnectTimeoutSeconds { get; }

    int ConnectionIdleSeconds { get; }

    int UplinkOnlySeconds { get; }

    int DownlinkOnlySeconds { get; }

    bool UseCone { get; }

    bool ReceiveOriginalDestination { get; }

    string ServerName { get; }

    string Alpn { get; }

    EndPoint? RemoteEndPoint { get; }

    EndPoint? LocalEndPoint { get; }

    EndPoint? OriginalDestinationEndPoint { get; }

    ITrojanSniffingDefinition Sniffing { get; }

    bool TryAuthenticate(string passwordHash, out TrojanUser? user);

    IReadOnlyList<ITrojanFallbackDefinition> Fallbacks { get; }
}

public static class TrojanOutboundTransports
{
    public const string Tcp = "tcp";
    public const string Tls = "tls";
    public const string Ws = "ws";
    public const string Wss = "wss";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Tls
            : value.Trim().ToLowerInvariant();
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

    public string Transport { get; init; } = TrojanOutboundTransports.Tls;

    public string WebSocketPath { get; init; } = "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketEarlyDataBytes { get; init; }

    public int WebSocketHeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public required string Password { get; init; }

    public int ConnectTimeoutSeconds { get; init; }

    public int HandshakeTimeoutSeconds { get; init; }

    public bool SkipCertificateValidation { get; init; }
}

public interface ITrojanOutboundSettingsProvider
{
    bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings);
}

public sealed record UserTrafficSnapshot
{
    public required string UserId { get; init; }

    public required long UploadBytes { get; init; }

    public required long DownloadBytes { get; init; }
}

internal sealed class DefaultTrojanInboundConnectionOptions : ITrojanInboundConnectionOptions
{
    public static ITrojanInboundConnectionOptions Instance { get; } = new DefaultTrojanInboundConnectionOptions();

    private DefaultTrojanInboundConnectionOptions()
    {
    }

    public string InboundTag => string.Empty;

    public int HandshakeTimeoutSeconds => 60;

    public int ConnectTimeoutSeconds => 10;

    public int ConnectionIdleSeconds => 300;

    public int UplinkOnlySeconds => 1;

    public int DownlinkOnlySeconds => 1;

    public bool UseCone => true;

    public bool ReceiveOriginalDestination => false;

    public string ServerName => string.Empty;

    public string Alpn => string.Empty;

    public EndPoint? RemoteEndPoint => null;

    public EndPoint? LocalEndPoint => null;

    public EndPoint? OriginalDestinationEndPoint => null;

    public ITrojanSniffingDefinition Sniffing => TrojanSniffingRuntime.Disabled;

    public bool TryAuthenticate(string passwordHash, out TrojanUser? user)
    {
        user = null;
        return false;
    }

    public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks => Array.Empty<ITrojanFallbackDefinition>();
}

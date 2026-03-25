using System.Net;

namespace NodePanel.Core.Runtime;

public static class LocalInboundProtocols
{
    public const string Socks = "socks";
    public const string Http = "http";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Socks
            : value.Trim().ToLowerInvariant() switch
            {
                Http => Http,
                _ => Socks
            };
}

public sealed record LocalProxyServerLimits
{
    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public sealed record LocalProxyListenerDefinition
{
    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 10;
}

public sealed record LocalProxyServerCallbacks
{
    public Action<LocalProxyListenerDefinition>? ListenerStarted { get; init; }

    public Action<LocalProxyConnectionErrorContext>? ConnectionError { get; init; }
}

public sealed record LocalProxyConnectionErrorContext
{
    public required string Protocol { get; init; }

    public required string InboundTag { get; init; }

    public Exception Exception { get; init; } = new InvalidOperationException("Local proxy connection failed.");

    public EndPoint? RemoteEndPoint { get; init; }
}

public sealed record Socks5LocalProxyServerOptions
{
    public IReadOnlyList<LocalProxyListenerDefinition> Listeners { get; init; } = Array.Empty<LocalProxyListenerDefinition>();

    public LocalProxyServerLimits Limits { get; init; } = new();

    public LocalProxyServerCallbacks Callbacks { get; init; } = new();
}

public sealed record HttpLocalProxyServerOptions
{
    public IReadOnlyList<LocalProxyListenerDefinition> Listeners { get; init; } = Array.Empty<LocalProxyListenerDefinition>();

    public LocalProxyServerLimits Limits { get; init; } = new();

    public LocalProxyServerCallbacks Callbacks { get; init; } = new();
}

internal sealed record LocalProxyConnectionOptions : ITrojanInboundConnectionOptions
{
    public required string InboundTag { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public bool ReceiveOriginalDestination => false;

    public string ServerName => string.Empty;

    public string Alpn => string.Empty;

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public EndPoint? OriginalDestinationEndPoint => null;

    public ITrojanSniffingDefinition Sniffing => TrojanSniffingRuntime.Disabled;

    public bool TryAuthenticate(string passwordHash, out TrojanUser? user)
    {
        user = null;
        return false;
    }

    public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks => Array.Empty<ITrojanFallbackDefinition>();
}

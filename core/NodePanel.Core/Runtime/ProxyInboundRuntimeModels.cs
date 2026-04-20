using System.Net;

namespace NodePanel.Core.Runtime;

public static class ProxyInboundProtocols
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

public record ProxyInboundServerLimits
{
    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public record ProxyInboundListenerDefinition
{
    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public int UserLevel { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public RuntimeSniffingOptions Sniffing { get; init; } = new();

    public bool AllowTransparent { get; init; }
}

public record ProxyInboundServerCallbacks
{
    public Action<ProxyInboundListenerDefinition>? ListenerStarted { get; init; }

    public Action<ProxyInboundConnectionErrorContext>? ConnectionError { get; init; }
}

public record ProxyInboundConnectionErrorContext
{
    public required string Protocol { get; init; }

    public required string InboundTag { get; init; }

    public Exception Exception { get; init; } = new InvalidOperationException("Proxy inbound connection failed.");

    public EndPoint? RemoteEndPoint { get; init; }
}

public sealed record Socks5LocalUserCredential
{
    public string Username { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;
}

public sealed record Socks5LocalAuthenticationOptions
{
    public static Socks5LocalAuthenticationOptions Disabled { get; } = new();

    public IReadOnlyDictionary<string, string> Accounts { get; init; }
        = new Dictionary<string, string>(StringComparer.Ordinal);

    public bool Enabled => Accounts.Count > 0;

    public bool TryAuthenticate(string username, string password)
        => Accounts.TryGetValue(username, out var expectedPassword) &&
           string.Equals(expectedPassword, password, StringComparison.Ordinal);

    public static Socks5LocalAuthenticationOptions Create(IEnumerable<Socks5LocalUserCredential> credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        var accounts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var credential in credentials)
        {
            if (credential is null ||
                string.IsNullOrEmpty(credential.Username))
            {
                continue;
            }

            accounts[credential.Username] = credential.Password ?? string.Empty;
        }

        return accounts.Count == 0
            ? Disabled
            : new Socks5LocalAuthenticationOptions
            {
                Accounts = accounts
            };
    }
}

public record SocksInboundServerOptions
{
    public IReadOnlyList<ProxyInboundListenerDefinition> Listeners { get; init; } = Array.Empty<ProxyInboundListenerDefinition>();

    public ProxyInboundServerLimits Limits { get; init; } = new();

    public bool UseCone { get; init; } = true;

    public IReadOnlyDictionary<string, Socks5LocalAuthenticationOptions> AuthenticationsByTag { get; init; }
        = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);

    public ProxyInboundServerCallbacks Callbacks { get; init; } = new();
}

public record HttpInboundServerOptions
{
    public IReadOnlyList<ProxyInboundListenerDefinition> Listeners { get; init; } = Array.Empty<ProxyInboundListenerDefinition>();

    public ProxyInboundServerLimits Limits { get; init; } = new();

    public IReadOnlyDictionary<string, Socks5LocalAuthenticationOptions> AuthenticationsByTag { get; init; }
        = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);

    public ProxyInboundServerCallbacks Callbacks { get; init; } = new();
}

internal record ProxyInboundConnectionOptions : IRuntimeInboundConnectionOptions
{
    public required string InboundTag { get; init; }

    public int UserLevel { get; init; }

    public string UserId { get; init; } = string.Empty;

    public string ScopedUserId { get; init; } = string.Empty;

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public bool AllowTransparent { get; init; }

    public bool ReceiveOriginalDestination => false;

    public string ServerName => string.Empty;

    public string Alpn => string.Empty;

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public EndPoint? OriginalDestinationEndPoint => null;

    public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;
}

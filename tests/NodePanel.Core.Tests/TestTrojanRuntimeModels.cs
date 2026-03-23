using System.Net;
using NodePanel.Core.Cryptography;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

internal sealed record TestTrojanFallback : ITrojanFallbackDefinition
{
    public string Name { get; init; } = string.Empty;

    public string Alpn { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public string Type { get; init; } = "tcp";

    public string Dest { get; init; } = string.Empty;

    public int ProxyProtocolVersion { get; init; }
}

internal sealed record TestTrojanConnectionOptions : ITrojanInboundConnectionOptions
{
    public string InboundTag { get; init; } = string.Empty;

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public bool ReceiveOriginalDestination { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public string Alpn { get; init; } = string.Empty;

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public EndPoint? OriginalDestinationEndPoint { get; init; }

    public ITrojanSniffingDefinition Sniffing { get; init; } = TrojanSniffingRuntime.Disabled;

    public IReadOnlyDictionary<string, TrojanUser> UsersByHash { get; init; }
        = new Dictionary<string, TrojanUser>(StringComparer.Ordinal);

    public bool TryAuthenticate(string passwordHash, out TrojanUser? user)
        => UsersByHash.TryGetValue(passwordHash, out user);

    public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks { get; init; } = Array.Empty<ITrojanFallbackDefinition>();

    public static IReadOnlyDictionary<string, TrojanUser> CreateUsers(params (string UserId, string Password, long BytesPerSecond)[] users)
        => CreateUsersWithDeviceLimit(
            users.Select(static user => (user.UserId, user.Password, user.BytesPerSecond, DeviceLimit: 0)).ToArray());

    public static IReadOnlyDictionary<string, TrojanUser> CreateUsersWithDeviceLimit(params (string UserId, string Password, long BytesPerSecond, int DeviceLimit)[] users)
        => users.ToDictionary(
            static user => TrojanPassword.ComputeHash(user.Password),
            static user =>
            {
                var passwordHash = TrojanPassword.ComputeHash(user.Password);
                return new TrojanUser
                {
                    UserId = user.UserId,
                    PasswordHash = passwordHash,
                    BytesPerSecond = user.BytesPerSecond,
                    DeviceLimit = Math.Max(0, user.DeviceLimit)
                };
            },
            StringComparer.Ordinal);
}

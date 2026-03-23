using System.Net;

namespace NodePanel.Core.Runtime;

internal sealed record VlessInboundSessionOptions : ITrojanInboundConnectionOptions
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

    public IReadOnlyDictionary<string, VlessUser> UsersByUuid { get; init; }
        = new Dictionary<string, VlessUser>(StringComparer.OrdinalIgnoreCase);

    public bool TryResolveUser(string uuid, out VlessUser? user)
        => UsersByUuid.TryGetValue(uuid, out user);

    public bool TryAuthenticate(string passwordHash, out TrojanUser? user)
    {
        user = null;
        return false;
    }

    public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks => Array.Empty<ITrojanFallbackDefinition>();
}

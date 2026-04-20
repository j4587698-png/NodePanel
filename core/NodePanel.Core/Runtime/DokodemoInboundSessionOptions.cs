using System.Net;

namespace NodePanel.Core.Runtime;

internal sealed record DokodemoInboundSessionOptions : IRuntimeInboundConnectionOptions
{
    public string InboundTag { get; init; } = string.Empty;

    public string Network { get; init; } = RoutingNetworks.Tcp;

    public string DestinationHost { get; init; } = string.Empty;

    public int DestinationPort { get; init; }

    public IReadOnlyDictionary<string, string> PortMap { get; init; }
        = new Dictionary<string, string>(StringComparer.Ordinal);

    public int UserLevel { get; init; }

    public int Mark { get; init; }

    public bool FollowRedirect { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 10;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public bool ReceiveOriginalDestination => FollowRedirect;

    public string ServerName => string.Empty;

    public string Alpn => string.Empty;

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public EndPoint? OriginalDestinationEndPoint { get; init; }

    public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;
}

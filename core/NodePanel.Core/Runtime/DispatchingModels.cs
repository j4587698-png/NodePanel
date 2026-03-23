using System.Net;

namespace NodePanel.Core.Runtime;

public enum DispatchNetwork
{
    Tcp = 1,
    Udp = 2
}

public sealed record DispatchDestination
{
    public required string Host { get; init; }

    public required int Port { get; init; }

    public DispatchNetwork Network { get; init; } = DispatchNetwork.Tcp;
}

public sealed record DispatchContext
{
    public string InboundProtocol { get; init; } = string.Empty;

    public string InboundTag { get; init; } = string.Empty;

    public string DetectedProtocol { get; init; } = string.Empty;

    public string DetectedDomain { get; init; } = string.Empty;

    public string Network { get; init; } = string.Empty;

    public string UserId { get; init; } = string.Empty;

    public string OutboundTag { get; init; } = string.Empty;

    public string OriginalDestinationHost { get; init; } = string.Empty;

    public int OriginalDestinationPort { get; init; }

    public string InboundOriginalDestinationHost { get; init; } = string.Empty;

    public int InboundOriginalDestinationPort { get; init; }

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public EndPoint? SourceEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }
}

public sealed record DispatchDatagram
{
    public required string SourceHost { get; init; }

    public required int SourcePort { get; init; }

    public required byte[] Payload { get; init; }
}

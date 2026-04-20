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

public sealed record DispatchContent
{
    private static readonly IReadOnlyDictionary<string, string> EmptyAttributes =
        new Dictionary<string, string>(StringComparer.Ordinal);

    public static DispatchContent Empty { get; } = new();

    public string Protocol { get; init; } = string.Empty;

    public IReadOnlyDictionary<string, string> Attributes { get; init; } = EmptyAttributes;

    public bool SkipDnsResolve { get; init; }
}

public sealed record DispatchContext
{
    public string InboundProtocol { get; init; } = string.Empty;

    public string InboundKind { get; init; } = string.Empty;

    public string InboundTag { get; init; } = string.Empty;

    public int InboundUserLevel { get; init; }

    public int DispatchDepth { get; init; }

    public bool SkipTransportFlowControl { get; init; }

    public string DetectedProtocol { get; init; } = string.Empty;

    public string DetectedDomain { get; init; } = string.Empty;

    public string Network { get; init; } = string.Empty;

    public string InboundSourceNetwork { get; init; } = string.Empty;

    public string UserId { get; init; } = string.Empty;

    public string ScopedUserId { get; init; } = string.Empty;

    public string ProcessName { get; init; } = string.Empty;

    public string ProcessPath { get; init; } = string.Empty;

    public bool ProcessIsCurrentExecutable { get; init; }

    public string OutboundTag { get; init; } = string.Empty;

    public string OriginalDestinationHost { get; init; } = string.Empty;

    public int OriginalDestinationPort { get; init; }

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; }

    public string RouteTargetHost { get; init; } = string.Empty;

    public int RouteTargetPort { get; init; }

    public string InboundOriginalDestinationHost { get; init; } = string.Empty;

    public int InboundOriginalDestinationPort { get; init; }

    public IReadOnlyList<IPAddress> TargetAddresses { get; init; } = Array.Empty<IPAddress>();

    public IReadOnlyList<IPAddress> SourceAddresses { get; init; } = Array.Empty<IPAddress>();

    public IReadOnlyList<IPAddress> LocalAddresses { get; init; } = Array.Empty<IPAddress>();

    public int VlessRoutePort { get; init; }

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public byte[] InitialPayload { get; init; } = Array.Empty<byte>();

    public DispatchContent Content { get; init; } = DispatchContent.Empty;

    public EndPoint? SourceEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }
}

public sealed record OutboundRouteDecision
{
    public required string OutboundTag { get; init; }

    public string RuleTag { get; init; } = string.Empty;

    public IReadOnlyList<string> OutboundGroupTags { get; init; } = Array.Empty<string>();
}

public sealed record ResolvedOutboundRoute
{
    public required IOutboundHandler Handler { get; init; }

    public required DispatchContext Context { get; init; }

    public string OutboundTag { get; init; } = string.Empty;

    public string RuleTag { get; init; } = string.Empty;

    public IReadOnlyList<string> OutboundGroupTags { get; init; } = Array.Empty<string>();
}

public sealed record DispatchDatagram
{
    public required string SourceHost { get; init; }

    public required int SourcePort { get; init; }

    public required byte[] Payload { get; init; }
}

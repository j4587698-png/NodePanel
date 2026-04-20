using System.Net;

namespace NodePanel.Core.Runtime;

internal static class RuntimeInboundDispatchContextFactory
{
    public static DispatchContext Create(
        string inboundProtocol,
        IRuntimeInboundConnectionOptions options,
        string inboundSourceNetwork,
        IRuntimeUserDefinition user,
        string network = "",
        string originalDestinationHost = "",
        int originalDestinationPort = 0,
        string detectedProtocol = "",
        string detectedDomain = "",
        DispatchContent? content = null,
        int vlessRoutePort = 0,
        EndPoint? sourceEndPoint = null,
        EndPoint? localEndPoint = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inboundProtocol);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(user);

        return CreateCore(
            inboundProtocol,
            options,
            Math.Max(options.UserLevel, user.Level),
            inboundSourceNetwork,
            network,
            user.UserId,
            RuntimeUserKeys.Get(user),
            originalDestinationHost,
            originalDestinationPort,
            detectedProtocol,
            detectedDomain,
            content,
            vlessRoutePort,
            sourceEndPoint,
            localEndPoint);
    }

    public static DispatchContext Create(
        string inboundProtocol,
        IRuntimeInboundConnectionOptions options,
        string inboundSourceNetwork,
        string userId = "",
        string scopedUserId = "",
        string network = "",
        string originalDestinationHost = "",
        int originalDestinationPort = 0,
        string detectedProtocol = "",
        string detectedDomain = "",
        DispatchContent? content = null,
        int vlessRoutePort = 0,
        EndPoint? sourceEndPoint = null,
        EndPoint? localEndPoint = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inboundProtocol);
        ArgumentNullException.ThrowIfNull(options);

        return CreateCore(
            inboundProtocol,
            options,
            Math.Max(0, options.UserLevel),
            inboundSourceNetwork,
            network,
            userId,
            scopedUserId,
            originalDestinationHost,
            originalDestinationPort,
            detectedProtocol,
            detectedDomain,
            content,
            vlessRoutePort,
            sourceEndPoint,
            localEndPoint);
    }

    public static string NormalizeAddress(IPAddress? address)
    {
        if (address is null)
        {
            return string.Empty;
        }

        return address.IsIPv4MappedToIPv6
            ? address.MapToIPv4().ToString()
            : address.ToString();
    }

    private static DispatchContext CreateCore(
        string inboundProtocol,
        IRuntimeInboundConnectionOptions options,
        int inboundUserLevel,
        string inboundSourceNetwork,
        string network,
        string userId,
        string scopedUserId,
        string originalDestinationHost,
        int originalDestinationPort,
        string detectedProtocol,
        string detectedDomain,
        DispatchContent? content,
        int vlessRoutePort,
        EndPoint? sourceEndPoint,
        EndPoint? localEndPoint)
    {
        var originalDestination = options.OriginalDestinationEndPoint as IPEndPoint;
        return new DispatchContext
        {
            InboundProtocol = inboundProtocol,
            InboundKind = inboundProtocol,
            InboundTag = options.InboundTag,
            InboundUserLevel = Math.Max(0, inboundUserLevel),
            Network = RoutingNetworks.Normalize(network),
            InboundSourceNetwork = RoutingNetworks.Normalize(inboundSourceNetwork),
            UserId = userId ?? string.Empty,
            ScopedUserId = scopedUserId ?? string.Empty,
            OriginalDestinationHost = originalDestinationHost ?? string.Empty,
            OriginalDestinationPort = Math.Max(0, originalDestinationPort),
            InboundOriginalDestinationHost = NormalizeAddress(originalDestination?.Address),
            InboundOriginalDestinationPort = originalDestination?.Port ?? 0,
            VlessRoutePort = Math.Max(0, vlessRoutePort),
            ConnectTimeoutSeconds = options.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = options.ConnectionIdleSeconds,
            UplinkOnlySeconds = options.UplinkOnlySeconds,
            DownlinkOnlySeconds = options.DownlinkOnlySeconds,
            UseCone = options.UseCone,
            DetectedProtocol = detectedProtocol ?? string.Empty,
            DetectedDomain = detectedDomain ?? string.Empty,
            Content = content ?? DispatchContent.Empty,
            SourceEndPoint = sourceEndPoint ?? options.RemoteEndPoint,
            LocalEndPoint = localEndPoint ?? options.LocalEndPoint
        };
    }
}

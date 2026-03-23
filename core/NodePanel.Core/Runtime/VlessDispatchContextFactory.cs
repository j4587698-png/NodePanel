using System.Net;

namespace NodePanel.Core.Runtime;

internal static class VlessDispatchContextFactory
{
    public static DispatchContext Create(VlessUser user, VlessInboundSessionOptions options)
    {
        var originalDestination = options.OriginalDestinationEndPoint as IPEndPoint;
        return new DispatchContext
        {
            InboundProtocol = InboundProtocols.Vless,
            InboundTag = options.InboundTag,
            UserId = user.UserId,
            InboundOriginalDestinationHost = originalDestination?.Address.ToString() ?? string.Empty,
            InboundOriginalDestinationPort = originalDestination?.Port ?? 0,
            ConnectTimeoutSeconds = options.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = options.ConnectionIdleSeconds,
            UplinkOnlySeconds = options.UplinkOnlySeconds,
            DownlinkOnlySeconds = options.DownlinkOnlySeconds,
            UseCone = options.UseCone,
            SourceEndPoint = options.RemoteEndPoint,
            LocalEndPoint = options.LocalEndPoint
        };
    }
}

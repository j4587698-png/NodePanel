using System.Net;

namespace NodePanel.Core.Runtime;

internal static class VmessDispatchContextFactory
{
    public static DispatchContext Create(VmessUser user, VmessInboundSessionOptions options)
    {
        var originalDestination = options.OriginalDestinationEndPoint as IPEndPoint;
        return new DispatchContext
        {
            InboundProtocol = InboundProtocols.Vmess,
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

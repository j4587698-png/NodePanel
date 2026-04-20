using System.Net;

namespace NodePanel.Core.Runtime;

internal static class VlessDispatchContextFactory
{
    public static DispatchContext Create(VlessUser user, VlessInboundSessionOptions options, int vlessRoutePort = 0)
        => RuntimeInboundDispatchContextFactory.Create(
            InboundProtocols.Vless,
            options,
            RoutingNetworks.Tcp,
            user,
            vlessRoutePort: vlessRoutePort);
}

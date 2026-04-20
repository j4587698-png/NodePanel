using System.Net;

namespace NodePanel.Core.Runtime;

internal static class VmessDispatchContextFactory
{
    public static DispatchContext Create(VmessUser user, VmessInboundSessionOptions options)
        => RuntimeInboundDispatchContextFactory.Create(
            InboundProtocols.Vmess,
            options,
            RoutingNetworks.Tcp,
            user);
}

using System.Net;

namespace NodePanel.Core.Runtime;

internal static class TrojanDispatchContextFactory
{
    public static DispatchContext Create(TrojanUser user, IRuntimeInboundConnectionOptions options)
        => RuntimeInboundDispatchContextFactory.Create(
            InboundProtocols.Trojan,
            options,
            RoutingNetworks.Tcp,
            user);
}

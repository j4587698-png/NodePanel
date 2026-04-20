using System.Net;

namespace NodePanel.Core.Runtime;

internal static class ShadowsocksDispatchContextFactory
{
    public static DispatchContext Create(ShadowsocksUser user, ShadowsocksInboundSessionOptions options)
        => RuntimeInboundDispatchContextFactory.Create(
            InboundProtocols.Shadowsocks,
            options,
            options.Network,
            user);

    public static DispatchContext Create(Shadowsocks2022User user, Shadowsocks2022InboundSessionOptions options)
        => RuntimeInboundDispatchContextFactory.Create(
            InboundProtocols.Shadowsocks,
            options,
            options.Network,
            user);
}

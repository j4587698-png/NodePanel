using System.Net;

namespace NodePanel.Core.Runtime;

internal static class DokodemoDispatchContextFactory
{
    public static DispatchContext Create(
        DokodemoInboundSessionOptions options,
        DispatchDestination? destination = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        var originalDestination = options.OriginalDestinationEndPoint as IPEndPoint;
        return RuntimeInboundDispatchContextFactory.Create(
            InboundProtocols.DokodemoDoor,
            options,
            options.Network,
            originalDestinationHost: destination?.Host ?? RuntimeInboundDispatchContextFactory.NormalizeAddress(originalDestination?.Address),
            originalDestinationPort: destination?.Port ?? originalDestination?.Port ?? 0);
    }
}

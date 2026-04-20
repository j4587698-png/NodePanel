using System.Net;

namespace NodePanel.Core.Runtime;

internal static class OutboundClientDialContext
{
    public static DispatchContext Resolve(
        DispatchContext context,
        EndPoint? sourceEndPoint,
        EndPoint? localEndPoint)
    {
        ArgumentNullException.ThrowIfNull(context);

        var effectiveSourceEndPoint = sourceEndPoint ?? context.SourceEndPoint;
        var effectiveLocalEndPoint = localEndPoint ?? context.LocalEndPoint;
        if (ReferenceEquals(effectiveSourceEndPoint, context.SourceEndPoint) &&
            ReferenceEquals(effectiveLocalEndPoint, context.LocalEndPoint))
        {
            return context;
        }

        return context with
        {
            SourceEndPoint = effectiveSourceEndPoint,
            LocalEndPoint = effectiveLocalEndPoint
        };
    }
}

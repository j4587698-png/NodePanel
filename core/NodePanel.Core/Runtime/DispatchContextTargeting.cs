namespace NodePanel.Core.Runtime;

internal static class DispatchContextTargeting
{
    public static DispatchContext SetOriginalAndTarget(
        DispatchContext context,
        DispatchDestination destination)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        return context with
        {
            OriginalDestinationHost = destination.Host,
            OriginalDestinationPort = destination.Port,
            TargetHost = destination.Host,
            TargetPort = destination.Port
        };
    }

    public static DispatchContext SetTarget(
        DispatchContext context,
        DispatchDestination destination)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);

        return context with
        {
            TargetHost = destination.Host,
            TargetPort = destination.Port
        };
    }

    public static DispatchContext ApplySniffing(
        DispatchContext context,
        RuntimeSniffingDecision sniffing,
        byte[]? initialPayload = null)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(sniffing);

        var updated = context with
        {
            DetectedProtocol = string.IsNullOrWhiteSpace(sniffing.Protocol)
                ? context.DetectedProtocol
                : sniffing.Protocol,
            DetectedDomain = string.IsNullOrWhiteSpace(sniffing.Domain)
                ? context.DetectedDomain
                : sniffing.Domain,
            Content = MergeContent(
                context.Content,
                sniffing.Content,
                sniffing.Protocol),
            RouteTargetHost = sniffing.RouteTarget?.Host ??
                              (sniffing.OverrideMatched ? string.Empty : context.RouteTargetHost),
            RouteTargetPort = sniffing.RouteTarget?.Port ??
                              (sniffing.OverrideMatched ? 0 : context.RouteTargetPort)
        };

        if (initialPayload is not { Length: > 0 })
        {
            return updated;
        }

        return updated with
        {
            InitialPayload = initialPayload
        };
    }

    private static DispatchContent MergeContent(
        DispatchContent current,
        DispatchContent sniffed,
        string sniffedProtocol)
    {
        var effectiveProtocol = !string.IsNullOrWhiteSpace(sniffed.Protocol)
            ? sniffed.Protocol
            : !string.IsNullOrWhiteSpace(sniffedProtocol)
                ? sniffedProtocol
                : current.Protocol;
        var skipDnsResolve = current.SkipDnsResolve || sniffed.SkipDnsResolve;

        if (string.Equals(current.Protocol, effectiveProtocol, StringComparison.Ordinal) &&
            sniffed.Attributes.Count == 0 &&
            !sniffed.SkipDnsResolve)
        {
            return current;
        }

        Dictionary<string, string>? attributes = null;
        if (current.Attributes.Count > 0 || sniffed.Attributes.Count > 0)
        {
            attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (key, value) in current.Attributes)
            {
                if (!string.IsNullOrWhiteSpace(key))
                {
                    attributes[key] = value ?? string.Empty;
                }
            }

            foreach (var (key, value) in sniffed.Attributes)
            {
                if (!string.IsNullOrWhiteSpace(key))
                {
                    attributes[key] = value ?? string.Empty;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(effectiveProtocol) &&
            (attributes is null || attributes.Count == 0) &&
            !skipDnsResolve)
        {
            return DispatchContent.Empty;
        }

        return new DispatchContent
        {
            Protocol = effectiveProtocol ?? string.Empty,
            Attributes = attributes ?? new Dictionary<string, string>(StringComparer.Ordinal),
            SkipDnsResolve = skipDnsResolve
        };
    }
}

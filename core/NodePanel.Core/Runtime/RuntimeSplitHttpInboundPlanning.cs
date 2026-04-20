namespace NodePanel.Core.Runtime;

internal static class RuntimeSplitHttpInboundPlanning
{
    private static readonly IReadOnlyList<string> DefaultApplicationProtocols = ["http/1.1", "h2"];
    private static readonly IReadOnlyList<string> Http3OnlyApplicationProtocols = ["h3"];

    public static IReadOnlyList<string> NormalizeApplicationProtocols(
        IReadOnlyList<string> values,
        Func<IReadOnlyList<string>, IReadOnlyList<string>> normalizeApplicationProtocols)
    {
        var normalized = normalizeApplicationProtocols(values);
        return IsHttp3Only(normalized)
            ? Http3OnlyApplicationProtocols
            : DefaultApplicationProtocols;
    }

    public static void AddListenerApplicationProtocols<TInbound>(
        IReadOnlyList<TInbound> inbounds,
        Func<TInbound, string> securityTypeSelector,
        Func<TInbound, string> transportProtocolSelector,
        Func<TInbound, IReadOnlyList<string>> applicationProtocolsSelector,
        Func<string, bool> isTlsLikeSecurity,
        Func<string, bool> isSplitHttpTransport,
        Action<string> addApplicationProtocol)
    {
        if (!inbounds.Any(inbound =>
                isTlsLikeSecurity(securityTypeSelector(inbound)) &&
                isSplitHttpTransport(transportProtocolSelector(inbound))))
        {
            return;
        }

        if (inbounds.Any(inbound =>
                isTlsLikeSecurity(securityTypeSelector(inbound)) &&
                isSplitHttpTransport(transportProtocolSelector(inbound)) &&
                IsHttp3Only(applicationProtocolsSelector(inbound))))
        {
            addApplicationProtocol("h3");
            return;
        }

        addApplicationProtocol("http/1.1");
        addApplicationProtocol("h2");
    }

    public static bool TryValidateSharedBinding<TInbound>(
        string protocolName,
        string bindingKey,
        IReadOnlyList<TInbound> inbounds,
        Func<TInbound, string> securityTypeSelector,
        Func<TInbound, string> transportProtocolSelector,
        Func<TInbound, IReadOnlyList<string>> applicationProtocolsSelector,
        Func<string, bool> isTlsLikeSecurity,
        Func<string, bool> isSplitHttpTransport,
        out string? error)
    {
        var hasSplitHttpH3Only = inbounds.Any(inbound =>
            isTlsLikeSecurity(securityTypeSelector(inbound)) &&
            isSplitHttpTransport(transportProtocolSelector(inbound)) &&
            IsHttp3Only(applicationProtocolsSelector(inbound)));

        if (!hasSplitHttpH3Only)
        {
            error = null;
            return true;
        }

        if (inbounds.Any(inbound =>
                isTlsLikeSecurity(securityTypeSelector(inbound)) &&
                !isSplitHttpTransport(transportProtocolSelector(inbound))))
        {
            error = $"{protocolName} listener {bindingKey} mixes SplitHTTP h3-only with TCP-based transports on the same binding.";
            return false;
        }

        error = null;
        return true;
    }

    public static bool IsHttp3Only(IReadOnlyList<string> applicationProtocols)
        => applicationProtocols.Count == 1 &&
           string.Equals(applicationProtocols[0], "h3", StringComparison.OrdinalIgnoreCase);
}

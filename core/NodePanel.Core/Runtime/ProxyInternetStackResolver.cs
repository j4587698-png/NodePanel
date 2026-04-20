namespace NodePanel.Core.Runtime;

public readonly record struct ProxyInternetStack(
    string Transport,
    string TransportProtocol,
    string SecurityType)
{
    public bool IsGrpcTransport
        => string.Equals(TransportProtocol, RuntimeInternetTransportProtocols.Grpc, StringComparison.Ordinal);

    public bool UsesPathBasedTransport
        => TransportProtocol is
            RuntimeInternetTransportProtocols.Ws or
            RuntimeInternetTransportProtocols.HttpUpgrade or
            RuntimeInternetTransportProtocols.SplitHttp;

    internal RuntimeInternetStack ToRuntimeInternetStack()
        => RuntimeInternetStack.Create(TransportProtocol, SecurityType);
}

public static class ProxyInternetStackResolver
{
    public static ProxyInternetStack Resolve(string? transport, string? transportSecurity)
    {
        if (!TryResolve(transport, transportSecurity, out var stack, out var error))
        {
            throw new NotSupportedException(error);
        }

        return stack;
    }

    public static bool TryResolve(
        string? transport,
        string? transportSecurity,
        out ProxyInternetStack stack,
        out string? error)
    {
        var hasExplicitTransport = !string.IsNullOrWhiteSpace(transport);
        var hasExplicitSecurity = !string.IsNullOrWhiteSpace(transportSecurity);
        var normalizedTransport = hasExplicitTransport
            ? TrojanOutboundTransports.Normalize(transport)
            : hasExplicitSecurity
                ? TrojanOutboundTransports.Tcp
                : TrojanOutboundTransports.Normalize(transport);

        if (normalizedTransport is not (
                TrojanOutboundTransports.Tcp or
                TrojanOutboundTransports.Tls or
                TrojanOutboundTransports.Ws or
                TrojanOutboundTransports.Wss or
                TrojanOutboundTransports.HttpUpgrade or
                TrojanOutboundTransports.HttpUpgradeTls or
                TrojanOutboundTransports.Grpc or
                TrojanOutboundTransports.SplitHttp or
                RuntimeInternetTransportProtocols.Mkcp))
        {
            stack = default;
            error = RuntimeInternetTransportProtocols.TryGetKnownAvailabilityError(normalizedTransport, out var availabilityError)
                ? availabilityError
                : $"Unsupported proxy outbound transport: {transport?.Trim() ?? string.Empty}.";
            return false;
        }

        var normalizedSecurity = hasExplicitSecurity
            ? RuntimeInternetSecurityTypes.Normalize(transportSecurity)
            : ResolveLegacySecurityType(normalizedTransport);
        if (normalizedSecurity is not (
                RuntimeInternetSecurityTypes.None or
                RuntimeInternetSecurityTypes.Tls or
                RuntimeInternetSecurityTypes.Reality))
        {
            stack = default;
            error = $"Unsupported proxy outbound security: {transportSecurity?.Trim() ?? string.Empty}.";
            return false;
        }

        var legacySecurity = ResolveLegacySecurityType(normalizedTransport);
        if (hasExplicitSecurity &&
            HasFixedLegacySecurity(normalizedTransport) &&
            !string.Equals(legacySecurity, normalizedSecurity, StringComparison.Ordinal))
        {
            stack = default;
            error = $"Transport '{normalizedTransport}' cannot be combined with security '{normalizedSecurity}'.";
            return false;
        }

        var transportProtocol = ResolveTransportProtocol(normalizedTransport);
        if (string.Equals(normalizedSecurity, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal) &&
            transportProtocol is not (
                RuntimeInternetTransportProtocols.Tcp or
                RuntimeInternetTransportProtocols.Grpc or
                RuntimeInternetTransportProtocols.SplitHttp))
        {
            stack = default;
            error = "REALITY security currently only supports TCP, SplitHTTP and gRPC transports.";
            return false;
        }

        stack = new ProxyInternetStack(
            normalizedTransport,
            transportProtocol,
            normalizedSecurity);
        error = null;
        return true;
    }

    private static string ResolveTransportProtocol(string transport)
        => TrojanOutboundTransports.Normalize(transport) switch
        {
            TrojanOutboundTransports.Tls => RuntimeInternetTransportProtocols.Tcp,
            TrojanOutboundTransports.Wss => RuntimeInternetTransportProtocols.Ws,
            TrojanOutboundTransports.HttpUpgradeTls => RuntimeInternetTransportProtocols.HttpUpgrade,
            _ => TrojanOutboundTransports.Normalize(transport)
        };

    private static string ResolveLegacySecurityType(string transport)
        => TrojanOutboundTransports.Normalize(transport) switch
        {
            TrojanOutboundTransports.Tls or
            TrojanOutboundTransports.Wss or
            TrojanOutboundTransports.HttpUpgradeTls or
            TrojanOutboundTransports.Grpc
                => RuntimeInternetSecurityTypes.Tls,
            _ => RuntimeInternetSecurityTypes.None
        };

    private static bool HasFixedLegacySecurity(string transport)
        => TrojanOutboundTransports.Normalize(transport) is
            TrojanOutboundTransports.Tls or
            TrojanOutboundTransports.Wss or
            TrojanOutboundTransports.HttpUpgradeTls;
}

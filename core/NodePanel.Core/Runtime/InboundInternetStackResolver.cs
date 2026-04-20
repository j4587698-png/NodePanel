namespace NodePanel.Core.Runtime;

public interface IInboundInternetDefinition
{
    string TransportProtocol { get; }

    string TransportSecurity { get; }
}

public readonly record struct InboundInternetStack(
    string Transport,
    string TransportProtocol,
    string SecurityType)
{
    public bool IsWebSocketTransport
        => string.Equals(TransportProtocol, RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal);

    public bool IsGrpcTransport
        => string.Equals(TransportProtocol, RuntimeInternetTransportProtocols.Grpc, StringComparison.Ordinal);

    public bool UsesTlsLikeSecurity
        => RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(SecurityType);
}

public static class InboundInternetStackResolver
{
    public static InboundInternetStack Resolve(
        string? transport,
        string? transportProtocol,
        string? transportSecurity)
    {
        if (!TryResolve(transport, transportProtocol, transportSecurity, out var stack, out var error))
        {
            throw new NotSupportedException(error);
        }

        return stack;
    }

    public static bool TryResolve(
        string? transport,
        string? transportProtocol,
        string? transportSecurity,
        out InboundInternetStack stack,
        out string? error)
    {
        var hasExplicitTransportProtocol = !string.IsNullOrWhiteSpace(transportProtocol);
        var hasExplicitTransportSecurity = !string.IsNullOrWhiteSpace(transportSecurity);
        var hasLegacyTransport = !string.IsNullOrWhiteSpace(transport);

        if (!hasExplicitTransportProtocol &&
            !hasExplicitTransportSecurity)
        {
            var normalizedLegacyTransport = hasLegacyTransport
                ? InboundTransports.Normalize(transport)
                : InboundTransports.Tls;
            if (!TryResolveLegacyTransport(normalizedLegacyTransport, out var legacyTransportProtocol, out var legacySecurityType))
            {
                stack = default;
                error = $"Unsupported inbound transport: {transport?.Trim() ?? string.Empty}.";
                return false;
            }

            stack = new InboundInternetStack(
                normalizedLegacyTransport,
                legacyTransportProtocol,
                legacySecurityType);
            error = null;
            return true;
        }

        var normalizedTransportProtocol = hasExplicitTransportProtocol
            ? RuntimeInternetTransportProtocols.Normalize(transportProtocol)
            : RuntimeInternetTransportProtocols.Tcp;
        if (normalizedTransportProtocol is not (
                RuntimeInternetTransportProtocols.Tcp or
                RuntimeInternetTransportProtocols.Mkcp or
                RuntimeInternetTransportProtocols.Ws or
                RuntimeInternetTransportProtocols.HttpUpgrade or
                RuntimeInternetTransportProtocols.Grpc or
                RuntimeInternetTransportProtocols.SplitHttp))
        {
            stack = default;
            error = RuntimeInternetTransportProtocols.TryGetKnownAvailabilityError(normalizedTransportProtocol, out var availabilityError)
                ? availabilityError
                : $"Unsupported inbound transport protocol: {transportProtocol?.Trim() ?? string.Empty}.";
            return false;
        }

        var normalizedSecurityType = hasExplicitTransportSecurity
            ? RuntimeInternetSecurityTypes.Normalize(transportSecurity)
            : RuntimeInternetSecurityTypes.None;
        if (normalizedSecurityType is not (
                RuntimeInternetSecurityTypes.None or
                RuntimeInternetSecurityTypes.Tls or
                RuntimeInternetSecurityTypes.Reality))
        {
            stack = default;
            error = $"Unsupported inbound transport security: {transportSecurity?.Trim() ?? string.Empty}.";
            return false;
        }

        if (string.Equals(normalizedSecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal) &&
            normalizedTransportProtocol is not (
                RuntimeInternetTransportProtocols.Tcp or
                RuntimeInternetTransportProtocols.Grpc or
                RuntimeInternetTransportProtocols.SplitHttp))
        {
            stack = default;
            error = "REALITY inbound security currently only supports TCP, SplitHTTP and gRPC transports.";
            return false;
        }

        if (hasLegacyTransport)
        {
            var normalizedLegacyTransport = InboundTransports.Normalize(transport);
            if (TryResolveLegacyTransport(normalizedLegacyTransport, out var legacyTransportProtocol, out var legacySecurityType))
            {
                var protocolMatches = string.Equals(legacyTransportProtocol, normalizedTransportProtocol, StringComparison.Ordinal);
                var securityMatches = string.Equals(legacySecurityType, normalizedSecurityType, StringComparison.Ordinal);
                var legacyTransportRepresentsProtocolOnly = string.Equals(
                    normalizedLegacyTransport,
                    legacyTransportProtocol,
                    StringComparison.Ordinal);

                if ((!protocolMatches || !securityMatches) &&
                    !(legacyTransportRepresentsProtocolOnly && protocolMatches))
                {
                    stack = default;
                    error = $"Legacy inbound transport '{normalizedLegacyTransport}' conflicts with transport protocol '{normalizedTransportProtocol}' and security '{normalizedSecurityType}'.";
                    return false;
                }
            }
        }

        stack = new InboundInternetStack(
            ToLegacyTransport(normalizedTransportProtocol, normalizedSecurityType),
            normalizedTransportProtocol,
            normalizedSecurityType);
        error = null;
        return true;
    }

    public static string ToLegacyTransport(string? transportProtocol, string? securityType)
    {
        var normalizedTransportProtocol = RuntimeInternetTransportProtocols.Normalize(transportProtocol);
        var normalizedSecurityType = RuntimeInternetSecurityTypes.Normalize(securityType);

        return (normalizedTransportProtocol, normalizedSecurityType) switch
        {
            (RuntimeInternetTransportProtocols.Tcp, RuntimeInternetSecurityTypes.Tls) => InboundTransports.Tls,
            (RuntimeInternetTransportProtocols.Ws, RuntimeInternetSecurityTypes.Tls) => InboundTransports.Wss,
            _ => normalizedTransportProtocol
        };
    }

    public static bool IsTcpTls(string? transportProtocol, string? securityType)
        => string.Equals(
               RuntimeInternetTransportProtocols.Normalize(transportProtocol),
               RuntimeInternetTransportProtocols.Tcp,
               StringComparison.Ordinal) &&
           string.Equals(
               RuntimeInternetSecurityTypes.Normalize(securityType),
               RuntimeInternetSecurityTypes.Tls,
               StringComparison.Ordinal);

    public static bool IsWsTls(string? transportProtocol, string? securityType)
        => string.Equals(
               RuntimeInternetTransportProtocols.Normalize(transportProtocol),
               RuntimeInternetTransportProtocols.Ws,
               StringComparison.Ordinal) &&
           string.Equals(
               RuntimeInternetSecurityTypes.Normalize(securityType),
               RuntimeInternetSecurityTypes.Tls,
               StringComparison.Ordinal);

    public static bool IsGrpcTls(string? transportProtocol, string? securityType)
        => string.Equals(
               RuntimeInternetTransportProtocols.Normalize(transportProtocol),
               RuntimeInternetTransportProtocols.Grpc,
               StringComparison.Ordinal) &&
           string.Equals(
               RuntimeInternetSecurityTypes.Normalize(securityType),
               RuntimeInternetSecurityTypes.Tls,
               StringComparison.Ordinal);

    public static bool IsSplitHttpTls(string? transportProtocol, string? securityType)
        => string.Equals(
               RuntimeInternetTransportProtocols.Normalize(transportProtocol),
               RuntimeInternetTransportProtocols.SplitHttp,
               StringComparison.Ordinal) &&
           string.Equals(
               RuntimeInternetSecurityTypes.Normalize(securityType),
               RuntimeInternetSecurityTypes.Tls,
               StringComparison.Ordinal);

    private static bool TryResolveLegacyTransport(
        string transport,
        out string transportProtocol,
        out string securityType)
    {
        switch (InboundTransports.Normalize(transport))
        {
            case InboundTransports.Tls:
                transportProtocol = RuntimeInternetTransportProtocols.Tcp;
                securityType = RuntimeInternetSecurityTypes.Tls;
                return true;
            case InboundTransports.Wss:
                transportProtocol = RuntimeInternetTransportProtocols.Ws;
                securityType = RuntimeInternetSecurityTypes.Tls;
                return true;
            case InboundTransports.Grpc:
                transportProtocol = RuntimeInternetTransportProtocols.Grpc;
                securityType = RuntimeInternetSecurityTypes.Tls;
                return true;
            case RuntimeInternetTransportProtocols.Mkcp:
                transportProtocol = RuntimeInternetTransportProtocols.Mkcp;
                securityType = RuntimeInternetSecurityTypes.None;
                return true;
            case InboundTransports.SplitHttp:
                transportProtocol = RuntimeInternetTransportProtocols.SplitHttp;
                securityType = RuntimeInternetSecurityTypes.Tls;
                return true;
            default:
                transportProtocol = string.Empty;
                securityType = string.Empty;
                return false;
        }
    }
}

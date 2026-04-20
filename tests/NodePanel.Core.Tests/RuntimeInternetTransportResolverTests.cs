using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeInternetTransportResolverTests
{
    [Theory]
    [InlineData("raw", RuntimeInternetTransportProtocols.Tcp)]
    [InlineData("tcp", RuntimeInternetTransportProtocols.Tcp)]
    [InlineData("websocket", RuntimeInternetTransportProtocols.Ws)]
    [InlineData("ws", RuntimeInternetTransportProtocols.Ws)]
    [InlineData("xhttp", RuntimeInternetTransportProtocols.SplitHttp)]
    [InlineData("split-http", RuntimeInternetTransportProtocols.SplitHttp)]
    [InlineData("kcp", RuntimeInternetTransportProtocols.Mkcp)]
    [InlineData("mkcp", RuntimeInternetTransportProtocols.Mkcp)]
    public void Normalize_maps_xray_core_transport_aliases(string value, string expected)
    {
        Assert.Equal(expected, RuntimeInternetTransportProtocols.Normalize(value));
    }

    [Fact]
    public void ProxyInternetStackResolver_accepts_raw_alias_with_explicit_tls_security()
    {
        var stack = ProxyInternetStackResolver.Resolve("raw", RuntimeInternetSecurityTypes.Tls);

        Assert.Equal(TrojanOutboundTransports.Tcp, stack.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, stack.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, stack.SecurityType);
    }

    [Fact]
    public void ProxyInternetStackResolver_accepts_websocket_alias_with_explicit_tls_security()
    {
        var stack = ProxyInternetStackResolver.Resolve("websocket", RuntimeInternetSecurityTypes.Tls);

        Assert.Equal(TrojanOutboundTransports.Ws, stack.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Ws, stack.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, stack.SecurityType);
    }

    [Theory]
    [InlineData(RuntimeInternetSecurityTypes.None)]
    [InlineData(RuntimeInternetSecurityTypes.Tls)]
    public void ProxyInternetStackResolver_accepts_mkcp_transport(string securityType)
    {
        var stack = ProxyInternetStackResolver.Resolve("mkcp", securityType);

        Assert.Equal(RuntimeInternetTransportProtocols.Mkcp, stack.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Mkcp, stack.TransportProtocol);
        Assert.Equal(securityType, stack.SecurityType);
    }

    [Fact]
    public void InboundInternetStackResolver_accepts_raw_transport_protocol_alias()
    {
        var stack = InboundInternetStackResolver.Resolve(
            transport: null,
            transportProtocol: "raw",
            transportSecurity: RuntimeInternetSecurityTypes.Tls);

        Assert.Equal(InboundTransports.Tls, stack.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, stack.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, stack.SecurityType);
    }

    [Fact]
    public void InboundInternetStackResolver_accepts_websocket_transport_protocol_alias()
    {
        var stack = InboundInternetStackResolver.Resolve(
            transport: null,
            transportProtocol: "websocket",
            transportSecurity: RuntimeInternetSecurityTypes.Tls);

        Assert.Equal(InboundTransports.Wss, stack.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Ws, stack.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, stack.SecurityType);
    }

    [Fact]
    public void InboundInternetStackResolver_accepts_mkcp_transport_protocol()
    {
        var stack = InboundInternetStackResolver.Resolve(
            transport: null,
            transportProtocol: "kcp",
            transportSecurity: RuntimeInternetSecurityTypes.None);

        Assert.Equal(RuntimeInternetTransportProtocols.Mkcp, stack.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Mkcp, stack.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, stack.SecurityType);
    }

    [Theory]
    [InlineData(InboundTransports.Grpc, RuntimeInternetTransportProtocols.Grpc)]
    [InlineData(InboundTransports.SplitHttp, RuntimeInternetTransportProtocols.SplitHttp)]
    public void InboundInternetStackResolver_accepts_explicit_none_security_for_protocol_named_legacy_transports(
        string transport,
        string expectedProtocol)
    {
        var stack = InboundInternetStackResolver.Resolve(
            transport: transport,
            transportProtocol: expectedProtocol,
            transportSecurity: RuntimeInternetSecurityTypes.None);

        Assert.Equal(transport, stack.Transport);
        Assert.Equal(expectedProtocol, stack.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.None, stack.SecurityType);
    }

    [Theory]
    [InlineData("http", "removed")]
    [InlineData("h2", "removed")]
    [InlineData("h3", "removed")]
    [InlineData("quic", "removed")]
    [InlineData("kcp", "plain inbound server")]
    [InlineData("mkcp", "plain inbound server")]
    [InlineData("hysteria", "not implemented")]
    public void RuntimeInternetTransportProtocols_reports_known_unavailable_transports(
        string value,
        string expectedMessageFragment)
    {
        Assert.True(RuntimeInternetTransportProtocols.TryGetKnownAvailabilityError(value, out var error));
        Assert.NotNull(error);
        Assert.Contains(expectedMessageFragment, error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("quic", "removed")]
    [InlineData("hysteria", "not implemented")]
    public void ProxyInternetStackResolver_returns_specific_error_for_known_unavailable_transports(
        string transport,
        string expectedMessageFragment)
    {
        var exception = Assert.Throws<NotSupportedException>(() => ProxyInternetStackResolver.Resolve(transport, null));

        Assert.Contains(expectedMessageFragment, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("quic", "removed")]
    [InlineData("hysteria", "not implemented")]
    public void InboundInternetStackResolver_returns_specific_error_for_known_unavailable_transport_protocols(
        string transportProtocol,
        string expectedMessageFragment)
    {
        var exception = Assert.Throws<NotSupportedException>(() => InboundInternetStackResolver.Resolve(
            transport: null,
            transportProtocol: transportProtocol,
            transportSecurity: RuntimeInternetSecurityTypes.None));

        Assert.Contains(expectedMessageFragment, exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}

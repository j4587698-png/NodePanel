using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanSniffingEvaluatorTests
{
    [Fact]
    public void Evaluate_detects_http_and_overrides_destination()
    {
        var sniffing = new TrojanSniffingRuntime
        {
            Enabled = true,
            DestinationOverride = [RoutingProtocols.Http]
        };

        var decision = TrojanSniffingEvaluator.Evaluate(
            sniffing,
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: edge.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.10",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(RoutingProtocols.Http, decision.Protocol);
        Assert.Equal("edge.example.com", decision.Domain);
        Assert.NotNull(decision.OverrideDestination);
        Assert.Equal("edge.example.com", decision.OverrideDestination!.Host);
    }

    [Fact]
    public void Evaluate_respects_domain_exclusion_and_route_only()
    {
        var sniffing = new TrojanSniffingRuntime
        {
            Enabled = true,
            RouteOnly = true,
            DestinationOverride = [RoutingProtocols.Http],
            DomainsExcluded = ["blocked.example.com"]
        };

        var blocked = TrojanSniffingEvaluator.Evaluate(
            sniffing,
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.10",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });
        var routeOnly = TrojanSniffingEvaluator.Evaluate(
            sniffing with { DomainsExcluded = Array.Empty<string>() },
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: route.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.11",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(RoutingProtocols.Http, blocked.Protocol);
        Assert.Equal("blocked.example.com", blocked.Domain);
        Assert.False(blocked.OverrideMatched);
        Assert.Null(blocked.OverrideDestination);

        Assert.True(routeOnly.OverrideMatched);
        Assert.True(routeOnly.RouteOnly);
        Assert.Null(routeOnly.OverrideDestination);
    }

    [Fact]
    public void Evaluate_detects_tls_sni_and_quic()
    {
        var sniffing = new TrojanSniffingRuntime
        {
            Enabled = true,
            DestinationOverride = [RoutingProtocols.Tls]
        };

        var tlsDecision = TrojanSniffingEvaluator.Evaluate(
            sniffing,
            BuildTlsClientHello("tls.example.com"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "198.51.100.10",
                Port = 443,
                Network = DispatchNetwork.Tcp
            });
        var quicDecision = TrojanSniffingEvaluator.Evaluate(
            new TrojanSniffingRuntime
            {
                Enabled = true
            },
            [0xC3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00],
            DispatchNetwork.Udp,
            new DispatchDestination
            {
                Host = "198.51.100.11",
                Port = 443,
                Network = DispatchNetwork.Udp
            });

        Assert.Equal(RoutingProtocols.Tls, tlsDecision.Protocol);
        Assert.Equal("tls.example.com", tlsDecision.Domain);
        Assert.NotNull(tlsDecision.OverrideDestination);
        Assert.Equal("tls.example.com", tlsDecision.OverrideDestination!.Host);

        Assert.Equal(RoutingProtocols.Quic, quicDecision.Protocol);
        Assert.Equal(string.Empty, quicDecision.Domain);
    }

    private static byte[] BuildTlsClientHello(string host)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        using var handshakeBody = new MemoryStream();
        handshakeBody.WriteByte(0x03);
        handshakeBody.WriteByte(0x03);
        handshakeBody.Write(new byte[32]);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x02);
        handshakeBody.WriteByte(0x13);
        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x00);

        using var extensions = new MemoryStream();
        var serverNameListLength = (ushort)(1 + 2 + hostBytes.Length);
        var extensionLength = (ushort)(2 + serverNameListLength);
        extensions.WriteByte(0x00);
        extensions.WriteByte(0x00);
        extensions.WriteByte((byte)(extensionLength >> 8));
        extensions.WriteByte((byte)extensionLength);
        extensions.WriteByte((byte)(serverNameListLength >> 8));
        extensions.WriteByte((byte)serverNameListLength);
        extensions.WriteByte(0x00);
        extensions.WriteByte((byte)(hostBytes.Length >> 8));
        extensions.WriteByte((byte)hostBytes.Length);
        extensions.Write(hostBytes);

        var extensionsBytes = extensions.ToArray();
        handshakeBody.WriteByte((byte)(extensionsBytes.Length >> 8));
        handshakeBody.WriteByte((byte)extensionsBytes.Length);
        handshakeBody.Write(extensionsBytes);

        var handshakeBytes = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        record.WriteByte(0x03);
        record.WriteByte(0x01);
        var recordLength = (ushort)(handshakeBytes.Length + 4);
        record.WriteByte((byte)(recordLength >> 8));
        record.WriteByte((byte)recordLength);
        record.WriteByte(0x01);
        record.WriteByte((byte)((handshakeBytes.Length >> 16) & 0xff));
        record.WriteByte((byte)((handshakeBytes.Length >> 8) & 0xff));
        record.WriteByte((byte)(handshakeBytes.Length & 0xff));
        record.Write(handshakeBytes);
        return record.ToArray();
    }
}

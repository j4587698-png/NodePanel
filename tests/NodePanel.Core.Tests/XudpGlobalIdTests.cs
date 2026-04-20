using System.Net;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class XudpGlobalIdTests
{
    [Theory]
    [InlineData(false, ProxyInboundProtocols.Socks, RoutingNetworks.Udp)]
    [InlineData(true, ProxyInboundProtocols.Socks, RoutingNetworks.Tcp)]
    [InlineData(true, InboundProtocols.Vless, RoutingNetworks.Udp)]
    public void Create_returns_zero_for_ineligible_context(
        bool useCone,
        string inboundKind,
        string inboundSourceNetwork)
    {
        var actual = XudpGlobalId.Create(
            CreateContext(useCone, inboundKind, inboundSourceNetwork),
            CreateSequentialBaseKey());

        Assert.Equal(new byte[8], actual);
    }

    [Fact]
    public void Create_derives_expected_global_id_for_supported_udp_inbound()
    {
        var actual = XudpGlobalId.Create(
            CreateContext(useCone: true, ProxyInboundProtocols.Socks, RoutingNetworks.Udp),
            CreateSequentialBaseKey());

        Assert.Equal(Convert.FromHexString("ED28A933CDE4E09F"), actual);
    }

    [Fact]
    public void Create_derives_different_global_id_for_different_source_endpoints()
    {
        var baseKey = CreateSequentialBaseKey();
        var left = XudpGlobalId.Create(
            CreateContext(useCone: true, ProxyInboundProtocols.Socks, RoutingNetworks.Udp, 12345),
            baseKey);
        var right = XudpGlobalId.Create(
            CreateContext(useCone: true, ProxyInboundProtocols.Socks, RoutingNetworks.Udp, 12346),
            baseKey);

        Assert.NotEqual(left, right);
    }

    [Fact]
    public void ResolveBaseKey_prefers_primary_environment_name()
    {
        var primaryKey = CreateSequentialBaseKey();
        var alternateKey = Enumerable.Repeat((byte)0xAA, 32).ToArray();

        var actual = XudpGlobalId.ResolveBaseKey(name => name switch
        {
            XudpGlobalId.BaseKeyEnvironmentName => ToBase64Url(primaryKey),
            XudpGlobalId.BaseKeyAlternateEnvironmentName => ToBase64Url(alternateKey),
            _ => null
        });

        Assert.Equal(primaryKey, actual);
    }

    [Fact]
    public void ResolveBaseKey_uses_alternate_environment_name_when_primary_is_missing()
    {
        var alternateKey = Enumerable.Range(32, 32).Select(static value => (byte)value).ToArray();

        var actual = XudpGlobalId.ResolveBaseKey(name => name == XudpGlobalId.BaseKeyAlternateEnvironmentName
            ? ToBase64Url(alternateKey)
            : null);

        Assert.Equal(alternateKey, actual);
    }

    [Fact]
    public void DecodeConfiguredBaseKey_rejects_invalid_length()
    {
        var raw = ToBase64Url([0x01, 0x02, 0x03, 0x04]);

        var exception = Assert.Throws<InvalidOperationException>(() => XudpGlobalId.DecodeConfiguredBaseKey(raw));

        Assert.Contains("BaseKey must be 32 bytes", exception.Message, StringComparison.Ordinal);
    }

    private static DispatchContext CreateContext(
        bool useCone,
        string inboundKind,
        string inboundSourceNetwork,
        int sourcePort = 12345)
        => new()
        {
            UseCone = useCone,
            InboundKind = inboundKind,
            InboundSourceNetwork = inboundSourceNetwork,
            SourceEndPoint = new IPEndPoint(IPAddress.Loopback, sourcePort)
        };

    private static byte[] CreateSequentialBaseKey()
        => Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();

    private static string ToBase64Url(byte[] value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

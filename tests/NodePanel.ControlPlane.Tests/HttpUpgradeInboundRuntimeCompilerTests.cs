using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Runtime;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Tests;

public sealed class HttpUpgradeInboundRuntimeCompilerTests
{
    [Fact]
    public void TrojanCompiler_normalizes_explicit_httpupgrade_transport_and_keeps_active_users()
        => AssertHttpUpgradeCompiler(new TrojanInboundRuntimeCompiler(), InboundProtocols.Trojan);

    [Fact]
    public void VlessCompiler_normalizes_explicit_httpupgrade_transport_and_keeps_active_users()
        => AssertHttpUpgradeCompiler(new VlessInboundRuntimeCompiler(), InboundProtocols.Vless);

    [Fact]
    public void VmessCompiler_normalizes_explicit_httpupgrade_transport_and_keeps_active_users()
        => AssertHttpUpgradeCompiler(new VmessInboundRuntimeCompiler(), InboundProtocols.Vmess);

    private static void AssertHttpUpgradeCompiler(
        IInboundProtocolRuntimeCompiler compiler,
        string protocol)
    {
        const string userId = "demo-user";
        var config = new NodeServiceConfig
        {
            Users = string.Equals(protocol, InboundProtocols.Trojan, StringComparison.Ordinal)
                ? [new TrojanUserConfig
                {
                    UserId = $" {userId} ",
                    Password = " secret "
                }]
                : Array.Empty<TrojanUserConfig>(),
            Inbounds =
            [
                new InboundConfig
                {
                    Tag = $"{protocol}-httpupgrade",
                    Enabled = true,
                    Protocol = protocol,
                    TransportProtocol = " HTTPUPGRADE ",
                    TransportSecurity = " TLS ",
                    ListenAddress = "127.0.0.1",
                    Port = -1,
                    Host = " edge.example.com ",
                    Path = " upgrade ",
                    ApplicationProtocols = [" h2 ", "http/1.1"],
                    Users = CreateInboundUsers(protocol, userId)
                }
            ]
        };

        var normalized = compiler.Normalize(config);
        var inbound = Assert.Single(normalized.Inbounds);

        Assert.Equal(RuntimeInternetTransportProtocols.HttpUpgrade, inbound.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.HttpUpgrade, inbound.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, inbound.TransportSecurity);
        Assert.Equal(8443, inbound.Port);
        Assert.Equal("edge.example.com", inbound.Host);
        Assert.Equal("/upgrade", inbound.Path);
        Assert.Equal(["http/1.1"], inbound.ApplicationProtocols);

        if (string.Equals(protocol, InboundProtocols.Trojan, StringComparison.Ordinal))
        {
            var user = Assert.Single(inbound.Users);
            Assert.Equal(userId, user.UserId);
            Assert.Equal("secret", user.Password);
        }

        var result = compiler.TryCompile(normalized, out var compilation, out var error);

        Assert.True(result, error);
        Assert.Single(compilation.ActiveUsers);

        switch (compilation.Plan)
        {
            case TrojanInboundRuntimePlan trojanPlan:
            {
                var listener = Assert.Single(trojanPlan.Listeners);
                Assert.Equal(8443, listener.Binding.Port);
                Assert.Equal(["http/1.1"], listener.ApplicationProtocols);
                Assert.Equal("/upgrade", listener.HttpUpgradeInbound!.Path);
                break;
            }
            case VlessInboundRuntimePlan vlessPlan:
            {
                var listener = Assert.Single(vlessPlan.Listeners);
                Assert.Equal(8443, listener.Binding.Port);
                Assert.Equal(["http/1.1"], listener.ApplicationProtocols);
                Assert.Equal("/upgrade", listener.HttpUpgradeInbound!.Path);
                break;
            }
            case VmessInboundRuntimePlan vmessPlan:
            {
                var listener = Assert.Single(vmessPlan.Listeners);
                Assert.Equal(8443, listener.Binding.Port);
                Assert.Equal(["http/1.1"], listener.ApplicationProtocols);
                Assert.Equal("/upgrade", listener.HttpUpgradeInbound!.Path);
                break;
            }
            default:
                throw new InvalidOperationException("Unexpected inbound runtime plan type.");
        }
    }

    private static IReadOnlyList<TrojanUserConfig> CreateInboundUsers(string protocol, string userId)
        => string.Equals(protocol, InboundProtocols.Trojan, StringComparison.Ordinal)
            ? Array.Empty<TrojanUserConfig>()
            :
            [
                new TrojanUserConfig
                {
                    UserId = $" {userId} ",
                    Uuid = Guid.NewGuid().ToString("D")
                }
            ];
}

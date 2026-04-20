using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Runtime;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Tests;

public sealed class SplitHttpInboundRuntimeCompilerTests
{
    [Fact]
    public void TrojanCompiler_normalizes_legacy_splithttp_transport_and_keeps_active_users()
        => AssertSplitHttpCompiler(new TrojanInboundRuntimeCompiler(), InboundProtocols.Trojan);

    [Fact]
    public void VlessCompiler_normalizes_legacy_splithttp_transport_and_keeps_active_users()
        => AssertSplitHttpCompiler(new VlessInboundRuntimeCompiler(), InboundProtocols.Vless);

    [Fact]
    public void VmessCompiler_normalizes_legacy_splithttp_transport_and_keeps_active_users()
        => AssertSplitHttpCompiler(new VmessInboundRuntimeCompiler(), InboundProtocols.Vmess);

    private static void AssertSplitHttpCompiler(
        IInboundProtocolRuntimeCompiler compiler,
        string protocol)
    {
        var config = new NodeServiceConfig
        {
            Inbounds =
            [
                new InboundConfig
                {
                    Tag = $"{protocol}-xhttp",
                    Enabled = true,
                    Protocol = protocol,
                    Transport = InboundTransports.SplitHttp,
                    ListenAddress = "127.0.0.1",
                    Port = 2443,
                    Host = " edge.example.com ",
                    Path = " xhttp?route=1 ",
                    SplitHttpMode = " STREAM-UP ",
                    SplitHttpSessionPlacement = " Query ",
                    Users =
                    [
                        new TrojanUserConfig
                        {
                            UserId = " demo-user ",
                            Uuid = Guid.NewGuid().ToString("D"),
                            Password = " secret "
                        }
                    ]
                }
            ]
        };

        var normalized = compiler.Normalize(config);
        var inbound = Assert.Single(normalized.Inbounds);
        Assert.Equal(InboundTransports.SplitHttp, inbound.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.SplitHttp, inbound.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, inbound.TransportSecurity);
        Assert.Equal("/xhttp/?route=1", inbound.Path);

        var result = compiler.TryCompile(normalized, out var compilation, out var error);

        Assert.True(result, error);
        Assert.Single(compilation.ActiveUsers);

        switch (compilation.Plan)
        {
            case TrojanInboundRuntimePlan trojanPlan:
                Assert.True(trojanPlan.HasSplitHttp);
                Assert.Equal("/xhttp/?route=1", Assert.Single(trojanPlan.Listeners).SplitHttpInbound!.Path);
                Assert.Equal("stream-up", Assert.Single(trojanPlan.Listeners).SplitHttpInbound!.SplitHttp.Mode);
                Assert.Equal("query", Assert.Single(trojanPlan.Listeners).SplitHttpInbound!.SplitHttp.SessionPlacement);
                break;
            case VlessInboundRuntimePlan vlessPlan:
                Assert.True(vlessPlan.HasSplitHttp);
                Assert.Equal("/xhttp/?route=1", Assert.Single(vlessPlan.Listeners).SplitHttpInbound!.Path);
                Assert.Equal("stream-up", Assert.Single(vlessPlan.Listeners).SplitHttpInbound!.SplitHttp.Mode);
                Assert.Equal("query", Assert.Single(vlessPlan.Listeners).SplitHttpInbound!.SplitHttp.SessionPlacement);
                break;
            case VmessInboundRuntimePlan vmessPlan:
                Assert.True(vmessPlan.HasSplitHttp);
                Assert.Equal("/xhttp/?route=1", Assert.Single(vmessPlan.Listeners).SplitHttpInbound!.Path);
                Assert.Equal("stream-up", Assert.Single(vmessPlan.Listeners).SplitHttpInbound!.SplitHttp.Mode);
                Assert.Equal("query", Assert.Single(vmessPlan.Listeners).SplitHttpInbound!.SplitHttp.SessionPlacement);
                break;
            default:
                throw new InvalidOperationException("Unexpected inbound runtime plan type.");
        }
    }
}

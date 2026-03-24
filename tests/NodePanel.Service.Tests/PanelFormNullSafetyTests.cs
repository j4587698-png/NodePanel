using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;

namespace NodePanel.Service.Tests;

public sealed class PanelFormNullSafetyTests
{
    [Fact]
    public void PanelCertificateFormInput_try_to_request_accepts_null_alt_names()
    {
        var form = new PanelCertificateFormInput
        {
            CertificateId = "panel-cert",
            DisplayName = "Panel Certificate",
            Domain = "panel.example.com",
            AltNames = null!,
            EnvironmentVariables = null!,
            ChallengeType = CertificateChallengeTypes.Http01
        };

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal("panel.example.com", request.Domain);
        Assert.Empty(request.AltNames);
    }

    [Fact]
    public void NodeFormInput_try_to_request_accepts_null_csv_fields()
    {
        var form = CreateBaseForm();
        form.GroupIds = null!;
        form.Inbounds[0].ApplicationProtocols = null!;
        form.Inbounds[1].ApplicationProtocols = null!;

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Empty(request.GroupIds);
        Assert.All(request.Config.Inbounds, inbound => Assert.Empty(inbound.ApplicationProtocols));
    }

    private static NodeFormInput CreateBaseForm()
        => new()
        {
            NodeId = "node-a",
            DisplayName = "Node A",
            Protocol = InboundProtocols.Trojan,
            GroupIds = "1, 2",
            TrafficMultiplier = 1.0m,
            Enabled = true,
            Inbounds =
            [
                new TrojanInboundFormInput
                {
                    Tag = "trojan-tcp-tls",
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Tls,
                    Enabled = true,
                    ListenAddress = "0.0.0.0",
                    Port = 443,
                    HandshakeTimeoutSeconds = 10
                },
                new TrojanInboundFormInput
                {
                    Tag = "trojan-wss",
                    Protocol = InboundProtocols.Trojan,
                    Transport = InboundTransports.Wss,
                    Enabled = true,
                    ListenAddress = "0.0.0.0",
                    Port = 8443,
                    Host = "ws.example.com",
                    Path = "/ws",
                    HandshakeTimeoutSeconds = 10
                }
            ]
        };
}

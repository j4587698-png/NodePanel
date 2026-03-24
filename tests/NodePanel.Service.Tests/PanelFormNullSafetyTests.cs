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
    public void PanelCertificateFormInput_try_to_request_accepts_null_optional_text_fields()
    {
        var form = new PanelCertificateFormInput
        {
            CertificateId = "panel-cert",
            DisplayName = null!,
            Domain = "panel.example.com",
            AltNames = null!,
            Email = null!,
            AcmeDirectoryUrl = null!,
            PfxPassword = null!,
            DnsZone = null!,
            DnsApiToken = null!,
            DnsAccessKeyId = null!,
            DnsAccessKeySecret = null!,
            DnsHookPresentCommand = null!,
            DnsHookPresentArguments = null!,
            DnsHookCleanupCommand = null!,
            DnsHookCleanupArguments = null!,
            EnvironmentVariables = null!,
            ChallengeType = CertificateChallengeTypes.Http01
        };

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal("panel.example.com", request.Domain);
        Assert.Equal(string.Empty, request.DisplayName);
        Assert.Equal(string.Empty, request.Email);
        Assert.Equal(string.Empty, request.DnsHookPresentCommand);
        Assert.Empty(request.EnvironmentVariables);
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

    [Fact]
    public void NodeFormInput_try_to_request_accepts_null_optional_text_fields()
    {
        var form = CreateBaseForm();
        form.DisplayName = null!;
        form.SubscriptionHost = null!;
        form.SubscriptionSni = null!;
        form.CertificatePfxPath = null!;
        form.CertificatePfxPassword = null!;
        form.CertificateDomain = null!;
        form.CertificateAltNames = null!;
        form.CertificateEmail = null!;
        form.CertificateAcmeDirectoryUrl = null!;
        form.CertificateHttpChallengeListenAddress = null!;
        form.CertificateExternalToolPath = null!;
        form.CertificateExternalArguments = null!;
        form.CertificateWorkingDirectory = null!;
        form.CertificateEnvironmentVariables = null!;
        form.AdvancedConfigJson = null!;
        form.Inbounds[0].ListenAddress = null!;
        form.Inbounds[1].Host = null!;
        form.Inbounds[1].Path = null!;

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal(string.Empty, request.DisplayName);
        Assert.Equal(string.Empty, request.SubscriptionHost);
        Assert.Equal(string.Empty, request.SubscriptionSni);
        Assert.Equal(string.Empty, request.Config.Certificate.PfxPath);
        Assert.Equal(string.Empty, request.Config.Certificate.Domain);
        Assert.Equal(string.Empty, request.Config.Inbounds[0].ListenAddress);
        Assert.Equal(string.Empty, request.Config.Inbounds[1].Host);
        Assert.Equal(string.Empty, request.Config.Inbounds[1].Path);
    }

    [Fact]
    public void UserFormInput_to_request_accepts_null_optional_text_fields()
    {
        var form = new UserFormInput
        {
            UserId = "user-a",
            DisplayName = null!,
            SubscriptionToken = null!,
            TrojanPassword = null!,
            V2rayUuid = null!,
            InviteUserId = null!,
            PlanName = null!,
            ExpiresAt = null!,
            PurchaseUrl = null!,
            PortalNotice = null!,
            NodeIds = null!
        };

        var request = form.ToRequest();

        Assert.Equal(string.Empty, request.DisplayName);
        Assert.Equal(string.Empty, request.SubscriptionToken);
        Assert.Equal(string.Empty, request.InviteUserId);
        Assert.Equal(string.Empty, request.Subscription.PlanName);
        Assert.Equal(string.Empty, request.Subscription.PurchaseUrl);
        Assert.Equal(string.Empty, request.Subscription.PortalNotice);
        Assert.Empty(request.NodeIds);
    }

    [Fact]
    public void PlanFormInput_to_request_accepts_null_name()
    {
        var form = new PlanFormInput
        {
            PlanId = "plan-a",
            Name = null!
        };

        var request = form.ToRequest();

        Assert.Equal(string.Empty, request.Name);
    }

    [Fact]
    public void TrojanFallbackFormInput_to_config_accepts_null_text_fields()
    {
        var form = new TrojanFallbackFormInput
        {
            Name = null!,
            Alpn = null!,
            Path = null!,
            Type = null!,
            Dest = null!
        };

        var config = form.ToConfig();

        Assert.Equal(string.Empty, config.Name);
        Assert.Equal(string.Empty, config.Alpn);
        Assert.Equal(string.Empty, config.Path);
        Assert.Equal(string.Empty, config.Type);
        Assert.Equal(string.Empty, config.Dest);
    }

    [Fact]
    public void OutboundFormInput_try_to_config_accepts_null_optional_text_fields()
    {
        var form = new OutboundFormInput
        {
            Tag = "proxy",
            Via = null!,
            ViaCidr = null!,
            ProxyOutboundTag = null!,
            ServerHost = null!,
            ServerName = null!,
            WebSocketPath = null!,
            WebSocketHeadersText = null!,
            ApplicationProtocols = null!,
            Password = null!
        };

        var success = form.TryToConfig(out var config, out var error);

        Assert.True(success, error);
        Assert.Equal("proxy", config.Tag);
        Assert.Equal(string.Empty, config.Via);
        Assert.Equal(string.Empty, config.ServerHost);
        Assert.Equal(string.Empty, config.Password);
        Assert.Empty(config.WebSocketHeaders);
        Assert.Empty(config.ApplicationProtocols);
    }

    [Fact]
    public void DnsServerFormInput_try_to_config_accepts_null_headers_text()
    {
        var form = new DnsServerFormInput
        {
            Url = "https://dns.example/resolve",
            HeadersText = null!
        };

        var success = form.TryToConfig(out var config, out var error);

        Assert.True(success, error);
        Assert.Equal("https://dns.example/resolve", config.Url);
        Assert.Empty(config.Headers);
    }

    [Fact]
    public void RoutingRuleFormInput_to_config_accepts_null_outbound_tag()
    {
        var form = new RoutingRuleFormInput
        {
            OutboundTag = null!
        };

        var config = form.ToConfig();

        Assert.Equal(string.Empty, config.OutboundTag);
    }

    [Fact]
    public void PanelHttpsSettingsFormInput_normalize_accepts_null_strings()
    {
        var form = new PanelHttpsSettingsFormInput
        {
            CertificateId = null!,
            ListenAddress = null!
        };

        var normalized = form.Normalize();

        Assert.Equal(string.Empty, normalized.CertificateId);
        Assert.Equal("0.0.0.0", normalized.ListenAddress);
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

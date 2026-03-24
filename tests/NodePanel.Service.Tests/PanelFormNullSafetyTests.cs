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

    [Fact]
    public void PanelCertificateFormInput_from_record_clamps_out_of_range_values()
    {
        var form = PanelCertificateFormInput.FromRecord(
            new PanelCertificateRecord
            {
                CertificateId = "panel-cert",
                Domain = "panel.example.com",
                RenewBeforeDays = 999,
                CheckIntervalMinutes = 99999
            });

        Assert.Equal(365, form.RenewBeforeDays);
        Assert.Equal(1440, form.CheckIntervalMinutes);
    }

    [Fact]
    public void NodeFormInput_from_record_clamps_out_of_range_values()
    {
        var form = NodeFormInput.FromRecord(
            new PanelNodeRecord
            {
                NodeId = "node-a",
                TrafficMultiplier = 0m,
                Config = new NodeServiceConfig
                {
                    Certificate = new CertificateOptions
                    {
                        RenewBeforeDays = 999,
                        CheckIntervalMinutes = 99999,
                        ExternalTimeoutSeconds = 99999
                    },
                    Limits = new TrojanInboundLimits
                    {
                        GlobalBytesPerSecond = -1,
                        ConnectTimeoutSeconds = 999,
                        ConnectionIdleSeconds = 999999,
                        UplinkOnlySeconds = 99999,
                        DownlinkOnlySeconds = 99999
                    },
                    Telemetry = new TelemetryOptions
                    {
                        FlushIntervalSeconds = 99999
                    }
                }
            });

        Assert.Equal(0.01m, form.TrafficMultiplier);
        Assert.Equal(365, form.CertificateRenewBeforeDays);
        Assert.Equal(1440, form.CertificateCheckIntervalMinutes);
        Assert.Equal(3600, form.CertificateExternalTimeoutSeconds);
        Assert.Equal(0L, form.GlobalBytesPerSecond);
        Assert.Equal(600, form.ConnectTimeoutSeconds);
        Assert.Equal(86400, form.ConnectionIdleSeconds);
        Assert.Equal(3600, form.UplinkOnlySeconds);
        Assert.Equal(3600, form.DownlinkOnlySeconds);
        Assert.Equal(3600, form.TelemetryFlushIntervalSeconds);
    }

    [Fact]
    public void TrojanInboundFormInput_from_inbound_clamps_out_of_range_values()
    {
        var form = TrojanInboundFormInput.FromInbound(
            new InboundConfig
            {
                Transport = InboundTransports.Wss,
                Port = 99999,
                HandshakeTimeoutSeconds = 999,
                EarlyDataBytes = 999999,
                HeartbeatPeriodSeconds = 99999
            });

        Assert.Equal(65535, form.Port);
        Assert.Equal(600, form.HandshakeTimeoutSeconds);
        Assert.Equal(65535, form.EarlyDataBytes);
        Assert.Equal(3600, form.HeartbeatPeriodSeconds);
    }

    [Fact]
    public void DnsFormInput_from_config_clamps_out_of_range_values()
    {
        var form = DnsFormInput.FromConfig(
            new DnsOptions
            {
                TimeoutSeconds = 999,
                CacheTtlSeconds = 999999
            });

        Assert.Equal(300, form.TimeoutSeconds);
        Assert.Equal(86400, form.CacheTtlSeconds);
    }

    [Fact]
    public void TrojanFallbackFormInput_from_config_clamps_out_of_range_values()
    {
        var form = TrojanFallbackFormInput.FromConfig(
            new TrojanFallbackConfig
            {
                ProxyProtocolVersion = 999
            });

        Assert.Equal(2, form.ProxyProtocolVersion);
    }

    [Fact]
    public void OutboundFormInput_from_config_clamps_out_of_range_values()
    {
        var form = OutboundFormInput.FromConfig(
            new OutboundConfig
            {
                MultiplexSettings = new OutboundMultiplexConfig
                {
                    Concurrency = 99999,
                    XudpConcurrency = 99999
                },
                ServerPort = 99999,
                WebSocketEarlyDataBytes = 999999,
                WebSocketHeartbeatPeriodSeconds = 99999,
                ConnectTimeoutSeconds = 99999,
                HandshakeTimeoutSeconds = 99999
            });

        Assert.Equal(1024, form.MultiplexConcurrency);
        Assert.Equal(1024, form.MultiplexXudpConcurrency);
        Assert.Equal(65535, form.ServerPort);
        Assert.Equal(65535, form.WebSocketEarlyDataBytes);
        Assert.Equal(3600, form.WebSocketHeartbeatPeriodSeconds);
        Assert.Equal(600, form.ConnectTimeoutSeconds);
        Assert.Equal(600, form.HandshakeTimeoutSeconds);
    }

    [Fact]
    public void UserFormInput_from_record_clamps_out_of_range_values()
    {
        var form = UserFormInput.FromRecord(
            new PanelUserRecord
            {
                UserId = "user-a",
                CommissionRate = 999,
                GroupId = -1,
                BytesPerSecond = -1,
                DeviceLimit = -1,
                Subscription = new PanelUserSubscriptionProfile
                {
                    TransferEnableBytes = -1
                }
            });

        Assert.Equal(100, form.CommissionRate);
        Assert.Equal(0, form.GroupId);
        Assert.Equal(0L, form.BytesPerSecond);
        Assert.Equal(0, form.DeviceLimit);
        Assert.Equal(0L, form.TransferEnableBytes);
    }

    [Fact]
    public void PlanFormInput_from_record_clamps_out_of_range_values()
    {
        var form = PlanFormInput.FromRecord(
            new PanelPlanRecord
            {
                PlanId = "plan-a",
                GroupId = -1,
                TransferEnableBytes = -1
            });

        Assert.Equal(0, form.GroupId);
        Assert.Equal(0L, form.TransferEnableBytes);
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

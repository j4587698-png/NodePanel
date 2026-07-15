using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;

namespace NodePanel.Service.Tests;

public sealed class NodeFormInputTests
{
    [Fact]
    public void TryToRequest_maps_advanced_config_json_sections()
    {
        var form = CreateBaseForm();
        form.AdvancedConfigJson =
            """
            {
              "certificate": {
                "rejectUnknownSni": true,
                "clientHelloPolicy": {
                  "enabled": true,
                  "allowedServerNames": ["api.example.com"]
                }
              },
              "limits": {
                "connectionIdleSeconds": 120,
                "uplinkOnlySeconds": 5,
                "downlinkOnlySeconds": 6
              },
              "dns": {
                "mode": "http",
                "timeoutSeconds": 8,
                "cacheTtlSeconds": 45,
                "servers": [
                  {
                    "url": "https://dns.example/resolve",
                    "headers": {
                      "Authorization": "Bearer demo-token"
                    }
                  }
                ]
              },
              "inbounds": [
                {
                  "transport": "tls",
                  "applicationProtocols": ["h2", "http/1.1"],
                  "sniffing": {
                    "enabled": true,
                    "destinationOverride": ["tls"],
                    "domainsExcluded": ["example.org"],
                    "metadataOnly": true,
                    "routeOnly": true
                  },
                  "fallbacks": [
                    {
                      "alpn": "h2",
                      "dest": "127.0.0.1:9000"
                    }
                  ]
                }
              ],
              "outbounds": [
                {
                  "tag": "proxy",
                  "protocol": "trojan",
                  "serverHost": "edge.example.com",
                  "serverPort": 443,
                  "password": "secret"
                }
              ],
              "routingResources": {
                "resourceDirectory": "assets",
                "geoSitePath": "assets/geosite.dat",
                "geoIpPath": "assets/geoip.dat"
              },
              "routingRules": [
                {
                  "outboundTag": "proxy",
                  "domains": ["example.com"]
                }
              ]
            }
            """;

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.True(request.Config.Certificate.RejectUnknownSni);
        Assert.True(request.Config.Certificate.ClientHelloPolicy.Enabled);
        Assert.Equal(["api.example.com"], request.Config.Certificate.ClientHelloPolicy.AllowedServerNames);
        Assert.Equal(120, request.Config.Limits.ConnectionIdleSeconds);
        Assert.Equal(5, request.Config.Limits.UplinkOnlySeconds);
        Assert.Equal(6, request.Config.Limits.DownlinkOnlySeconds);
        Assert.Equal(DnsModes.Http, request.Config.Dns.Mode);
        var dnsServer = Assert.Single(request.Config.Dns.Servers);
        Assert.Equal("https://dns.example/resolve", dnsServer.Url);
        Assert.Equal("Bearer demo-token", dnsServer.Headers["Authorization"]);

        var tlsInbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(
            request.Config,
            InboundProtocols.Trojan,
            InboundTransports.Tls);
        Assert.Equal(["h2", "http/1.1"], tlsInbound.ApplicationProtocols);
        Assert.True(tlsInbound.Sniffing.Enabled);
        Assert.True(tlsInbound.Sniffing.MetadataOnly);
        Assert.True(tlsInbound.Sniffing.RouteOnly);
        Assert.Single(tlsInbound.Fallbacks);

        var wssInbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(
            request.Config,
            InboundProtocols.Trojan,
            InboundTransports.Wss);
        Assert.Empty(wssInbound.ApplicationProtocols);
        Assert.Empty(wssInbound.Fallbacks);

        var outbound = Assert.Single(request.Config.Outbounds);
        Assert.Equal("proxy", outbound.Tag);
        Assert.Equal("edge.example.com", outbound.ServerHost);
        Assert.Equal("assets", request.Config.RoutingResources.ResourceDirectory);
        Assert.Equal("assets/geosite.dat", request.Config.RoutingResources.GeoSitePath);
        Assert.Equal("assets/geoip.dat", request.Config.RoutingResources.GeoIpPath);
        Assert.Single(request.Config.RoutingRules);
    }

    [Fact]
    public void TryToRequest_maps_structured_panel_sections()
    {
        var form = CreateBaseForm();
        form.Inbounds[0].ApplicationProtocols = "h2, http/1.1";
        form.Inbounds[0].Sniffing = new InboundSniffingFormInput
        {
            Enabled = true,
            DestinationOverride = "tls, http",
            DomainsExcluded = "example.org",
            MetadataOnly = true,
            RouteOnly = true
        };
        form.Inbounds[0].Fallbacks =
        [
            new TrojanFallbackFormInput
            {
                Alpn = "h2",
                Dest = "127.0.0.1:9000"
            }
        ];
        form.Dns = new DnsFormInput
        {
            Mode = DnsModes.Http,
            TimeoutSeconds = 8,
            CacheTtlSeconds = 45,
            Servers =
            [
                new DnsServerFormInput
                {
                    Url = "https://dns.example/resolve",
                    HeadersText = "Authorization=Bearer demo-token\nX-Node=panel"
                }
            ]
        };
        form.Outbounds =
        [
            new OutboundFormInput
            {
                Tag = "proxy",
                Enabled = true,
                Protocol = OutboundProtocols.Trojan,
                Via = "eth0",
                ViaCidr = "192.0.2.0/24",
                TargetStrategy = OutboundTargetStrategies.UseIpv4,
                ProxyOutboundTag = "upstream",
                MultiplexEnabled = true,
                MultiplexConcurrency = 8,
                MultiplexXudpConcurrency = 2,
                MultiplexXudpProxyUdp443 = OutboundXudpProxyModes.Allow,
                Transport = TrojanOutboundTransports.Wss,
                ServerHost = "edge.example.com",
                ServerPort = 443,
                ServerName = "edge.example.com",
                WebSocketPath = "/ws",
                WebSocketHeadersText = "Host=edge.example.com",
                WebSocketEarlyDataBytes = 2048,
                WebSocketHeartbeatPeriodSeconds = 30,
                ApplicationProtocols = "h2",
                Password = "secret",
                ConnectTimeoutSeconds = 9,
                HandshakeTimeoutSeconds = 10,
                SkipCertificateValidation = true
            }
        ];
        form.RoutingRules =
        [
            new RoutingRuleFormInput
            {
                Enabled = true,
                InboundTags = "trojan-tcp-tls",
                Protocols = "http, tls",
                Networks = "tcp",
                UserIds = "user-a",
                Processes = "curl.exe, /usr/bin/",
                Domains = "example.com",
                SourceCidrs = "10.0.0.0/8",
                DestinationCidrs = "198.51.100.0/24",
                DestinationPorts = "443",
                SourcePorts = "50000",
                LocalCidrs = "127.0.0.0/8",
                LocalPorts = "10808-10810",
                VlessRoutes = "4360-4370",
                OutboundTag = "proxy"
            }
        ];
        form.RoutingResources = new RoutingResourceFormInput
        {
            ResourceDirectory = "assets",
            GeoSitePath = "config/geosite.dat",
            GeoIpPath = "config/geoip.dat"
        };

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);

        var tlsInbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(
            request.Config,
            InboundProtocols.Trojan,
            InboundTransports.Tls);
        Assert.Equal(["h2", "http/1.1"], tlsInbound.ApplicationProtocols);
        Assert.True(tlsInbound.Sniffing.Enabled);
        Assert.Equal(["tls", "http"], tlsInbound.Sniffing.DestinationOverride);
        Assert.Equal(["example.org"], tlsInbound.Sniffing.DomainsExcluded);
        Assert.Single(tlsInbound.Fallbacks);
        Assert.Equal("127.0.0.1:9000", tlsInbound.Fallbacks[0].Dest);

        Assert.Equal(DnsModes.Http, request.Config.Dns.Mode);
        var dnsServer = Assert.Single(request.Config.Dns.Servers);
        Assert.Equal("https://dns.example/resolve", dnsServer.Url);
        Assert.Equal("Bearer demo-token", dnsServer.Headers["Authorization"]);
        Assert.Equal("panel", dnsServer.Headers["X-Node"]);

        var outbound = Assert.Single(request.Config.Outbounds);
        Assert.Equal("proxy", outbound.Tag);
        Assert.True(outbound.Enabled);
        Assert.Equal(OutboundProtocols.Trojan, outbound.Protocol);
        Assert.Equal("eth0", outbound.Via);
        Assert.Equal("192.0.2.0/24", outbound.ViaCidr);
        Assert.Equal(OutboundTargetStrategies.UseIpv4, outbound.TargetStrategy);
        Assert.Equal("upstream", outbound.ProxyOutboundTag);
        Assert.True(outbound.MultiplexSettings.Enabled);
        Assert.Equal(8, outbound.MultiplexSettings.Concurrency);
        Assert.Equal(2, outbound.MultiplexSettings.XudpConcurrency);
        Assert.Equal(OutboundXudpProxyModes.Allow, outbound.MultiplexSettings.XudpProxyUdp443);
        Assert.Equal(TrojanOutboundTransports.Wss, outbound.Transport);
        Assert.Equal("edge.example.com", outbound.ServerHost);
        Assert.Equal(443, outbound.ServerPort);
        Assert.Equal("/ws", outbound.WebSocketPath);
        Assert.Equal("edge.example.com", outbound.WebSocketHeaders["Host"]);
        Assert.Equal(["h2"], outbound.ApplicationProtocols);
        Assert.True(outbound.SkipCertificateValidation);

        var rule = Assert.Single(request.Config.RoutingRules);
        Assert.True(rule.Enabled);
        Assert.Equal(["trojan-tcp-tls"], rule.InboundTags);
        Assert.Equal(["http", "tls"], rule.Protocols);
        Assert.Equal(["tcp"], rule.Networks);
        Assert.Equal(["user-a"], rule.UserIds);
        Assert.Equal(["curl.exe", "/usr/bin/"], rule.Processes);
        Assert.Equal(["example.com"], rule.Domains);
        Assert.Equal(["10.0.0.0/8"], rule.SourceCidrs);
        Assert.Equal(["198.51.100.0/24"], rule.DestinationCidrs);
        Assert.Equal(["443"], rule.DestinationPorts);
        Assert.Equal(["50000"], rule.SourcePorts);
        Assert.Equal(["127.0.0.0/8"], rule.LocalCidrs);
        Assert.Equal(["10808-10810"], rule.LocalPorts);
        Assert.Equal(["4360-4370"], rule.VlessRoutes);
        Assert.Equal("proxy", rule.OutboundTag);
        Assert.Equal("assets", request.Config.RoutingResources.ResourceDirectory);
        Assert.Equal("config/geosite.dat", request.Config.RoutingResources.GeoSitePath);
        Assert.Equal("config/geoip.dat", request.Config.RoutingResources.GeoIpPath);
    }

    [Fact]
    public void TryToRequest_maps_reality_server_options_only_when_reality_inbound_is_enabled()
    {
        var form = CreateBaseForm();
        form.GetOrderedTrojanInbounds();
        form.Inbounds[0].TransportSecurity = RuntimeInternetSecurityTypes.Reality;
        form.Reality = new RealityServerFormInput
        {
            ServerNames = "download.microsoft.com, update.microsoft.com",
            Dest = "download.microsoft.com:443",
            Type = "tcp",
            PrivateKey = "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
            ShortIds = "0123456789abcdef",
            MaxTimeDiffMilliseconds = 30000,
            ClientHelloPolicy = new ClientHelloPolicyFormInput
            {
                Enabled = true,
                AllowedApplicationProtocols = "h2,http/1.1"
            }
        };

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        var inbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(
            request.Config,
            InboundProtocols.Trojan,
            InboundTransports.Tls);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, inbound.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, inbound.TransportSecurity);
        Assert.NotNull(request.Config.Reality);
        Assert.Equal(["download.microsoft.com", "update.microsoft.com"], request.Config.Reality.ServerNames);
        Assert.Equal("download.microsoft.com:443", request.Config.Reality.Dest);
        Assert.Equal("tcp", request.Config.Reality.Type);
        Assert.Equal("UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc", request.Config.Reality.PrivateKey);
        Assert.Equal(["0123456789abcdef"], request.Config.Reality.ShortIds);
        Assert.Equal(30000, request.Config.Reality.MaxTimeDiffMilliseconds);
        Assert.True(request.Config.Reality.ClientHelloPolicy.Enabled);
        Assert.Equal(["h2", "http/1.1"], request.Config.Reality.ClientHelloPolicy.AllowedApplicationProtocols);
    }

    [Fact]
    public void TryToRequest_does_not_require_reality_private_key_for_tls_inbound()
    {
        var form = CreateBaseForm();
        form.GetOrderedTrojanInbounds();
        form.Inbounds[0].TransportSecurity = RuntimeInternetSecurityTypes.Tls;
        form.Reality = new RealityServerFormInput
        {
            ServerNames = "download.microsoft.com",
            Dest = "download.microsoft.com:443",
            ShortIds = "0123456789abcdef",
            PrivateKey = string.Empty
        };

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Null(request.Config.Reality);
        var inbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(
            request.Config,
            InboundProtocols.Trojan,
            InboundTransports.Tls);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, inbound.TransportSecurity);
    }

    [Fact]
    public void PrepareForEditView_applies_reality_download_site_defaults()
    {
        var form = CreateBaseForm();
        form.Reality = new RealityServerFormInput
        {
            ServerNames = string.Empty,
            Dest = string.Empty
        };

        form.PrepareForEditView();

        Assert.Equal("dl.google.com", form.Reality.ServerNames);
        Assert.Equal("dl.google.com:443", form.Reality.Dest);
    }

    [Fact]
    public void FromRecord_maps_structured_fields_and_leaves_fallback_json_empty()
    {
        var record = new PanelNodeRecord
        {
            NodeId = "node-a",
            DisplayName = "Node A",
            Protocol = InboundProtocols.Trojan,
            Config = new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "trojan-tcp-tls",
                        Enabled = true,
                        Protocol = InboundProtocols.Trojan,
                        Transport = InboundTransports.Tls,
                        ListenAddress = "0.0.0.0",
                        Port = 443,
                        ApplicationProtocols = ["h2"],
                        Sniffing = new InboundSniffingConfig
                        {
                            Enabled = true
                        },
                        Fallbacks =
                        [
                            new TrojanFallbackConfig
                            {
                                Dest = "127.0.0.1:9000"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    RejectUnknownSni = true,
                    ClientHelloPolicy = new TlsClientHelloPolicyConfig
                    {
                        Enabled = true,
                        AllowedJa3 = ["a1b2c3"]
                    }
                },
                Limits = new InboundLimitsConfig
                {
                    ConnectionIdleSeconds = 90,
                    UplinkOnlySeconds = 2,
                    DownlinkOnlySeconds = 3
                },
                Dns = new DnsOptions
                {
                    Mode = DnsModes.Http,
                    Servers =
                    [
                        new DnsHttpServerConfig
                        {
                            Url = "https://dns.example/resolve"
                        }
                    ]
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "proxy",
                        Protocol = OutboundProtocols.Trojan,
                        ServerHost = "edge.example.com",
                        ServerPort = 443,
                        Password = "secret"
                    }
                ],
                RoutingResources = new RoutingResourceOptions
                {
                    ResourceDirectory = "assets",
                    GeoSitePath = "assets/geosite.dat",
                    GeoIpPath = "assets/geoip.dat"
                },
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        OutboundTag = "proxy",
                        Processes = ["curl.exe", "/usr/bin/"],
                        Domains = ["example.com"],
                        DestinationCidrs = ["198.51.100.0/24"],
                        SourcePorts = ["50000"],
                        LocalCidrs = ["127.0.0.0/8"],
                        LocalPorts = ["10808-10810"],
                        VlessRoutes = ["4360-4370"]
                    }
                ]
            }
        };

        var form = NodeFormInput.FromRecord(record);

        Assert.True(string.IsNullOrWhiteSpace(form.AdvancedConfigJson));
        Assert.True(form.CertificateRejectUnknownSni);
        Assert.True(form.CertificateClientHelloPolicy.Enabled);
        Assert.Equal("a1b2c3", form.CertificateClientHelloPolicy.AllowedJa3);
        Assert.Equal(90, form.ConnectionIdleSeconds);
        Assert.Equal(2, form.UplinkOnlySeconds);
        Assert.Equal(3, form.DownlinkOnlySeconds);
        Assert.Equal(DnsModes.Http, form.Dns.Mode);
        Assert.Equal("https://dns.example/resolve", Assert.Single(form.Dns.Servers).Url);
        Assert.Equal("proxy", Assert.Single(form.Outbounds).Tag);
        Assert.Equal("assets", form.RoutingResources.ResourceDirectory);
        Assert.Equal("assets/geosite.dat", form.RoutingResources.GeoSitePath);
        Assert.Equal("assets/geoip.dat", form.RoutingResources.GeoIpPath);
        Assert.Equal("curl.exe, /usr/bin/", Assert.Single(form.RoutingRules).Processes);
        Assert.Equal("example.com", Assert.Single(form.RoutingRules).Domains);
        Assert.Equal("198.51.100.0/24", Assert.Single(form.RoutingRules).DestinationCidrs);
        Assert.Equal("50000", Assert.Single(form.RoutingRules).SourcePorts);
        Assert.Equal("127.0.0.0/8", Assert.Single(form.RoutingRules).LocalCidrs);
        Assert.Equal("10808-10810", Assert.Single(form.RoutingRules).LocalPorts);
        Assert.Equal("4360-4370", Assert.Single(form.RoutingRules).VlessRoutes);
        Assert.Equal("h2", form.Inbounds[0].ApplicationProtocols);
        Assert.True(form.Inbounds[0].Sniffing.Enabled);
        Assert.Equal("127.0.0.1:9000", Assert.Single(form.Inbounds[0].Fallbacks).Dest);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal("assets", request.Config.RoutingResources.ResourceDirectory);
        Assert.Equal("assets/geosite.dat", request.Config.RoutingResources.GeoSitePath);
        Assert.Equal("assets/geoip.dat", request.Config.RoutingResources.GeoIpPath);
    }

    [Fact]
    public void FromRecord_maps_reality_server_options_and_security_selection()
    {
        var record = new PanelNodeRecord
        {
            NodeId = "node-reality",
            DisplayName = "Node Reality",
            Protocol = InboundProtocols.Vless,
            Config = new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vless-tcp-reality",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = RuntimeInternetTransportProtocols.Tcp,
                        TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                        TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                        ListenAddress = "0.0.0.0",
                        Port = 443
                    }
                ],
                Reality = new RuntimeRealityServerOptions
                {
                    ServerNames = ["download.microsoft.com", "update.microsoft.com"],
                    Dest = "download.microsoft.com:443",
                    Type = "tcp",
                    PrivateKey = "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
                    ShortIds = ["0123456789abcdef"],
                    MaxTimeDiffMilliseconds = 30000,
                    ClientHelloPolicy = new RuntimeTlsClientHelloPolicyOptions
                    {
                        Enabled = true,
                        AllowedApplicationProtocols = ["h2", "http/1.1"]
                    }
                }
            }
        };

        var form = NodeFormInput.FromRecord(record);

        Assert.Equal(RuntimeInternetSecurityTypes.Reality, form.Inbounds[0].TransportSecurity);
        Assert.Equal("download.microsoft.com, update.microsoft.com", form.Reality.ServerNames);
        Assert.Equal("download.microsoft.com:443", form.Reality.Dest);
        Assert.Equal("UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc", form.Reality.PrivateKey);
        Assert.Equal("0123456789abcdef", form.Reality.ShortIds);
        Assert.Equal(30000, form.Reality.MaxTimeDiffMilliseconds);
        Assert.True(form.Reality.ClientHelloPolicy.Enabled);
        Assert.Equal("h2, http/1.1", form.Reality.ClientHelloPolicy.AllowedApplicationProtocols);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.NotNull(request.Config.Reality);
        Assert.Equal(["download.microsoft.com", "update.microsoft.com"], request.Config.Reality.ServerNames);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, request.Config.Inbounds[0].TransportSecurity);
    }

    [Theory]
    [InlineData("vmess")]
    [InlineData("vless")]
    public void TryToRequest_uses_selected_protocol_for_all_inbounds(string protocol)
    {
        var form = CreateBaseForm();
        form.Protocol = protocol;

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal(protocol, InboundProtocols.Normalize(request.Protocol));
        Assert.All(request.Config.Inbounds, inbound => Assert.Equal(protocol, InboundProtocols.Normalize(inbound.Protocol)));
        Assert.Equal(
            protocol,
            InboundProtocols.Normalize(NodeServiceConfigInbounds.GetProtocolTransportInbound(request.Config, protocol, InboundTransports.Tls).Protocol));
        Assert.Equal(
            protocol,
            InboundProtocols.Normalize(NodeServiceConfigInbounds.GetProtocolTransportInbound(request.Config, protocol, InboundTransports.Wss).Protocol));
    }

    [Fact]
    public void TryToRequest_allows_round_trip_without_enabled_remote_inbounds()
    {
        var form = NodeFormInput.FromRecord(
            new PanelNodeRecord
            {
                NodeId = "node-disabled",
                DisplayName = "Disabled Node",
                Protocol = InboundProtocols.Vless,
                Config = new NodeServiceConfig
                {
                    Inbounds =
                    [
                        NodeServiceConfigInbounds.CreateDefaultInbound(InboundProtocols.Vless, InboundTransports.Tls),
                        NodeServiceConfigInbounds.CreateDefaultInbound(InboundProtocols.Vless, InboundTransports.Wss)
                    ]
                }
            });

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal(InboundProtocols.Vless, InboundProtocols.Normalize(request.Protocol));
        Assert.Equal(5, request.Config.Inbounds.Count);
        Assert.All(request.Config.Inbounds, static inbound => Assert.False(inbound.Enabled));
    }

    [Fact]
    public void TryToRequest_builds_shadowsocks_tcp_inbound_only()
    {
        var form = CreateBaseForm();
        form.Protocol = InboundProtocols.Shadowsocks;
        form.GetOrderedTrojanInbounds();
        foreach (var inbound in form.Inbounds)
        {
            inbound.Enabled = false;
        }

        form.Inbounds[5].Enabled = true;
        form.Inbounds[5].ListenAddress = "127.0.0.1";
        form.Inbounds[5].Port = 8388;

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        var inboundConfig = Assert.Single(request.Config.Inbounds);
        Assert.Equal(InboundProtocols.Shadowsocks, InboundProtocols.Normalize(inboundConfig.Protocol));
        Assert.Equal(InboundTransports.Tcp, InboundTransports.Normalize(inboundConfig.Transport));
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, inboundConfig.TransportProtocol);
        Assert.Equal("127.0.0.1", inboundConfig.ListenAddress);
        Assert.Equal(8388, inboundConfig.Port);
    }

    [Fact]
    public void TryToRequest_refreshes_generated_tags_and_grpc_service_name_after_protocol_switch()
    {
        var form = CreateBaseForm();
        form.GetOrderedTrojanInbounds();
        form.Protocol = InboundProtocols.Vless;
        form.Inbounds[0].Enabled = true;
        form.Inbounds[1].Enabled = false;
        form.Inbounds[2].Enabled = false;
        form.Inbounds[3].Enabled = true;
        form.Inbounds[4].Enabled = false;
        form.Inbounds[3].GrpcServiceName = TrojanInboundFormInput.GetDefaultGrpcServiceName(InboundProtocols.Trojan);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        var tlsInbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(request.Config, InboundProtocols.Vless, InboundTransports.Tls);
        var grpcInbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(request.Config, InboundProtocols.Vless, InboundTransports.Grpc);
        Assert.Equal("vless-tcp-tls", tlsInbound.Tag);
        Assert.Equal("vless-grpc", grpcInbound.Tag);
        Assert.Equal("/vless/service", grpcInbound.GrpcServiceName);
    }

    [Fact]
    public void TryParse_advanced_config_accepts_tcp_httpupgrade_grpc_and_splithttp_inbounds()
    {
        const string json =
            """
            {
              "inbounds": [
                { "transport": "tcp" },
                { "transport": "http-upgrade" },
                { "transport": "grpc" },
                { "transport": "split-http" }
              ]
            }
            """;

        var success = NodeAdvancedConfigInput.TryParse(json, out var input, out var error);

        Assert.True(success, error);
        Assert.Equal(
            [InboundTransports.Tcp, InboundTransports.HttpUpgrade, InboundTransports.Grpc, InboundTransports.SplitHttp],
            input.Inbounds!.Select(static inbound => inbound.Transport).ToArray());
    }

    [Fact]
    public void FromRecord_preserves_grpc_advanced_inbound_settings_inside_advanced_json()
    {
        var record = new PanelNodeRecord
        {
            NodeId = "node-grpc",
            DisplayName = "Node gRPC",
            Protocol = InboundProtocols.Vmess,
            Config = new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vmess-grpc",
                        Enabled = true,
                        Protocol = InboundProtocols.Vmess,
                        Transport = InboundTransports.Grpc,
                        TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                        TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                        ListenAddress = "0.0.0.0",
                        Port = 443,
                        GrpcServiceName = "/vmess/service",
                        ApplicationProtocols = ["h2"],
                        Sniffing = new InboundSniffingConfig
                        {
                            Enabled = true
                        }
                    }
                ]
            }
        };

        var form = NodeFormInput.FromRecord(record);

        Assert.Contains("\"transport\": \"grpc\"", form.AdvancedConfigJson, StringComparison.Ordinal);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        var grpcInbound = NodeServiceConfigInbounds.GetProtocolTransportInbound(request.Config, InboundProtocols.Vmess, InboundTransports.Grpc);
        Assert.Equal(["h2"], grpcInbound.ApplicationProtocols);
        Assert.True(grpcInbound.Sniffing.Enabled);
    }

    [Fact]
    public void Subscription_metadata_round_trips_between_form_request_and_record()
    {
        var form = CreateBaseForm();
        form.SubscriptionRegion = "香港";
        form.SubscriptionTags = "stream, ai, stream";

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal("香港", request.SubscriptionRegion);
        Assert.Equal(["stream", "ai"], request.SubscriptionTags);

        var record = new PanelNodeRecord
        {
            NodeId = "node-a",
            DisplayName = "Node A",
            Protocol = InboundProtocols.Trojan,
            SubscriptionRegion = request.SubscriptionRegion,
            SubscriptionTags = request.SubscriptionTags,
            Config = request.Config
        };

        var rebound = NodeFormInput.FromRecord(record);
        Assert.Equal("香港", rebound.SubscriptionRegion);
        Assert.Equal("stream, ai", rebound.SubscriptionTags);
    }

    [Fact]
    public void Local_inbounds_round_trip_through_advanced_config_json()
    {
        var record = new PanelNodeRecord
        {
            NodeId = "node-local",
            DisplayName = "Node Local",
            Protocol = InboundProtocols.Trojan,
            Config = new NodeServiceConfig
            {
                ProxyInbounds =
                [
                    new ProxyInboundConfig
                    {
                        Tag = "socks-local",
                        Enabled = true,
                        Protocol = ProxyInboundProtocols.Socks,
                        ListenAddress = "127.0.0.1",
                        Port = 10808,
                        HandshakeTimeoutSeconds = 12
                    },
                    new ProxyInboundConfig
                    {
                        Tag = "http-local",
                        Enabled = true,
                        Protocol = ProxyInboundProtocols.Http,
                        ListenAddress = "127.0.0.1",
                        Port = 10809,
                        HandshakeTimeoutSeconds = 15
                    }
                ]
            }
        };

        var form = NodeFormInput.FromRecord(record);

        Assert.Contains("\"proxyInbounds\"", form.AdvancedConfigJson, StringComparison.Ordinal);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal(2, request.Config.ProxyInbounds.Count);
        Assert.Equal("socks-local", request.Config.ProxyInbounds[0].Tag);
        Assert.Equal(ProxyInboundProtocols.Socks, request.Config.ProxyInbounds[0].Protocol);
        Assert.Equal("http-local", request.Config.ProxyInbounds[1].Tag);
        Assert.Equal(ProxyInboundProtocols.Http, request.Config.ProxyInbounds[1].Protocol);
    }

    [Fact]
    public void Strategy_outbounds_round_trip_with_structured_outbounds()
    {
        var record = new PanelNodeRecord
        {
            NodeId = "node-strategy",
            DisplayName = "Node Strategy",
            Protocol = InboundProtocols.Trojan,
            Config = new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    },
                    new OutboundConfig
                    {
                        Tag = "proxy",
                        Enabled = true,
                        Protocol = OutboundProtocols.Trojan,
                        ServerHost = "edge.example.com",
                        ServerPort = 443,
                        Password = "secret"
                    },
                    new OutboundConfig
                    {
                        Tag = "auto",
                        Enabled = true,
                        Protocol = OutboundProtocols.Selector,
                        CandidateTags = ["proxy", "direct"],
                        SelectedTag = "proxy",
                        ProbeUrl = "https://probe.example/test"
                    }
                ]
            }
        };

        var form = NodeFormInput.FromRecord(record);

        Assert.Equal(2, form.Outbounds.Count);
        Assert.Contains("\"auto\"", form.AdvancedConfigJson, StringComparison.Ordinal);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal(3, request.Config.Outbounds.Count);
        var strategyOutbound = Assert.Single(
            request.Config.Outbounds,
            static outbound => string.Equals(outbound.Tag, "auto", StringComparison.Ordinal));
        Assert.Equal(OutboundProtocols.Selector, strategyOutbound.Protocol);
        Assert.Equal(["proxy", "direct"], strategyOutbound.CandidateTags);
        Assert.Equal("proxy", strategyOutbound.SelectedTag);
    }

    [Fact]
    public void Vless_reverse_outbounds_round_trip_with_advanced_config()
    {
        var record = new PanelNodeRecord
        {
            NodeId = "node-reverse",
            DisplayName = "Node Reverse",
            Protocol = InboundProtocols.Trojan,
            Config = new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    },
                    new OutboundConfig
                    {
                        Tag = "reverse-proxy",
                        Enabled = true,
                        Protocol = OutboundProtocols.Vless,
                        ServerHost = "edge.example.com",
                        ServerPort = 443,
                        ReverseTag = "reverse-edge"
                    }
                ]
            }
        };

        var form = NodeFormInput.FromRecord(record);

        Assert.Single(form.Outbounds);
        Assert.Equal("direct", form.Outbounds[0].Tag);
        Assert.Contains("\"reverseTag\": \"reverse-edge\"", form.AdvancedConfigJson, StringComparison.Ordinal);

        var success = form.TryToRequest(out var request, out var error);

        Assert.True(success, error);
        Assert.Equal(2, request.Config.Outbounds.Count);
        var reverseOutbound = Assert.Single(
            request.Config.Outbounds,
            static outbound => string.Equals(outbound.Tag, "reverse-proxy", StringComparison.Ordinal));
        Assert.Equal(OutboundProtocols.Vless, reverseOutbound.Protocol);
        Assert.Equal("reverse-edge", reverseOutbound.ReverseTag);
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

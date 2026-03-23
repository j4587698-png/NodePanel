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
                Domains = "example.com",
                SourceCidrs = "10.0.0.0/8",
                DestinationPorts = "443",
                OutboundTag = "proxy"
            }
        ];

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
        Assert.Equal(["example.com"], rule.Domains);
        Assert.Equal(["10.0.0.0/8"], rule.SourceCidrs);
        Assert.Equal(["443"], rule.DestinationPorts);
        Assert.Equal("proxy", rule.OutboundTag);
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
                Limits = new TrojanInboundLimits
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
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        OutboundTag = "proxy",
                        Domains = ["example.com"]
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
        Assert.Equal("example.com", Assert.Single(form.RoutingRules).Domains);
        Assert.Equal("h2", form.Inbounds[0].ApplicationProtocols);
        Assert.True(form.Inbounds[0].Sniffing.Enabled);
        Assert.Equal("127.0.0.1:9000", Assert.Single(form.Inbounds[0].Fallbacks).Dest);
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

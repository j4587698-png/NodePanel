using System.Net;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Runtime;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Tests;

public sealed class NodeRuntimeSnapshotBuilderTests
{
    [Fact]
    public void TryBuild_builds_runtime_snapshot_with_host_metadata()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            7,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " trojan-entry ",
                        Enabled = true,
                        Protocol = " TROJAN ",
                        Transport = " TLS ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 18443,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = " demo-user ",
                                Password = " secret ",
                                BytesPerSecond = 2048,
                                DeviceLimit = 2
                            }
                        ]
                    }
                ],
                ProxyInbounds =
                [
                    new ProxyInboundConfig
                    {
                        Tag = " socks-local ",
                        Enabled = true,
                        Protocol = " SOCKS ",
                        ListenAddress = " ",
                        Port = -1,
                        HandshakeTimeoutSeconds = 0
                    },
                    new ProxyInboundConfig
                    {
                        Tag = "http-local",
                        Enabled = true,
                        Protocol = " HTTP ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 10809,
                        HandshakeTimeoutSeconds = 15
                    }
                ],
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
                        Tag = " edge ",
                        Enabled = true,
                        Protocol = " TROJAN ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        ServerName = " edge.example.com ",
                        Transport = " WSS ",
                        WebSocketPath = " ws ",
                        WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" Host "] = " edge.example.com "
                        },
                        ApplicationProtocols = [" h2 "],
                        Password = " secret ",
                        ConnectTimeoutSeconds = 12,
                        HandshakeTimeoutSeconds = 18
                    },
                    new OutboundConfig
                    {
                        Tag = " auto ",
                        Enabled = true,
                        Protocol = " selector ",
                        CandidateTags = [" direct ", " edge "],
                        SelectedTag = " edge "
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                },
                Dns = new DnsOptions
                {
                    Mode = " HTTP ",
                    TimeoutSeconds = 6,
                    CacheTtlSeconds = 45,
                    Servers =
                    [
                        new DnsHttpServerConfig
                        {
                            Url = " https://dns.example/resolve ",
                            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                            {
                                [" Authorization "] = " Bearer demo-token "
                            }
                        }
                    ]
                },
                Limits = new InboundLimitsConfig
                {
                    GlobalBytesPerSecond = 4096,
                    ConnectTimeoutSeconds = 11,
                    ConnectionIdleSeconds = 301,
                    UplinkOnlySeconds = 2,
                    DownlinkOnlySeconds = 3
                }
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Trojan, OutboundProtocols.Selector],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.RequiresCertificate);
        Assert.Equal(7, snapshot.Revision);
        Assert.Equal(4096, snapshot.TransportLimits.GlobalBytesPerSecond);
        Assert.Equal(11, snapshot.TransportLimits.ConnectTimeoutSeconds);
        Assert.Equal(301, snapshot.TransportLimits.ConnectionIdleSeconds);
        Assert.Equal(2, snapshot.TransportLimits.UplinkOnlySeconds);
        Assert.Equal(3, snapshot.TransportLimits.DownlinkOnlySeconds);

        Assert.Equal(DnsModes.Http, snapshot.Dns.Mode);
        Assert.Equal(6, snapshot.Dns.TimeoutSeconds);
        Assert.Equal(45, snapshot.Dns.CacheTtlSeconds);
        var dnsServer = Assert.Single(snapshot.Dns.Servers);
        Assert.Equal("https://dns.example/resolve", dnsServer.Url);
        Assert.Equal("Bearer demo-token", dnsServer.Headers["Authorization"]);

        Assert.Collection(
            snapshot.ProxyInbounds.SocksListeners,
            listener =>
            {
                Assert.Equal("socks-local", listener.Tag);
                Assert.Equal("127.0.0.1", listener.Binding.ListenAddress);
                Assert.Equal(10808, listener.Binding.Port);
                Assert.Equal(10, listener.HandshakeTimeoutSeconds);
            });
        Assert.Collection(
            snapshot.ProxyInbounds.HttpListeners,
            listener =>
            {
                Assert.Equal("http-local", listener.Tag);
                Assert.Equal("127.0.0.1", listener.Binding.ListenAddress);
                Assert.Equal(10809, listener.Binding.Port);
                Assert.Equal(15, listener.HandshakeTimeoutSeconds);
            });

        Assert.True(snapshot.OutboundSettings.TryGetTrojan("edge", out var trojan));
        Assert.Equal("edge.example.com", trojan.ServerHost);
        Assert.Equal(TrojanOutboundTransports.Wss, trojan.Transport);
        Assert.Equal("/ws", trojan.WebSocketPath);
        Assert.Equal("edge.example.com", trojan.WebSocketHeaders["Host"]);
        Assert.Equal(["http/1.1"], trojan.ApplicationProtocols);
        Assert.Equal(12, trojan.ConnectTimeoutSeconds);
        Assert.Equal(18, trojan.HandshakeTimeoutSeconds);

        var user = Assert.Single(snapshot.ActiveUsers);
        Assert.Equal("demo-user", user.UserId);
        Assert.Equal(2048, user.BytesPerSecond);
        Assert.Equal(2, user.DeviceLimit);

        var runtimePlan = snapshot.CreateRuntimePlan(useCone: false);
        Assert.Equal(snapshot.Revision, runtimePlan.Revision);
        Assert.Equal(snapshot.Plan, runtimePlan.Plan);
        Assert.Equal(snapshot.TransportLimits, runtimePlan.TransportLimits);
        Assert.Equal(snapshot.SessionPolicies, runtimePlan.SessionPolicies);
        Assert.Equal(snapshot.Dns, runtimePlan.Dns);
        Assert.Equal(snapshot.ProxyInbounds, runtimePlan.ProxyInbounds);
        Assert.Equal(snapshot.OutboundSettings, runtimePlan.OutboundSettings);
        Assert.False(runtimePlan.UseCone);
        Assert.Null(runtimePlan.Tls);

    }

    [Fact]
    public void TryBuild_defaults_acme_managed_certificate_path_when_empty()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            1,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "trojan-entry",
                        Enabled = true,
                        Protocol = InboundProtocols.Trojan,
                        Transport = InboundTransports.Tls,
                        ListenAddress = "127.0.0.1",
                        Port = 443,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "demo-user",
                                Password = "secret"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    Mode = CertificateModes.AcmeManaged,
                    Domain = " edge.example.com "
                }
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.Equal(
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "certificates", "acme-managed", "edge.example.com.pfx")),
            snapshot.Config.Certificate.PfxPath);
    }

    [Fact]
    public void TryBuild_builds_http_local_proxy_authentication_and_transparent_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            2,
            new NodeServiceConfig
            {
                ProxyInbounds =
                [
                    new ProxyInboundConfig
                    {
                        Tag = " http-local ",
                        Enabled = true,
                        Protocol = " HTTP ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 10809,
                        HandshakeTimeoutSeconds = 0,
                        AllowTransparent = true,
                        HttpUsers =
                        [
                            new LocalSocksUserConfig
                            {
                                Username = " alice ",
                                Password = "secret"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var config = Assert.Single(snapshot.Config.ProxyInbounds);
        Assert.Equal("http-local", config.Tag);
        Assert.Equal(ProxyInboundProtocols.Http, config.Protocol);
        Assert.Equal("127.0.0.1", config.ListenAddress);
        Assert.Equal(10809, config.Port);
        Assert.Equal(10, config.HandshakeTimeoutSeconds);
        Assert.True(config.AllowTransparent);
        var httpUser = Assert.Single(config.HttpUsers);
        Assert.Equal("alice", httpUser.Username);

        var listener = Assert.Single(snapshot.ProxyInbounds.HttpListeners);
        Assert.Equal("http-local", listener.Tag);
        Assert.True(listener.AllowTransparent);

        Assert.True(snapshot.ProxyInbounds.HttpAuthenticationsByTag.TryGetValue("http-local", out var authentication));
        Assert.NotNull(authentication);
        Assert.True(authentication!.Enabled);
        Assert.True(authentication.TryAuthenticate("alice", "secret"));
    }

    [Fact]
    public void TryBuild_accepts_proxy_inbound_null_user_lists_and_normalizes_them_to_empty()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            3,
            new NodeServiceConfig
            {
                ProxyInbounds =
                [
                    new ProxyInboundConfig
                    {
                        Tag = " socks-local ",
                        Enabled = true,
                        Protocol = " SOCKS ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 10808,
                        SocksUsers = null!,
                        HttpUsers = null!
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var proxyInbound = Assert.Single(snapshot.Config.ProxyInbounds);
        Assert.NotNull(proxyInbound.SocksUsers);
        Assert.NotNull(proxyInbound.HttpUsers);
        Assert.Empty(proxyInbound.SocksUsers);
        Assert.Empty(proxyInbound.HttpUsers);

        var listener = Assert.Single(snapshot.ProxyInbounds.SocksListeners);
        Assert.Equal("socks-local", listener.Tag);
        Assert.False(snapshot.ProxyInbounds.SocksAuthenticationsByTag.ContainsKey("socks-local"));
    }

    [Fact]
    public void TryBuild_normalizes_routing_rule_attributes_and_enables_content_routing()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
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
                        Tag = "http-api",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        RuleTag = " http-api-rule ",
                        OutboundTag = " http-api ",
                        Protocols = [" HTTP "],
                        DestinationCidrs = [" 198.51.100.0/24 "],
                        SourcePorts = [" 50000 "],
                        LocalCidrs = [" 127.0.0.0/8 "],
                        LocalPorts = [" 10808-10810 "],
                        VlessRoutes = [" 4360-4370 "],
                        Attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" :path "] = " /api ",
                            [" X-Test "] = " peach$ "
                        }
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedRule = Assert.Single(snapshot.Config.RoutingRules);
        Assert.Equal("http-api-rule", normalizedRule.RuleTag);
        Assert.Equal("/api", normalizedRule.Attributes[":path"]);
        Assert.Equal("peach$", normalizedRule.Attributes["x-test"]);
        Assert.Equal(["198.51.100.0/24"], normalizedRule.DestinationCidrs);
        Assert.Equal(["50000"], normalizedRule.SourcePorts);
        Assert.Equal(["127.0.0.0/8"], normalizedRule.LocalCidrs);
        Assert.Equal(["10808-10810"], normalizedRule.LocalPorts);
        Assert.Equal(["4360-4370"], normalizedRule.VlessRoutes);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                OriginalDestinationHost = "198.51.100.7",
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10809),
                VlessRoutePort = 4369,
                Content = new DispatchContent
                {
                    Protocol = "http/1.1",
                    Attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [":path"] = "/api/v1",
                        ["x-test"] = "yellow-peach"
                    }
                }
            },
            out var matchedTag));
        Assert.Equal("http-api", matchedTag);
        Assert.True(snapshot.Plan.Outbound.TryPickRoute(
            new DispatchContext
            {
                OriginalDestinationHost = "198.51.100.7",
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10809),
                VlessRoutePort = 4369,
                Content = new DispatchContent
                {
                    Protocol = "http/1.1",
                    Attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [":path"] = "/api/v1",
                        ["x-test"] = "yellow-peach"
                    }
                }
            },
            out var route));
        Assert.Equal("http-api", route.OutboundTag);
        Assert.Equal("http-api-rule", route.RuleTag);
    }

    [Fact]
    public void TryBuild_trims_routing_rule_domains_and_preserves_xray_domain_semantics()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            5,
            new NodeServiceConfig
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
                        Tag = "domain-route",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        OutboundTag = " domain-route ",
                        Domains =
                        [
                            " example.com ",
                            " domain:google.com ",
                            " full:api.full-match.test ",
                            " regexp:^facebook\\.com$ ",
                            " dotless:local "
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedRule = Assert.Single(snapshot.Config.RoutingRules);
        Assert.Equal(
            ["example.com", "domain:google.com", "full:api.full-match.test", "regexp:^facebook\\.com$", "dotless:local"],
            normalizedRule.Domains);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "www.example.com.www"
            },
            out var plainTag));
        Assert.Equal("domain-route", plainTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "www.google.com"
            },
            out var domainTag));
        Assert.Equal("domain-route", domainTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "api.full-match.test"
            },
            out var fullTag));
        Assert.Equal("domain-route", fullTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "facebook.com"
            },
            out var regexTag));
        Assert.Equal("domain-route", regexTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "mylocal"
            },
            out var dotlessTag));
        Assert.Equal("domain-route", dotlessTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                DetectedDomain = "www.facebook.com"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryBuild_preserves_user_rule_case_and_enables_user_regexp_matching()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            6,
            new NodeServiceConfig
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
                        Tag = "user-route",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        OutboundTag = " user-route ",
                        UserIds =
                        [
                            " Admin@example.com ",
                            " admin@example.com ",
                            " regexp:^svc-[0-9]+$ "
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedRule = Assert.Single(snapshot.Config.RoutingRules);
        Assert.Equal(
            ["Admin@example.com", "admin@example.com", "regexp:^svc-[0-9]+$"],
            normalizedRule.UserIds);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "svc-12"
            },
            out var matchedTag));
        Assert.Equal("user-route", matchedTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                UserId = "SVC-12"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryBuild_normalizes_routing_rule_processes_and_enables_process_routing()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            7,
            new NodeServiceConfig
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
                        Tag = "process-route",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        OutboundTag = " process-route ",
                        Processes =
                        [
                            " curl.exe ",
                            @" C:\Apps\svc.exe ",
                            " /usr/bin/ ",
                            " self/ "
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedRule = Assert.Single(snapshot.Config.RoutingRules);
        Assert.Equal(
            ["curl.exe", @"C:\Apps\svc.exe", "/usr/bin/", "self/"],
            normalizedRule.Processes);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessPath = "/usr/bin/curl"
            },
            out var matchedTag));
        Assert.Equal("process-route", matchedTag);

        Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
            new DispatchContext
            {
                ProcessName = "CURL"
            },
            out var fallbackTag));
        Assert.Equal("direct", fallbackTag);
    }

    [Fact]
    public void TryBuild_rejects_unsupported_inbound_protocol_when_compiler_missing()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            1,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vmess-entry",
                        Enabled = true,
                        Protocol = InboundProtocols.Vmess,
                        Transport = InboundTransports.Tls,
                        ListenAddress = "127.0.0.1",
                        Port = 3443
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Equal("Unsupported inbound protocol: vmess.", error);
    }

    [Fact]
    public void TryBuild_builds_dokodemo_plan_from_unified_inbounds()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler(),
            new DokodemoInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            2,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " dokodemo-entry ",
                        Enabled = true,
                        Protocol = " TUNNEL ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 15353,
                        DestinationHost = " dns.google ",
                        DestinationPort = 53,
                        PortMap = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            [" 15353 "] = " 127.0.0.1:5353 "
                        },
                        Networks = [" UDP ", " udp "],
                        UserLevel = 6,
                        Mark = 88,
                        FollowRedirect = true,
                        Sniffing = new InboundSniffingConfig
                        {
                            Enabled = true,
                            DestinationOverride = [" HTTP ", " TLS "],
                            DomainsExcluded = [" Example.COM "],
                            MetadataOnly = true,
                            RouteOnly = true
                        }
                    }
                ],
                Limits = new InboundLimitsConfig
                {
                    ConnectTimeoutSeconds = 12,
                    ConnectionIdleSeconds = 310,
                    UplinkOnlySeconds = 2,
                    DownlinkOnlySeconds = 3
                },
                Policy = new PolicyConfig
                {
                    Level = new Dictionary<int, SessionLevelPolicyConfig>
                    {
                        [6] = new()
                        {
                            Timeout = new SessionTimeoutPolicyConfig
                            {
                                Handshake = 70,
                                ConnectionIdle = 44,
                                UplinkOnly = 5,
                                DownlinkOnly = 6
                            }
                        }
                    }
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedInbound = Assert.Single(snapshot.Config.Inbounds);
        Assert.Equal("dokodemo-entry", normalizedInbound.Tag);
        Assert.Equal(InboundProtocols.DokodemoDoor, normalizedInbound.Protocol);
        Assert.Equal("127.0.0.1", normalizedInbound.ListenAddress);
        Assert.Equal("dns.google", normalizedInbound.DestinationHost);
        Assert.Equal(53, normalizedInbound.DestinationPort);
        Assert.Equal(["udp"], normalizedInbound.Networks);
        Assert.Equal("127.0.0.1:5353", normalizedInbound.PortMap["15353"]);
        Assert.Equal(6, normalizedInbound.UserLevel);
        Assert.Equal(88, normalizedInbound.Mark);
        Assert.True(normalizedInbound.FollowRedirect);
        Assert.Equal(["http", "tls"], normalizedInbound.Sniffing.DestinationOverride);
        Assert.Equal(["example.com"], normalizedInbound.Sniffing.DomainsExcluded);
        Assert.True(normalizedInbound.Sniffing.MetadataOnly);
        Assert.True(normalizedInbound.Sniffing.RouteOnly);

        var plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.DokodemoDoor, DokodemoInboundRuntimePlan.Empty);
        var inbound = Assert.Single(plan.Inbounds);
        Assert.Equal("dokodemo-entry", inbound.Tag);
        Assert.Equal("127.0.0.1", inbound.Binding.ListenAddress);
        Assert.Equal(15353, inbound.Binding.Port);
        Assert.True(inbound.HasUdp);
        Assert.False(inbound.HasTcp);
        Assert.Equal(6, inbound.UserLevel);
        Assert.Equal(88, inbound.Mark);
        Assert.True(inbound.FollowRedirect);
        Assert.Equal("dns.google", inbound.DestinationHost);
        Assert.Equal(53, inbound.DestinationPort);
        Assert.Equal("127.0.0.1:5353", inbound.PortMap["15353"]);
        Assert.True(inbound.Sniffing.Enabled);
        Assert.Equal(["http", "tls"], inbound.Sniffing.DestinationOverride);
        Assert.Equal(["example.com"], inbound.Sniffing.DomainsExcluded);
        Assert.True(inbound.Sniffing.MetadataOnly);
        Assert.True(inbound.Sniffing.RouteOnly);
        Assert.Equal(310, snapshot.SessionPolicies.DefaultPolicy.Timeout.ConnectionIdleSeconds);
        Assert.Equal(2, snapshot.SessionPolicies.DefaultPolicy.Timeout.UplinkOnlySeconds);
        Assert.Equal(3, snapshot.SessionPolicies.DefaultPolicy.Timeout.DownlinkOnlySeconds);
        var levelPolicy = snapshot.SessionPolicies.ForLevel(6);
        Assert.Equal(70, levelPolicy.Timeout.HandshakeSeconds);
        Assert.Equal(44, levelPolicy.Timeout.ConnectionIdleSeconds);
        Assert.Equal(5, levelPolicy.Timeout.UplinkOnlySeconds);
        Assert.Equal(6, levelPolicy.Timeout.DownlinkOnlySeconds);
        Assert.Empty(snapshot.ActiveUsers);
    }

    [Fact]
    public void TryBuild_builds_vless_and_vmess_plans_from_shared_compilers()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler(),
            new VlessInboundRuntimeCompiler(),
            new VmessInboundRuntimeCompiler()
        ]);

        var vlessUuid = Guid.NewGuid().ToString("D");
        var vmessUuid = Guid.NewGuid().ToString("D");
        var success = builder.TryBuild(
            3,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vless-entry",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = InboundTransports.Tls,
                        ListenAddress = "127.0.0.1",
                        Port = 2443,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "vless-user",
                                Uuid = vlessUuid,
                                BytesPerSecond = 1024,
                                DeviceLimit = 1
                            }
                        ]
                    },
                    new InboundConfig
                    {
                        Tag = "vmess-entry",
                        Enabled = true,
                        Protocol = InboundProtocols.Vmess,
                        Transport = InboundTransports.Wss,
                        ListenAddress = "127.0.0.1",
                        Port = 3444,
                        Path = "vmess",
                        Host = "edge.example.com",
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "vmess-user",
                                Uuid = vmessUuid,
                                BytesPerSecond = 2048,
                                DeviceLimit = 3
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                }
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var vlessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty);
        var vlessListener = Assert.Single(vlessPlan.TlsListeners);
        Assert.Equal("vless-entry", vlessListener.RawTlsInbound!.Tag);
        var vlessUser = Assert.Single(vlessListener.RawTlsInbound.UsersByUuid);
        Assert.Equal(vlessUuid, vlessUser.Key);
        Assert.Equal("vless-user", vlessUser.Value.UserId);

        var vmessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
        var vmessListener = Assert.Single(vmessPlan.TlsListeners);
        Assert.Equal(["http/1.1"], vmessListener.ApplicationProtocols);
        Assert.Equal("/vmess", vmessListener.WebSocketInbound!.Path);
        Assert.Equal("edge.example.com", vmessListener.WebSocketInbound.Host);
        var vmessUser = Assert.Single(vmessListener.WebSocketInbound.Users);
        Assert.Equal("vmess-user", vmessUser.UserId);
        Assert.Equal(vmessUuid, vmessUser.Uuid);
        Assert.Equal(16, vmessUser.CmdKey.Length);
    }

    [Fact]
    public void TryBuild_normalizes_explicit_inbound_transport_protocol_and_security()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VlessInboundRuntimeCompiler(),
            new VmessInboundRuntimeCompiler()
        ]);

        var vlessUuid = Guid.NewGuid().ToString("D");
        var vmessUuid = Guid.NewGuid().ToString("D");
        var success = builder.TryBuild(
            31,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vless-wss",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = string.Empty,
                        TransportProtocol = RuntimeInternetTransportProtocols.Ws,
                        TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                        ListenAddress = "127.0.0.1",
                        Port = 2443,
                        Path = "vless",
                        Host = "edge.example.com",
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "vless-user",
                                Uuid = vlessUuid
                            }
                        ]
                    },
                    new InboundConfig
                    {
                        Tag = "vmess-tls",
                        Enabled = true,
                        Protocol = InboundProtocols.Vmess,
                        Transport = string.Empty,
                        TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                        TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                        ListenAddress = "127.0.0.1",
                        Port = 3443,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "vmess-user",
                                Uuid = vmessUuid
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                }
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedVless = Assert.Single(
            snapshot.Config.Inbounds,
            static inbound => string.Equals(inbound.Tag, "vless-wss", StringComparison.Ordinal));
        Assert.Equal(InboundTransports.Wss, normalizedVless.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Ws, normalizedVless.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, normalizedVless.TransportSecurity);
        Assert.Equal("/vless", normalizedVless.Path);

        var normalizedVmess = Assert.Single(
            snapshot.Config.Inbounds,
            static inbound => string.Equals(inbound.Tag, "vmess-tls", StringComparison.Ordinal));
        Assert.Equal(InboundTransports.Tls, normalizedVmess.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, normalizedVmess.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, normalizedVmess.TransportSecurity);

        var vlessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty);
        var vlessListener = Assert.Single(vlessPlan.Listeners);
        Assert.Equal(RuntimeInternetTransportProtocols.Ws, vlessListener.WebSocketInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, vlessListener.WebSocketInbound.SecurityType);

        var vmessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
        var vmessListener = Assert.Single(vmessPlan.Listeners);
        Assert.Equal(RuntimeInternetTransportProtocols.Tcp, vmessListener.RawTlsInbound!.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, vmessListener.RawTlsInbound.SecurityType);
    }

    [Fact]
    public void TryBuild_normalizes_grpc_inbounds_and_lifts_legacy_trojan_users()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler(),
            new VlessInboundRuntimeCompiler(),
            new VmessInboundRuntimeCompiler()
        ]);

        var vlessUuid = Guid.NewGuid().ToString("D");
        var vmessUuid = Guid.NewGuid().ToString("D");
        var success = builder.TryBuild(
            32,
            new NodeServiceConfig
            {
                Users =
                [
                    new TrojanUserConfig
                    {
                        UserId = " trojan-user ",
                        Password = " trojan-secret "
                    }
                ],
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " trojan-grpc ",
                        Enabled = true,
                        Protocol = InboundProtocols.Trojan,
                        Transport = string.Empty,
                        TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                        TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                        ListenAddress = " 127.0.0.1 ",
                        Port = 18443,
                        GrpcServiceName = " /trojan/service/Tun|TunMulti ",
                        GrpcMultiMode = true,
                        GrpcUserAgent = " Agent/1.0 ",
                        GrpcIdleTimeoutSeconds = 12,
                        GrpcHealthCheckTimeoutSeconds = 5,
                        GrpcPermitWithoutStream = true,
                        GrpcInitialWindowSize = 262_144,
                        ApplicationProtocols = [" http/1.1 "]
                    },
                    new InboundConfig
                    {
                        Tag = " vless-grpc ",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = string.Empty,
                        TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                        TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                        ListenAddress = " 127.0.0.1 ",
                        Port = 2443,
                        GrpcServiceName = " /vless/service/Tun|TunMulti ",
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = " vless-user ",
                                Uuid = $" {vlessUuid} "
                            }
                        ]
                    },
                    new InboundConfig
                    {
                        Tag = " vmess-grpc ",
                        Enabled = true,
                        Protocol = InboundProtocols.Vmess,
                        Transport = string.Empty,
                        TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                        TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                        ListenAddress = " 127.0.0.1 ",
                        Port = 3443,
                        GrpcServiceName = " /vmess/service/Tun|TunMulti ",
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = " vmess-user ",
                                Uuid = $" {vmessUuid} "
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedTrojan = Assert.Single(
            snapshot.Config.Inbounds,
            static inbound => string.Equals(inbound.Tag, "trojan-grpc", StringComparison.Ordinal));
        Assert.Equal(InboundTransports.Grpc, normalizedTrojan.Transport);
        Assert.Equal(RuntimeInternetTransportProtocols.Grpc, normalizedTrojan.TransportProtocol);
        Assert.Equal(RuntimeInternetSecurityTypes.Tls, normalizedTrojan.TransportSecurity);
        Assert.Equal("/trojan/service/Tun|TunMulti", normalizedTrojan.GrpcServiceName);
        Assert.Equal("Agent/1.0", normalizedTrojan.GrpcUserAgent);
        Assert.Equal(["h2"], normalizedTrojan.ApplicationProtocols);
        var trojanUser = Assert.Single(normalizedTrojan.Users);
        Assert.Equal("trojan-user", trojanUser.UserId);

        var trojanPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Trojan, TrojanInboundRuntimePlan.Empty);
        var trojanListener = Assert.Single(trojanPlan.Listeners);
        Assert.Equal(["h2"], trojanListener.ApplicationProtocols);
        Assert.NotNull(trojanListener.GrpcInbound);
        Assert.Equal("/trojan/service/Tun|TunMulti", trojanListener.GrpcInbound!.Grpc.ServiceName);
        Assert.True(trojanListener.GrpcInbound.Grpc.MultiMode);
        Assert.Equal("Agent/1.0", trojanListener.GrpcInbound.Grpc.UserAgent);
        Assert.Equal(12, trojanListener.GrpcInbound.Grpc.IdleTimeoutSeconds);
        Assert.Equal(5, trojanListener.GrpcInbound.Grpc.HealthCheckTimeoutSeconds);
        Assert.True(trojanListener.GrpcInbound.Grpc.PermitWithoutStream);
        Assert.Equal(262_144, trojanListener.GrpcInbound.Grpc.InitialWindowSize);
        var runtimeTrojanUser = Assert.Single(trojanListener.GrpcInbound.UsersByHash);
        Assert.Equal("trojan-user", runtimeTrojanUser.Value.UserId);

        var vlessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty);
        var vlessListener = Assert.Single(vlessPlan.Listeners);
        Assert.Equal(["h2"], vlessListener.ApplicationProtocols);
        Assert.NotNull(vlessListener.GrpcInbound);
        Assert.Equal("/vless/service/Tun|TunMulti", vlessListener.GrpcInbound!.Grpc.ServiceName);
        var vlessUser = Assert.Single(vlessListener.GrpcInbound.UsersByUuid);
        Assert.Equal(vlessUuid, vlessUser.Key);
        Assert.Equal("vless-user", vlessUser.Value.UserId);

        var vmessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
        var vmessListener = Assert.Single(vmessPlan.Listeners);
        Assert.Equal(["h2"], vmessListener.ApplicationProtocols);
        Assert.NotNull(vmessListener.GrpcInbound);
        Assert.Equal("/vmess/service/Tun|TunMulti", vmessListener.GrpcInbound!.Grpc.ServiceName);
        var vmessUser = Assert.Single(vmessListener.GrpcInbound.Users);
        Assert.Equal("vmess-user", vmessUser.UserId);
        Assert.Equal(vmessUuid, vmessUser.Uuid);

        Assert.Contains(
            snapshot.ActiveUsers,
            static user => string.Equals(user.UserId, "trojan-user", StringComparison.Ordinal));
        Assert.Contains(
            snapshot.ActiveUsers,
            static user => string.Equals(user.UserId, "vless-user", StringComparison.Ordinal));
        Assert.Contains(
            snapshot.ActiveUsers,
            static user => string.Equals(user.UserId, "vmess-user", StringComparison.Ordinal));
    }

    [Fact]
    public void TryBuild_normalizes_vless_inbound_flow_and_testseed_into_runtime_users()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VlessInboundRuntimeCompiler()
        ]);

        var vlessUuid = Guid.NewGuid().ToString("D");
        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " vless-entry ",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = InboundTransports.Tls,
                        ListenAddress = "127.0.0.1",
                        Port = 2443,
                        Flow = " XTLS-RPRX-VISION-UDP443 ",
                        TestSeed = [11u, 12u, 13u, 14u, 15u],
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = " vless-user ",
                                Uuid = vlessUuid,
                                TestSeed = [1u, 2u, 3u]
                            }
                        ]
                    }
                ],
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                }
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);

        var normalizedInbound = Assert.Single(snapshot.Config.Inbounds);
        Assert.Equal(VlessFlowTypes.Vision, normalizedInbound.Flow);
        Assert.Equal([11u, 12u, 13u, 14u], normalizedInbound.TestSeed);

        var vlessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty);
        var vlessListener = Assert.Single(vlessPlan.TlsListeners);
        var vlessUser = Assert.Single(vlessListener.RawTlsInbound!.UsersByUuid.Values);
        Assert.Equal("vless-user", vlessUser.UserId);
        Assert.Equal(VlessFlowTypes.Vision, vlessUser.Flow);
        Assert.Equal([11u, 12u, 13u, 14u], vlessUser.TestSeed);

        var activeUser = Assert.Single(snapshot.ActiveUsers.OfType<VlessUser>());
        Assert.Equal(VlessFlowTypes.Vision, activeUser.Flow);
        Assert.Equal([11u, 12u, 13u, 14u], activeUser.TestSeed);
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_inbound_plan_from_top_level_password()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new ShadowsocksInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " ss-entry ",
                        Enabled = true,
                        Protocol = " ss ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 8388,
                        Security = " aes-128-gcm ",
                        Password = " secret ",
                        Networks = [" tcp "]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Shadowsocks, ShadowsocksInboundRuntimePlan.Empty);
        var inbound = Assert.Single(plan.Inbounds);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("ss-entry", inbound.Tag);
        Assert.Equal("default", user.UserId);
        Assert.Equal(ShadowsocksCipherTypes.Aes128Gcm, user.Cipher);
        Assert.Equal("secret", user.Password);
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_inbound_plan_from_explicit_user_cipher()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new ShadowsocksInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " ss-users ",
                        Enabled = true,
                        Protocol = " shadowsocks ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 8388,
                        Security = " aes-128-gcm ",
                        Password = " top-secret ",
                        ShadowsocksUsers =
                        [
                            new ShadowsocksUserConfig
                            {
                                UserId = " demo-user ",
                                Cipher = " aead_xchacha20_poly1305 ",
                                Password = " demo-secret "
                            }
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Shadowsocks, ShadowsocksInboundRuntimePlan.Empty);
        var inbound = Assert.Single(plan.Inbounds);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("ss-users", inbound.Tag);
        Assert.Equal("demo-user", user.UserId);
        Assert.Equal(ShadowsocksCipherTypes.XChaCha20Poly1305, user.Cipher);
        Assert.Equal("demo-secret", user.Password);
    }

    [Fact]
    public void TryBuild_rejects_shadowsocks_inbound_user_without_explicit_cipher()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new ShadowsocksInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " ss-users-missing-cipher ",
                        Enabled = true,
                        Protocol = " shadowsocks ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 8388,
                        Security = " aes-128-gcm ",
                        Password = " top-secret ",
                        ShadowsocksUsers =
                        [
                            new ShadowsocksUserConfig
                            {
                                UserId = " demo-user ",
                                Cipher = string.Empty,
                                Password = " demo-secret "
                            }
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Equal(
            "Shadowsocks user 'demo-user' on inbound 'ss-users-missing-cipher' is invalid: Shadowsocks cipher is not specified.",
            error);
    }

    [Fact]
    public void TryBuild_rejects_shadowsocks_inbound_user_without_password_instead_of_ignoring_it()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new ShadowsocksInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " ss-users-missing-password ",
                        Enabled = true,
                        Protocol = " shadowsocks ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 8388,
                        Security = " aes-128-gcm ",
                        Password = " top-secret ",
                        ShadowsocksUsers =
                        [
                            new ShadowsocksUserConfig
                            {
                                UserId = " demo-user ",
                                Cipher = " aes-128-gcm ",
                                Password = string.Empty
                            }
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Equal(
            "Shadowsocks user 'demo-user' on inbound 'ss-users-missing-password' requires a password.",
            error);
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_2022_relay_inbound_plan_from_dedicated_users()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new ShadowsocksInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " ss-2022-relay ",
                        Enabled = true,
                        Protocol = " shadowsocks ",
                        ListenAddress = " 127.0.0.1 ",
                        Port = 8388,
                        Security = $" {ShadowsocksCipherTypes.Blake3Aes128Gcm} ",
                        Password = Convert.ToBase64String(new byte[16]),
                        Networks = [" udp "],
                        ShadowsocksUsers =
                        [
                            new ShadowsocksUserConfig
                            {
                                UserId = " relay-a ",
                                Password = Convert.ToBase64String(new byte[16]),
                                Address = " relay.example.com ",
                                Port = 53
                            }
                        ]
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Shadowsocks, ShadowsocksInboundRuntimePlan.Empty);
        Assert.Empty(plan.Inbounds);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal("ss-2022-relay", inbound.Tag);
        Assert.Equal(Shadowsocks2022InboundModes.Relay, inbound.Mode);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("relay-a", user.UserId);
        Assert.Equal("relay.example.com", user.Address);
        Assert.Equal(53, user.Port);

        var activeUser = Assert.Single(snapshot.ActiveUsers);
        Assert.Equal("relay-a", activeUser.UserId);
    }

    [Fact]
    public void TryBuild_builds_trojan_outbound_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
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
                        Tag = " trojan-edge ",
                        Enabled = true,
                        Protocol = " TROJAN ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        ServerName = " edge.example.com ",
                        Transport = " WSS ",
                        WebSocketPath = " ws ",
                        WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" Host "] = " edge.example.com "
                        },
                        ApplicationProtocols = [" h2 "],
                        Password = " secret ",
                        ConnectTimeoutSeconds = 7,
                        HandshakeTimeoutSeconds = 13
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Trojan],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetTrojan("trojan-edge", out var trojan));
        Assert.Equal("edge.example.com", trojan.ServerHost);
        Assert.Equal(TrojanOutboundTransports.Wss, trojan.Transport);
        Assert.Equal("/ws", trojan.WebSocketPath);
        Assert.Equal("edge.example.com", trojan.WebSocketHeaders["Host"]);
        Assert.Equal(["http/1.1"], trojan.ApplicationProtocols);
        Assert.Equal("secret", trojan.Password);
        Assert.Equal(7, trojan.ConnectTimeoutSeconds);
        Assert.Equal(13, trojan.HandshakeTimeoutSeconds);
    }

    [Fact]
    public void TryBuild_accepts_trojan_outbound_with_null_optional_collections_and_restores_defaults()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            4,
            new NodeServiceConfig
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
                        Tag = " trojan-edge ",
                        Enabled = true,
                        Protocol = " TROJAN ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Password = " secret ",
                        Fingerprint = null!,
                        MultiplexSettings = null!,
                        WebSocketHeaders = null!,
                        HttpHeaders = null!,
                        ApplicationProtocols = null!,
                        CandidateTags = null!,
                        RealityOptions = null!,
                        TestSeed = null!
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Trojan],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedOutbound = Assert.Single(snapshot.Config.Outbounds, static outbound => outbound.Tag == "trojan-edge");
        Assert.NotNull(normalizedOutbound.MultiplexSettings);
        Assert.Empty(normalizedOutbound.WebSocketHeaders);
        Assert.Empty(normalizedOutbound.HttpHeaders);
        Assert.Empty(normalizedOutbound.ApplicationProtocols);
        Assert.Empty(normalizedOutbound.CandidateTags);
        Assert.Empty(normalizedOutbound.TestSeed);
        Assert.Equal(string.Empty, normalizedOutbound.Fingerprint);
        Assert.True(normalizedOutbound.RealityOptions.IsEmpty);

        Assert.True(snapshot.OutboundSettings.TryGetTrojan("trojan-edge", out var trojan));
        Assert.Empty(trojan.WebSocketHeaders);
        Assert.Empty(trojan.ApplicationProtocols);
    }

    [Fact]
    public void TryBuild_builds_vmess_outbound_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            5,
            new NodeServiceConfig
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
                        Tag = " vmess-edge ",
                        Enabled = true,
                        Protocol = " VMESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        ServerName = " edge.example.com ",
                        Transport = " WSS ",
                        WebSocketPath = " ws ",
                        WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" Host "] = " edge.example.com "
                        },
                        ApplicationProtocols = [" h2 "],
                        Uuid = "11111111-1111-1111-1111-111111111111",
                        Security = " CHACHA20-POLY1305 ",
                        AuthenticatedLength = false,
                        NoTerminationSignal = true,
                        ConnectTimeoutSeconds = 9,
                        HandshakeTimeoutSeconds = 15
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vmess],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetVmess("vmess-edge", out var vmess));
        Assert.Equal("edge.example.com", vmess.ServerHost);
        Assert.Equal(VmessOutboundTransports.Wss, vmess.Transport);
        Assert.Equal("/ws", vmess.WebSocketPath);
        Assert.Equal("edge.example.com", vmess.WebSocketHeaders["Host"]);
        Assert.Equal(["http/1.1"], vmess.ApplicationProtocols);
        Assert.Equal("11111111-1111-1111-1111-111111111111", vmess.UserUuid);
        Assert.Equal(VmessOutboundSecurityTypes.ChaCha20Poly1305, vmess.Security);
        Assert.False(vmess.AuthenticatedLength);
        Assert.True(vmess.NoTerminationSignal);
        Assert.Equal(9, vmess.ConnectTimeoutSeconds);
        Assert.Equal(15, vmess.HandshakeTimeoutSeconds);
    }

    [Fact]
    public void TryBuild_builds_vless_httpupgrade_outbound_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            6,
            new NodeServiceConfig
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
                        Tag = " vless-edge ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        ServerName = " edge.example.com ",
                        Transport = " HTTPUPGRADE+TLS ",
                        WebSocketPath = " upgrade ",
                        WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" Host "] = " edge.example.com "
                        },
                        ApplicationProtocols = [" h2 ", "http/1.1"],
                        Uuid = "22222222-2222-2222-2222-222222222222",
                        ConnectTimeoutSeconds = 8,
                        HandshakeTimeoutSeconds = 14
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vless],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetVless("vless-edge", out var vless));
        Assert.Equal("edge.example.com", vless.ServerHost);
        Assert.Equal(VlessOutboundTransports.HttpUpgradeTls, vless.Transport);
        Assert.Equal("/upgrade", vless.WebSocketPath);
        Assert.Equal("edge.example.com", vless.WebSocketHeaders["Host"]);
        Assert.Equal(["http/1.1"], vless.ApplicationProtocols);
        Assert.Equal("22222222-2222-2222-2222-222222222222", vless.UserUuid);
        Assert.Equal(8, vless.ConnectTimeoutSeconds);
        Assert.Equal(14, vless.HandshakeTimeoutSeconds);
    }

    [Fact]
    public void TryBuild_preserves_zero_vmess_port_and_normalizes_unknown_security_to_auto()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            7,
            new NodeServiceConfig
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
                        Tag = " vmess-zero ",
                        Enabled = true,
                        Protocol = " VMESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 0,
                        Uuid = "33333333-3333-3333-3333-333333333333",
                        Security = " unknown-security "
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vmess],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetVmess("vmess-zero", out var vmess));
        Assert.Equal(0, vmess.ServerPort);
        Assert.Equal(VmessOutboundSecurityTypes.Auto, vmess.Security);
    }

    [Fact]
    public void TryBuild_normalizes_vless_flow_into_runtime_outbound_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            8,
            new NodeServiceConfig
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
                        Tag = " vless-vision ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Uuid = "22222222-2222-2222-2222-222222222222",
                        Flow = " XTLS-RPRX-VISION-UDP443 "
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vless],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetVless("vless-vision", out var vless));
        Assert.Equal(VlessFlowTypes.VisionUdp443, vless.Flow);
    }

    [Fact]
    public void TryBuild_normalizes_vless_testseed_into_runtime_outbound_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            8,
            new NodeServiceConfig
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
                        Tag = " vless-seed ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Uuid = "22222222-2222-2222-2222-222222222222",
                        TestSeed = [11u, 12u, 13u, 14u, 15u]
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vless],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedOutbound = Assert.Single(
            snapshot.Config.Outbounds,
            static outbound => outbound.Protocol == OutboundProtocols.Vless);
        Assert.Equal([11u, 12u, 13u, 14u], normalizedOutbound.TestSeed);

        Assert.True(snapshot.OutboundSettings.TryGetVless("vless-seed", out var vless));
        Assert.Equal([11u, 12u, 13u, 14u], vless.TestSeed);
    }

    [Fact]
    public void TryBuild_preserves_vless_testpre_into_runtime_outbound_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            8,
            new NodeServiceConfig
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
                        Tag = " vless-testpre ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Uuid = "22222222-2222-2222-2222-222222222222",
                        TestPre = 3
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vless],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedOutbound = Assert.Single(
            snapshot.Config.Outbounds,
            static outbound => outbound.Protocol == OutboundProtocols.Vless);
        Assert.Equal(3, normalizedOutbound.TestPre);

        Assert.True(snapshot.OutboundSettings.TryGetVless("vless-testpre", out var vless));
        Assert.Equal(3, vless.TestPre);
    }

    [Fact]
    public void TryBuild_preserves_vless_transport_encryption_into_runtime_outbound_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);
        var encryption = EncodeBase64Url(32, 0x44);

        var success = builder.TryBuild(
            9,
            new NodeServiceConfig
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
                        Tag = " vless-encryption ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Uuid = "22222222-2222-2222-2222-222222222222",
                        Encryption = $" {encryption} ",
                        XorMode = 2,
                        Seconds = 30,
                        Padding = " 100-35-40 "
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vless],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedOutbound = Assert.Single(
            snapshot.Config.Outbounds,
            static outbound => outbound.Protocol == OutboundProtocols.Vless);
        Assert.Equal(encryption, normalizedOutbound.Encryption.Trim());
        Assert.Equal((uint)2, normalizedOutbound.XorMode);
        Assert.Equal(30, normalizedOutbound.Seconds);
        Assert.Equal("100-35-40", normalizedOutbound.Padding.Trim());

        Assert.True(snapshot.OutboundSettings.TryGetVless("vless-encryption", out var vless));
        Assert.Equal(encryption, vless.Encryption);
        Assert.Equal((uint)2, vless.XorMode);
        Assert.Equal(30, vless.Seconds);
        Assert.Equal("100-35-40", vless.Padding);
    }

    [Fact]
    public void TryBuild_carries_vless_outbound_reverse_tag_into_runtime_outbound_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            9,
            new NodeServiceConfig
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
                        Tag = " vless-bridge ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Uuid = "22222222-2222-2222-2222-222222222222",
                        ReverseTag = " reverse-edge "
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Vless],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedOutbound = Assert.Single(
            snapshot.Config.Outbounds,
            static outbound => outbound.Tag == "vless-bridge");
        Assert.Equal("reverse-edge", normalizedOutbound.ReverseTag);

        Assert.True(snapshot.OutboundSettings.TryGetVless("vless-bridge", out var vless));
        Assert.Equal("reverse-edge", vless.ReverseTag);
    }

    [Fact]
    public void TryBuild_allows_routing_rules_targeting_vless_reverse_tag()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VlessInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = " vless-reverse ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        Transport = " TLS ",
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "user-a",
                                Uuid = "11111111-1111-1111-1111-111111111111",
                                ReverseTag = " reverse-edge "
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ],
                RoutingRules =
                [
                    new RoutingRuleConfig
                    {
                        Enabled = true,
                        InboundTags = [" vless-reverse "],
                        OutboundTag = " reverse-edge "
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedInbound = Assert.Single(snapshot.Config.Inbounds);
        var user = Assert.Single(normalizedInbound.Users);
        Assert.Equal("reverse-edge", user.ReverseTag);

        var rule = Assert.Single(snapshot.Plan.Outbound.RoutingRules);
        Assert.Equal("reverse-edge", rule.OutboundTag);
    }

    [Fact]
    public void TryBuild_rejects_vless_reverse_tag_conflicting_with_configured_outbound_tag()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VlessInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vless-reverse",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = InboundTransports.Tls,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "user-a",
                                Uuid = "11111111-1111-1111-1111-111111111111",
                                ReverseTag = "reverse-edge"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    PfxPath = "runtime.pfx"
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "reverse-edge",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("conflicts with configured outbound tag", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_normalizes_proxy_reality_security_into_runtime_outbound_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);
        var realityKey = EncodeBase64Url(32, 0x5A);

        var success = builder.TryBuild(
            9,
            new NodeServiceConfig
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
                        Tag = " trojan-reality ",
                        Enabled = true,
                        Protocol = " TROJAN ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Transport = " grpc ",
                        TransportSecurity = " REALITY ",
                        ApplicationProtocols = ["http/1.1"],
                        RealityOptions = new RuntimeRealityOptions
                        {
                            Fingerprint = " Chrome ",
                            Password = $" {realityKey} ",
                            ShortId = " abcd ",
                            SpiderX = " /portal?p=1-2&keep=1 "
                        },
                        Password = " trojan-secret "
                    }
                ]
            },
            [OutboundProtocols.Freedom, OutboundProtocols.Trojan],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var normalizedOutbound = Assert.Single(
            snapshot.Config.Outbounds,
            static outbound => outbound.Protocol == OutboundProtocols.Trojan);
        Assert.Equal(TrojanOutboundTransports.Grpc, normalizedOutbound.Transport);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, normalizedOutbound.TransportSecurity);
        Assert.Equal("chrome", normalizedOutbound.RealityOptions.Fingerprint);
        Assert.Equal("/portal?keep=1", normalizedOutbound.RealityOptions.SpiderX);
        Assert.Equal(["h2"], normalizedOutbound.ApplicationProtocols);

        Assert.True(snapshot.OutboundSettings.TryGetTrojan("trojan-reality", out var trojan));
        Assert.Equal(TrojanOutboundTransports.Grpc, trojan.Transport);
        Assert.Equal(RuntimeInternetSecurityTypes.Reality, trojan.TransportSecurity);
        Assert.Equal("chrome", trojan.RealityOptions.Fingerprint);
        Assert.Equal(realityKey, trojan.RealityOptions.PublicKey);
        Assert.Equal("abcd", trojan.RealityOptions.ShortId);
        Assert.Equal("/portal?keep=1", trojan.RealityOptions.SpiderX);
        Assert.Equal(["h2"], trojan.ApplicationProtocols);
    }

    [Fact]
    public void TryBuild_passes_reality_server_options_for_vless_tcp_reality_inbound()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VlessInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            11,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vless-reality",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = RuntimeInternetTransportProtocols.Tcp,
                        TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                        TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "user-a",
                                Uuid = "11111111-1111-1111-1111-111111111111"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    Mode = CertificateModes.Disabled
                },
                Reality = new RuntimeRealityServerOptions
                {
                    ServerNames = [" download.microsoft.com "],
                    Dest = " download.microsoft.com:443 ",
                    Type = " TCP ",
                    PrivateKey = " UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc ",
                    ShortIds = [" 0123456789ABCDEF "],
                    MaxTimeDiffMilliseconds = -1
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.False(snapshot.RequiresCertificate);
        Assert.True(snapshot.RequiresReality);
        Assert.NotNull(snapshot.Reality);
        Assert.Equal(["download.microsoft.com"], snapshot.Reality.ServerNames);
        Assert.Equal("download.microsoft.com:443", snapshot.Reality.Dest);
        Assert.Equal("tcp", snapshot.Reality.Type);
        Assert.Equal(["0123456789abcdef"], snapshot.Reality.ShortIds);
        Assert.Equal(0, snapshot.Reality.MaxTimeDiffMilliseconds);
        Assert.Single(snapshot.ActiveUsers);
        Assert.Same(snapshot.Reality, snapshot.CreateRuntimePlan().Reality);
    }

    [Fact]
    public void TryBuild_passes_reality_server_options_for_vmess_tcp_reality_inbound()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VmessInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            14,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vmess-reality",
                        Enabled = true,
                        Protocol = InboundProtocols.Vmess,
                        Transport = RuntimeInternetTransportProtocols.Tcp,
                        TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                        TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "user-a",
                                Uuid = "11111111-1111-1111-1111-111111111111"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    Mode = CertificateModes.Disabled
                },
                Reality = new RuntimeRealityServerOptions
                {
                    ServerNames = ["dl.google.com"],
                    Dest = "dl.google.com:443",
                    Type = "tcp",
                    PrivateKey = "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
                    ShortIds = ["0123456789abcdef"]
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.False(snapshot.RequiresCertificate);
        Assert.True(snapshot.RequiresReality);
        Assert.NotNull(snapshot.Reality);
        Assert.Single(snapshot.ActiveUsers);
        var vmessPlan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
        Assert.Single(vmessPlan.RealityListeners);
    }

    [Fact]
    public void TryBuild_passes_reality_server_options_for_trojan_tcp_reality_inbound()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            13,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "trojan-reality",
                        Enabled = true,
                        Protocol = InboundProtocols.Trojan,
                        Transport = RuntimeInternetTransportProtocols.Tcp,
                        TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                        TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "user-a",
                                Password = "secret"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    Mode = CertificateModes.Disabled
                },
                Reality = new RuntimeRealityServerOptions
                {
                    ServerNames = ["download.microsoft.com"],
                    Dest = "download.microsoft.com:443",
                    Type = "tcp",
                    PrivateKey = "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
                    ShortIds = ["0123456789abcdef"]
                },
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "direct",
                        Enabled = true,
                        Protocol = OutboundProtocols.Freedom
                    }
                ]
            },
            [OutboundProtocols.Freedom],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.False(snapshot.RequiresCertificate);
        Assert.True(snapshot.RequiresReality);
        Assert.NotNull(snapshot.Reality);
        Assert.Single(snapshot.ActiveUsers);
        Assert.Single(snapshot.TrojanPlan.RealityListeners);
    }

    [Fact]
    public void TryBuild_rejects_reality_inbound_without_server_options()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new VlessInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            12,
            new NodeServiceConfig
            {
                Inbounds =
                [
                    new InboundConfig
                    {
                        Tag = "vless-reality",
                        Enabled = true,
                        Protocol = InboundProtocols.Vless,
                        Transport = RuntimeInternetTransportProtocols.Tcp,
                        TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                        TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                        Users =
                        [
                            new TrojanUserConfig
                            {
                                UserId = "user-a",
                                Uuid = "11111111-1111-1111-1111-111111111111"
                            }
                        ]
                    }
                ],
                Certificate = new CertificateOptions
                {
                    Mode = CertificateModes.Disabled
                }
            },
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Contains("REALITY server settings", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryBuild_rejects_vless_outbound_with_invalid_uuid()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            8,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = " vless-invalid ",
                        Enabled = true,
                        Protocol = " VLESS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 443,
                        Uuid = "not-a-uuid"
                    }
                ]
            },
            [OutboundProtocols.Vless],
            out _,
            out var error);

        Assert.False(success);
        Assert.Equal("VLESS user UUID is invalid.", error);
    }

    [Fact]
    public void TryBuild_accepts_blackhole_outbound_without_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            8,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = " sink ",
                        Enabled = true,
                        Protocol = " BLACKHOLE "
                    }
                ]
            },
            [OutboundProtocols.Blackhole],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        var outbound = Assert.Single(snapshot.Plan.Outbound.Outbounds);
        Assert.Equal("sink", outbound.Tag);
        Assert.Equal(OutboundProtocols.Blackhole, outbound.Protocol);
        Assert.False(snapshot.OutboundSettings.TryGet("sink", out IRuntimeOutboundOptions _));
    }

    [Fact]
    public void TryBuild_builds_socks_outbound_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            9,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = " socks-edge ",
                        Enabled = true,
                        Protocol = " SOCKS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 1080,
                        Username = " alice ",
                        Password = " secret ",
                        ConnectTimeoutSeconds = 7,
                        HandshakeTimeoutSeconds = 11
                    }
                ]
            },
            [OutboundProtocols.Socks],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetSocks("socks-edge", out var socks));
        Assert.Equal("edge.example.com", socks.ServerHost);
        Assert.Equal(1080, socks.ServerPort);
        Assert.Equal("alice", socks.Username);
        Assert.Equal("secret", socks.Password);
        Assert.Equal(7, socks.ConnectTimeoutSeconds);
        Assert.Equal(11, socks.HandshakeTimeoutSeconds);
    }

    [Theory]
    [InlineData(" CHACHA20-POLY1305 ", ShadowsocksCipherTypes.ChaCha20Poly1305)]
    [InlineData(" XCHACHA20-POLY1305 ", ShadowsocksCipherTypes.XChaCha20Poly1305)]
    [InlineData(" AEAD_CHACHA20_POLY1305 ", ShadowsocksCipherTypes.ChaCha20Poly1305)]
    [InlineData(" PLAIN ", ShadowsocksCipherTypes.None)]
    public void TryBuild_builds_shadowsocks_outbound_runtime_settings(string security, string expectedCipher)
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = " ss-edge ",
                        Enabled = true,
                        Protocol = " SHADOWSOCKS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 8388,
                        Security = security,
                        Password = " secret ",
                        ConnectTimeoutSeconds = 6
                    }
                ]
            },
            [OutboundProtocols.Shadowsocks],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetShadowsocks("ss-edge", out var shadowsocks));
        Assert.Equal("edge.example.com", shadowsocks.ServerHost);
        Assert.Equal(8388, shadowsocks.ServerPort);
        Assert.Equal(expectedCipher, shadowsocks.Cipher);
        Assert.Equal("secret", shadowsocks.Password);
        Assert.Equal(6, shadowsocks.ConnectTimeoutSeconds);
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_2022_outbound_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "ss-2022",
                        Enabled = true,
                        Protocol = "shadowsocks",
                        ServerHost = "edge.example.com",
                        ServerPort = 8388,
                        Security = ShadowsocksCipherTypes.Blake3Aes128Gcm,
                        Password = Convert.ToBase64String(new byte[16]),
                        UdpOverTcp = true,
                        UdpOverTcpVersion = 2
                    }
                ]
            },
            [OutboundProtocols.Shadowsocks],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetShadowsocks2022("ss-2022", out var shadowsocks2022));
        Assert.Equal("edge.example.com", shadowsocks2022.ServerHost);
        Assert.Equal(8388, shadowsocks2022.ServerPort);
        Assert.Equal(ShadowsocksCipherTypes.Blake3Aes128Gcm, shadowsocks2022.Method);
        Assert.Equal(2, shadowsocks2022.UdpOverTcpVersion);
        Assert.True(shadowsocks2022.UdpOverTcp);
    }

    [Fact]
    public void TryBuild_ignores_regular_shadowsocks_udp_over_tcp_like_xray_core()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "ss-uot",
                        Enabled = true,
                        Protocol = "shadowsocks",
                        ServerHost = "edge.example.com",
                        ServerPort = 8388,
                        Security = ShadowsocksCipherTypes.Aes256Gcm,
                        Password = "secret",
                        UdpOverTcp = true,
                        UdpOverTcpVersion = 2
                    }
                ]
            },
            [OutboundProtocols.Shadowsocks],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetShadowsocks("ss-uot", out var shadowsocks));
        Assert.False(shadowsocks.UdpOverTcp);
        Assert.Equal(0, shadowsocks.UdpOverTcpVersion);
    }

    [Fact]
    public void TryBuild_rejects_invalid_shadowsocks_port()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = "ss-invalid-port",
                        Enabled = true,
                        Protocol = "shadowsocks",
                        ServerHost = "edge.example.com",
                        ServerPort = 0,
                        Security = ShadowsocksCipherTypes.Aes256Gcm,
                        Password = "secret"
                    }
                ]
            },
            [OutboundProtocols.Shadowsocks],
            out _,
            out var error);

        Assert.False(success);
        Assert.Equal("Invalid Shadowsocks port.", error);
    }

    [Fact]
    public void TryBuild_builds_http_outbound_runtime_settings()
    {
        var builder = new NodeRuntimeSnapshotBuilder(
        [
            new TrojanInboundRuntimeCompiler()
        ]);

        var success = builder.TryBuild(
            10,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = " http-edge ",
                        Enabled = true,
                        Protocol = " HTTP ",
                        Transport = " TLS ",
                        ServerHost = " edge.example.com ",
                        ServerPort = 8080,
                        ServerName = " proxy.example.com ",
                        Username = " alice ",
                        Password = " secret ",
                        HttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" X-Test "] = " demo "
                        },
                        ApplicationProtocols = [" h2 ", " http/1.1 "],
                        ConnectTimeoutSeconds = 6,
                        HandshakeTimeoutSeconds = 9,
                        SkipCertificateValidation = true
                    }
                ]
            },
            [OutboundProtocols.Http],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.True(snapshot.OutboundSettings.TryGetHttp("http-edge", out var http));
        Assert.Equal("edge.example.com", http.ServerHost);
        Assert.Equal(8080, http.ServerPort);
        Assert.Equal("proxy.example.com", http.ServerName);
        Assert.Equal(HttpOutboundTransports.Tls, http.Transport);
        Assert.Equal("alice", http.Username);
        Assert.Equal("secret", http.Password);
        Assert.Equal("demo", http.Headers["X-Test"]);
        Assert.Equal(["h2", "http/1.1"], http.ApplicationProtocols);
        Assert.Equal(6, http.ConnectTimeoutSeconds);
        Assert.Equal(9, http.HandshakeTimeoutSeconds);
        Assert.True(http.SkipCertificateValidation);
    }

    [Fact]
    public void TryBuild_allows_custom_outbound_compiler_and_preserves_unknown_protocol_fields()
    {
        var customCompiler = new CustomOutboundRuntimeCompiler();
        var builder = new NodeRuntimeSnapshotBuilder(
            Array.Empty<IInboundProtocolRuntimeCompiler>(),
            [customCompiler]);

        var success = builder.TryBuild(
            9,
            new NodeServiceConfig
            {
                Outbounds =
                [
                    new OutboundConfig
                    {
                        Tag = " custom-edge ",
                        Enabled = true,
                        Protocol = " CUSTOM ",
                        Transport = " QUIC ",
                        WebSocketPath = " /kept ",
                        WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            [" Host "] = " edge.example.com "
                        },
                        ApplicationProtocols = [" h3 "]
                    }
                ]
            },
            ["custom"],
            out var snapshot,
            out var error);

        Assert.True(success, error);
        Assert.NotNull(customCompiler.ObservedOutbound);
        Assert.Equal("custom-edge", customCompiler.ObservedOutbound.Tag);
        Assert.Equal("custom", customCompiler.ObservedOutbound.Protocol);
        Assert.Equal("QUIC", customCompiler.ObservedOutbound.Transport);
        Assert.Equal("/kept", customCompiler.ObservedOutbound.WebSocketPath);
        Assert.Equal("edge.example.com", customCompiler.ObservedOutbound.WebSocketHeaders["Host"]);
        Assert.Equal(["h3"], customCompiler.ObservedOutbound.ApplicationProtocols);

        Assert.True(snapshot.OutboundSettings.TryGet("custom-edge", out var runtimeOptions));
        var customOptions = Assert.IsType<CustomRuntimeOutboundOptions>(runtimeOptions);
        Assert.Equal("custom", customOptions.Protocol);
        Assert.Equal("QUIC", customOptions.Transport);
    }

    private sealed class CustomOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
    {
        public CustomOutboundRuntimeCompiler()
            : base("custom")
        {
        }

        public OutboundConfig? ObservedOutbound { get; private set; }

        public override bool TryValidate(NodeServiceConfig config, out string? error)
        {
            ObservedOutbound = Assert.Single(GetSupportedOutbounds(config));
            error = null;
            return true;
        }

        public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        {
            var outbound = Assert.Single(GetSupportedOutbounds(config));
            return
            [
                new CustomRuntimeOutboundOptions
                {
                    Tag = outbound.Tag,
                    Protocol = outbound.Protocol,
                    Transport = outbound.Transport
                }
            ];
        }
    }

    private sealed record CustomRuntimeOutboundOptions : IRuntimeOutboundOptions
    {
        public required string Tag { get; init; }

        public required string Protocol { get; init; }

        public string Transport { get; init; } = string.Empty;
    }

    private static string EncodeBase64Url(int length, byte value)
        => Convert.ToBase64String(Enumerable.Repeat(value, length).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

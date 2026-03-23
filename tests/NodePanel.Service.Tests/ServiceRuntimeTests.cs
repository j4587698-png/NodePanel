using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Tests;

public sealed class ServiceRuntimeTests
{
    [Fact]
    public async Task ApplySnapshotAsync_accepts_unified_unix_listener_and_normalizes_timeout_defaults()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json"),
                        ControlPlane = new ControlPlaneOptions
                        {
                            Url = "http://127.0.0.1:7181"
                        }
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var unixPath = Path.Combine(testRoot, "trojan.sock");
            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "unix-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Tls,
                            ListenAddress = unixPath,
                            Port = 0
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            var listener = Assert.Single(snapshot.TrojanPlan.TlsListeners);
            Assert.Equal(unixPath, listener.Binding.ListenAddress);
            Assert.Equal(0, listener.Binding.Port);
            Assert.NotNull(listener.RawTlsInbound);
            Assert.Equal(60, listener.RawTlsInbound!.HandshakeTimeoutSeconds);
            Assert.Equal(300, snapshot.Config.Limits.ConnectionIdleSeconds);
            Assert.Equal(1, snapshot.Config.Limits.UplinkOnlySeconds);
            Assert.Equal(1, snapshot.Config.Limits.DownlinkOnlySeconds);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_rejects_duplicate_unix_listener_path()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var unixPath = Path.Combine(testRoot, "shared.sock");
            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "unix-tls",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Tls,
                            ListenAddress = unixPath,
                            Port = 0
                        },
                        new InboundConfig
                        {
                            Tag = "unix-wss",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Wss,
                            ListenAddress = unixPath,
                            Port = 0
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.False(applyResult.Success);
            Assert.Contains("same UNIX listener path", applyResult.Error, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_builds_trojan_runtime_plan_from_unified_inbounds()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "tls-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Tls,
                            ListenAddress = "127.0.0.1",
                            Port = 18443,
                            AcceptProxyProtocol = true,
                            ReceiveOriginalDestination = true
                        },
                        new InboundConfig
                        {
                            Tag = "wss-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Wss,
                            ListenAddress = "127.0.0.1",
                            Port = 18444,
                            Path = "edge",
                            Host = "edge.example.com"
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            Assert.Equal(2, snapshot.TrojanPlan.TlsListeners.Count);
            Assert.True(snapshot.TrojanPlan.HasTcpTls);
            Assert.True(snapshot.TrojanPlan.HasWss);
            var tlsListener = Assert.Single(
                snapshot.TrojanPlan.TlsListeners,
                static listener => listener.RawTlsInbound is not null && listener.WebSocketInbound is null);
            var wssListener = Assert.Single(
                snapshot.TrojanPlan.TlsListeners,
                static listener => listener.RawTlsInbound is null && listener.WebSocketInbound is not null);
            Assert.True(tlsListener.AcceptProxyProtocol);
            Assert.Equal(18443, tlsListener.Binding.Port);
            Assert.Equal("tls-entry", tlsListener.RawTlsInbound!.Tag);
            Assert.True(tlsListener.RawTlsInbound.ReceiveOriginalDestination);
            Assert.Equal(["http/1.1"], wssListener.ApplicationProtocols);
            Assert.Equal("/edge", wssListener.WebSocketInbound!.Path);
            Assert.Equal("edge.example.com", wssListener.WebSocketInbound.Host);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_normalizes_http_dns_config_for_runtime()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Dns = new DnsOptions
                    {
                        Mode = " HTTP ",
                        TimeoutSeconds = 0,
                        CacheTtlSeconds = -5,
                        Servers =
                        [
                            new DnsHttpServerConfig
                            {
                                Url = " https://dns.example/resolve ",
                                Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                                {
                                    [" Authorization "] = " Bearer demo-token ",
                                    [""] = "ignored"
                                }
                            }
                        ]
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            Assert.Equal(DnsModes.Http, snapshot.Config.Dns.Mode);
            Assert.Equal(5, snapshot.Config.Dns.TimeoutSeconds);
            Assert.Equal(0, snapshot.Config.Dns.CacheTtlSeconds);
            var configuredServer = Assert.Single(snapshot.Config.Dns.Servers);
            Assert.Equal("https://dns.example/resolve", configuredServer.Url);
            Assert.Equal("Bearer demo-token", configuredServer.Headers["Authorization"]);

            var runtimeDns = runtimeConfigStore.GetCurrentDnsSettings();
            Assert.Equal(DnsModes.Http, runtimeDns.Mode);
            Assert.Equal(5, runtimeDns.TimeoutSeconds);
            Assert.Equal(0, runtimeDns.CacheTtlSeconds);
            var runtimeServer = Assert.Single(runtimeDns.Servers);
            Assert.Equal("https://dns.example/resolve", runtimeServer.Url);
            Assert.Equal("Bearer demo-token", runtimeServer.Headers["Authorization"]);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_normalizes_certificate_client_hello_policy()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Certificate = new CertificateOptions
                    {
                        ClientHelloPolicy = new TlsClientHelloPolicyConfig
                        {
                            Enabled = true,
                            AllowedServerNames = [" *.Example.com ", "api.example.com", "*.example.com"],
                            AllowedApplicationProtocols = [" H2 ", "http/1.1", "h2"],
                            BlockedApplicationProtocols = [" HTTP/1.1 ", "http/1.1"],
                            AllowedJa3 = [" A1B2C3 ", "a1b2c3"],
                            BlockedJa3 = [" D4E5F6 ", "d4e5f6"]
                        }
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var clientHelloPolicy = runtimeConfigStore.GetSnapshot().Config.Certificate.ClientHelloPolicy;
            Assert.True(clientHelloPolicy.Enabled);
            Assert.Equal(["*.example.com", "api.example.com"], clientHelloPolicy.AllowedServerNames);
            Assert.Equal(["h2", "http/1.1"], clientHelloPolicy.AllowedApplicationProtocols);
            Assert.Equal(["http/1.1"], clientHelloPolicy.BlockedApplicationProtocols);
            Assert.Equal(["a1b2c3"], clientHelloPolicy.AllowedJa3);
            Assert.Equal(["d4e5f6"], clientHelloPolicy.BlockedJa3);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_limits_wss_application_protocols_to_http11()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "wss-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Wss,
                            ListenAddress = "127.0.0.1",
                            Port = 18443,
                            Path = "/ws",
                            ApplicationProtocols = [" h2 ", "http/1.1", "h3"]
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            var listener = Assert.Single(snapshot.TrojanPlan.TlsListeners);
            Assert.Equal(["http/1.1"], listener.ApplicationProtocols);
            Assert.Equal(["http/1.1"], listener.WebSocketInbound!.ApplicationProtocols);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_merges_listener_application_protocols_from_inbounds_and_fallbacks()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "tls-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Tls,
                            ListenAddress = "127.0.0.1",
                            Port = 18443,
                            ApplicationProtocols = [" h2 "],
                            Fallbacks =
                            [
                                new TrojanFallbackConfig
                                {
                                    Alpn = "h3",
                                    Dest = "8443"
                                }
                            ]
                        },
                        new InboundConfig
                        {
                            Tag = "wss-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Wss,
                            ListenAddress = "127.0.0.1",
                            Port = 18443,
                            Path = "/ws"
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            var listener = Assert.Single(snapshot.TrojanPlan.TlsListeners);
            Assert.Equal(["http/1.1", "h2", "h3"], listener.ApplicationProtocols);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_migrates_legacy_trojan_users_and_fallbacks_into_inbounds()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "tls-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Tls,
                            ListenAddress = "127.0.0.1",
                            Port = 18443
                        }
                    ],
                    Users =
                    [
                        new TrojanUserConfig
                        {
                            UserId = "demo-user",
                            Password = "demo-password",
                            BytesPerSecond = 2048,
                            DeviceLimit = 2
                        }
                    ],
                    Fallbacks =
                    [
                        new TrojanFallbackConfig
                        {
                            Path = "/legacy",
                            Dest = "8080"
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            Assert.Empty(snapshot.Config.Users);
            Assert.Empty(snapshot.Config.Fallbacks);
            var inbound = Assert.Single(snapshot.Config.Inbounds);
            var user = Assert.Single(inbound.Users);
            var fallback = Assert.Single(inbound.Fallbacks);
            Assert.Equal("demo-user", user.UserId);
            Assert.Equal("demo-password", user.Password);
            Assert.Equal(2, user.DeviceLimit);
            Assert.Equal("tcp", fallback.Type);
            Assert.Equal("localhost:8080", fallback.Dest);

            var listener = Assert.Single(snapshot.TrojanPlan.TlsListeners);
            Assert.NotNull(listener.RawTlsInbound);
            Assert.Single(listener.RawTlsInbound!.UsersByHash);
            Assert.Equal(2, listener.RawTlsInbound.UsersByHash.Values.Single().DeviceLimit);
            Assert.Single(listener.RawTlsInbound.Fallbacks);
            Assert.Equal("localhost:8080", listener.RawTlsInbound.Fallbacks[0].Dest);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_builds_outbound_runtime_plan_from_unified_config()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "tls-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Trojan,
                            Transport = InboundTransports.Tls,
                            ListenAddress = "127.0.0.1",
                            Port = 18443
                        }
                    ],
                    Outbounds =
                    [
                        new OutboundConfig
                        {
                            Tag = "proxy",
                            Enabled = true,
                            Protocol = OutboundProtocols.Freedom
                        },
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
                            InboundTags = ["tls-entry"],
                            Networks = [RoutingNetworks.Tcp],
                            OutboundTag = "direct"
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            Assert.Equal("proxy", snapshot.OutboundPlan.DefaultOutboundTag);
            Assert.True(snapshot.OutboundPlan.TryResolveOutboundTag(
                new DispatchContext
                {
                    InboundTag = "tls-entry",
                    Network = RoutingNetworks.Tcp
                },
                out var matchedTag));
            Assert.Equal("direct", matchedTag);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_resolves_trojan_outbound_settings_from_runtime_config()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [
                    new FreedomOutboundHandler(),
                    new TrojanOutboundHandler(
                        new TrojanOutboundClient(),
                        new StubTrojanOutboundSettingsProvider(),
                        new TrojanUdpPacketReader(),
                        new TrojanUdpPacketWriter())
                ],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
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
                            Tag = "proxy",
                            Enabled = true,
                            Protocol = OutboundProtocols.Trojan,
                            Via = "srcip",
                            ViaCidr = "/24",
                            TargetStrategy = "force-ipv6v4",
                            ProxyOutboundTag = "direct",
                            MultiplexSettings = new OutboundMultiplexConfig
                            {
                                Enabled = true,
                                Concurrency = 4,
                                XudpConcurrency = 8,
                                XudpProxyUdp443 = OutboundXudpProxyModes.Skip
                            },
                            Transport = TrojanOutboundTransports.Wss,
                            ServerHost = "edge.example.com",
                            ServerPort = 443,
                            ServerName = "edge-sni.example.com",
                            WebSocketPath = "relay",
                            WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["Host"] = "cdn.example.com"
                            },
                            WebSocketEarlyDataBytes = 2048,
                            WebSocketHeartbeatPeriodSeconds = 15,
                            ApplicationProtocols = ["http/1.1", "h2", "http/1.1"],
                            Password = "demo-password",
                            ConnectTimeoutSeconds = 9,
                            HandshakeTimeoutSeconds = 12,
                            SkipCertificateValidation = true
                        }
                    ]
                },
                CancellationToken.None);

            Assert.True(applyResult.Success, applyResult.Error);
            TrojanOutboundSettings settings;
            Assert.True(runtimeConfigStore.TryResolve(new DispatchContext { OutboundTag = "proxy" }, out settings));
            Assert.Equal("proxy", settings.Tag);
            Assert.Equal("srcip", settings.Via);
            Assert.Equal("24", settings.ViaCidr);
            Assert.Equal(OutboundTargetStrategies.ForceIpv6v4, settings.TargetStrategy);
            Assert.Equal("direct", settings.ProxyOutboundTag);
            Assert.True(settings.MultiplexSettings.Enabled);
            Assert.Equal(4, settings.MultiplexSettings.Concurrency);
            Assert.Equal(8, settings.MultiplexSettings.XudpConcurrency);
            Assert.Equal(OutboundXudpProxyModes.Skip, settings.MultiplexSettings.XudpProxyUdp443);
            Assert.Equal("edge.example.com", settings.ServerHost);
            Assert.Equal("edge-sni.example.com", settings.ServerName);
            Assert.Equal(TrojanOutboundTransports.Wss, settings.Transport);
            Assert.Equal("/relay", settings.WebSocketPath);
            Assert.Equal("cdn.example.com", settings.WebSocketHeaders["Host"]);
            Assert.Equal(["http/1.1"], settings.ApplicationProtocols);
            Assert.Equal("demo-password", settings.Password);
            Assert.Equal(9, settings.ConnectTimeoutSeconds);
            Assert.Equal(12, settings.HandshakeTimeoutSeconds);
            Assert.True(settings.SkipCertificateValidation);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_rejects_enabled_inbound_with_unregistered_protocol()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "vmess-entry",
                            Enabled = true,
                            Protocol = "vmess",
                            ListenAddress = "127.0.0.1",
                            Port = 10086
                        }
                    ]
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.False(applyResult.Success);
            Assert.Contains("Unsupported inbound protocol: vmess.", applyResult.Error, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_builds_vless_runtime_plan_from_unified_inbounds()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler(), new VlessInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var uuid = Guid.NewGuid().ToString("D");
            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "vless-tls-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Vless,
                            Transport = InboundTransports.Tls,
                            ListenAddress = "127.0.0.1",
                            Port = 2443,
                            Users =
                            [
                                new TrojanUserConfig
                                {
                                    UserId = "demo-user",
                                    Uuid = uuid,
                                    BytesPerSecond = 4096,
                                    DeviceLimit = 2
                                }
                            ]
                        },
                        new InboundConfig
                        {
                            Tag = "vless-wss-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Vless,
                            Transport = InboundTransports.Wss,
                            ListenAddress = "127.0.0.1",
                            Port = 2444,
                            Path = "vless",
                            Host = "edge.example.com"
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            var plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty);
            Assert.Equal(2, plan.TlsListeners.Count);
            Assert.True(plan.HasTcpTls);
            Assert.True(plan.HasWss);

            var tlsListener = Assert.Single(
                plan.TlsListeners,
                static listener => listener.RawTlsInbound is not null && listener.WebSocketInbound is null);
            var wssListener = Assert.Single(
                plan.TlsListeners,
                static listener => listener.RawTlsInbound is null && listener.WebSocketInbound is not null);

            Assert.Equal(2443, tlsListener.Binding.Port);
            Assert.Equal("vless-tls-entry", tlsListener.RawTlsInbound!.Tag);
            var user = Assert.Single(tlsListener.RawTlsInbound.UsersByUuid);
            Assert.Equal(uuid, user.Key);
            Assert.Equal("demo-user", user.Value.UserId);
            Assert.Equal(2, user.Value.DeviceLimit);
            Assert.Equal(["http/1.1"], wssListener.ApplicationProtocols);
            Assert.Equal("/vless", wssListener.WebSocketInbound!.Path);
            Assert.Equal("edge.example.com", wssListener.WebSocketInbound.Host);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_builds_vmess_runtime_plan_from_unified_inbounds()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler(), new VlessInboundRuntimeCompiler(), new VmessInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var uuid = Guid.NewGuid().ToString("D");
            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "vmess-tls-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Vmess,
                            Transport = InboundTransports.Tls,
                            ListenAddress = "127.0.0.1",
                            Port = 3443,
                            Users =
                            [
                                new TrojanUserConfig
                                {
                                    UserId = "demo-user",
                                    Uuid = uuid,
                                    BytesPerSecond = 2048,
                                    DeviceLimit = 3
                                }
                            ]
                        },
                        new InboundConfig
                        {
                            Tag = "vmess-wss-entry",
                            Enabled = true,
                            Protocol = InboundProtocols.Vmess,
                            Transport = InboundTransports.Wss,
                            ListenAddress = "127.0.0.1",
                            Port = 3444,
                            Path = "vmess",
                            Host = "edge.example.com"
                        }
                    ],
                    Certificate = new CertificateOptions
                    {
                        PfxPath = Path.Combine(testRoot, "placeholder.pfx")
                    }
                },
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            var plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
            Assert.Equal(2, plan.TlsListeners.Count);
            Assert.True(plan.HasTcpTls);
            Assert.True(plan.HasWss);

            var tlsListener = Assert.Single(
                plan.TlsListeners,
                static listener => listener.RawTlsInbound is not null && listener.WebSocketInbound is null);
            var wssListener = Assert.Single(
                plan.TlsListeners,
                static listener => listener.RawTlsInbound is null && listener.WebSocketInbound is not null);

            Assert.Equal(3443, tlsListener.Binding.Port);
            Assert.Equal("vmess-tls-entry", tlsListener.RawTlsInbound!.Tag);
            var user = Assert.Single(tlsListener.RawTlsInbound.Users);
            Assert.Equal("demo-user", user.UserId);
            Assert.Equal(uuid, user.Uuid);
            Assert.Equal(16, user.CmdKey.Length);
            Assert.Equal(3, user.DeviceLimit);
            Assert.Equal(["http/1.1"], wssListener.ApplicationProtocols);
            Assert.Equal("/vmess", wssListener.WebSocketInbound!.Path);
            Assert.Equal("edge.example.com", wssListener.WebSocketInbound.Host);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_recomputes_vmess_behavior_seed_after_revision_reload()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler(), new VlessInboundRuntimeCompiler(), new VmessInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var firstApply = await orchestrator.ApplySnapshotAsync(
                1,
                CreateVmessRuntimeConfig("11111111-1111-1111-1111-111111111111", testRoot),
                CancellationToken.None).ConfigureAwait(false);
            Assert.True(firstApply.Success, firstApply.Error);

            var firstPlan = runtimeConfigStore.GetSnapshot().GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
            var firstListener = Assert.Single(firstPlan.TlsListeners);
            var firstBehaviorSeed = firstListener.RawTlsInbound!.BehaviorSeed;

            var secondApply = await orchestrator.ApplySnapshotAsync(
                2,
                CreateVmessRuntimeConfig("22222222-2222-2222-2222-222222222222", testRoot),
                CancellationToken.None).ConfigureAwait(false);
            Assert.True(secondApply.Success, secondApply.Error);

            var secondPlan = runtimeConfigStore.GetSnapshot().GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
            var secondListener = Assert.Single(secondPlan.TlsListeners);
            var secondBehaviorSeed = secondListener.RawTlsInbound!.BehaviorSeed;

            Assert.NotEqual(firstBehaviorSeed, secondBehaviorSeed);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    [Fact]
    public async Task ApplySnapshotAsync_accepts_empty_inbounds_without_trojan_listeners()
    {
        var testRoot = CreateTestRoot();
        try
        {
            var runtimeConfigStore = new RuntimeConfigStore();
            var orchestrator = new ConfigOrchestrator(
                runtimeConfigStore,
                new UserStore(),
                new RateLimiterRegistry(),
                [new FreedomOutboundHandler()],
                [new TrojanInboundRuntimeCompiler()],
                new PersistedNodeConfigStore(
                    new NodePanelOptions
                    {
                        CachedConfigPath = Path.Combine(testRoot, "runtime.json")
                    },
                    new TestLogger<PersistedNodeConfigStore>()),
                new TestLogger<ConfigOrchestrator>());

            orchestrator.ApplyBootstrap(new NodeServiceConfig());

            var applyResult = await orchestrator.ApplySnapshotAsync(
                1,
                new NodeServiceConfig(),
                CancellationToken.None).ConfigureAwait(false);

            Assert.True(applyResult.Success, applyResult.Error);

            var snapshot = runtimeConfigStore.GetSnapshot();
            Assert.Empty(snapshot.Config.Inbounds);
            Assert.Empty(snapshot.TrojanPlan.TlsListeners);
        }
        finally
        {
            DeleteDirectoryIfExists(testRoot);
        }
    }

    private static string CreateTestRoot()
    {
        var path = Path.Combine(Path.GetTempPath(), "np", Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(path);
        return path;
    }

    private static NodeServiceConfig CreateVmessRuntimeConfig(string uuid, string testRoot)
        => new()
        {
            Inbounds =
            [
                new InboundConfig
                {
                    Tag = "vmess-tls-entry",
                    Enabled = true,
                    Protocol = InboundProtocols.Vmess,
                    Transport = InboundTransports.Tls,
                    ListenAddress = "127.0.0.1",
                    Port = 3443,
                    Users =
                    [
                        new TrojanUserConfig
                        {
                            UserId = "demo-user",
                            Uuid = uuid,
                            BytesPerSecond = 2048,
                            DeviceLimit = 3
                        }
                    ]
                }
            ],
            Certificate = new CertificateOptions
            {
                PfxPath = Path.Combine(testRoot, "placeholder.pfx")
            }
        };

    private static void DeleteDirectoryIfExists(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        Directory.Delete(path, recursive: true);
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull
            => NoopScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => false;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
        }
    }

    private sealed class NoopScope : IDisposable
    {
        public static NoopScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }

    private sealed class StubTrojanOutboundSettingsProvider : ITrojanOutboundSettingsProvider
    {
        public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
        {
            settings = default!;
            return false;
        }
    }
}

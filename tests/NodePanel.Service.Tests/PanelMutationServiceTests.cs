using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class PanelMutationServiceTests
{
    [Fact]
    public async Task PanelCertificateEntity_roundtrip_preserves_thumbprint_and_timestamps()
    {
        using var harness = new PanelMutationHarness();

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(30);
        var lastAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-2);
        var lastSuccessAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        var createdAt = DateTimeOffset.UtcNow.AddDays(-10);
        var updatedAt = DateTimeOffset.UtcNow.AddMinutes(-30);

        var entity = new PanelCertificateEntity
        {
            CertificateId = "panel-cert",
            DisplayName = "Panel Certificate",
            Domain = "panel.example.com",
            PfxBase64 = Convert.ToBase64String([1, 2, 3]),
            Thumbprint = "AD4276A4B92312B203D12A22E6512623673C7C85",
            NotBefore = notBefore,
            NotAfter = notAfter,
            LastAttemptAt = lastAttemptAt,
            LastSuccessAt = lastSuccessAt,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt
        };

        await harness.DatabaseService.FSql.InsertOrUpdate<PanelCertificateEntity>()
            .SetSource(entity)
            .ExecuteAffrowsAsync(CancellationToken.None);

        var stored = await harness.DatabaseService.FSql.Select<PanelCertificateEntity>()
            .Where(item => item.CertificateId == entity.CertificateId)
            .FirstAsync(CancellationToken.None);

        Assert.NotNull(stored);
        Assert.Equal(entity.PfxBase64, stored!.PfxBase64);
        Assert.Equal(entity.Thumbprint, stored.Thumbprint);
        Assert.Equal(entity.NotBefore, stored.NotBefore);
        Assert.Equal(entity.NotAfter, stored.NotAfter);
        Assert.Equal(entity.LastAttemptAt, stored.LastAttemptAt);
        Assert.Equal(entity.LastSuccessAt, stored.LastSuccessAt);
        Assert.Equal(entity.CreatedAt, stored.CreatedAt);
        Assert.Equal(entity.UpdatedAt, stored.UpdatedAt);
    }

    [Fact]
    public void PanelCertificateEntity_falls_back_to_legacy_datetime_columns()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(30);
        var lastAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-2);
        var lastSuccessAt = DateTimeOffset.UtcNow.AddMinutes(-1);
        var createdAt = DateTimeOffset.UtcNow.AddDays(-10);
        var updatedAt = DateTimeOffset.UtcNow.AddMinutes(-30);

        var entity = new PanelCertificateEntity
        {
            LegacyNotBefore = notBefore,
            LegacyNotAfter = notAfter,
            LegacyLastAttemptAt = lastAttemptAt,
            LegacyLastSuccessAt = lastSuccessAt,
            LegacyCreatedAt = createdAt,
            LegacyUpdatedAt = updatedAt,
            NotBeforeUnixMilliseconds = null,
            NotAfterUnixMilliseconds = null,
            LastAttemptAtUnixMilliseconds = null,
            LastSuccessAtUnixMilliseconds = null,
            CreatedAtUnixMilliseconds = null,
            UpdatedAtUnixMilliseconds = null
        };

        Assert.Equal(notBefore, entity.NotBefore);
        Assert.Equal(notAfter, entity.NotAfter);
        Assert.Equal(lastAttemptAt, entity.LastAttemptAt);
        Assert.Equal(lastSuccessAt, entity.LastSuccessAt);
        Assert.Equal(createdAt, entity.CreatedAt);
        Assert.Equal(updatedAt, entity.UpdatedAt);
    }

    [Fact]
    public void PanelCertificateEntity_uses_pfx_metadata_when_timestamp_columns_are_missing()
    {
        var password = "panel-password";
        var pfx = CreateTestCertificatePfx("panel.example.com", password, out var thumbprint, out var notBefore, out var notAfter);

        var entity = new PanelCertificateEntity
        {
            CertificateId = "panel-cert",
            Domain = "panel.example.com",
            PfxPassword = password,
            PfxBase64 = Convert.ToBase64String(pfx),
            Thumbprint = string.Empty,
            LegacyNotBefore = null,
            LegacyNotAfter = null,
            NotBeforeUnixMilliseconds = null,
            NotAfterUnixMilliseconds = null
        };

        var record = entity.ToRecord();

        Assert.Equal(thumbprint, record.Thumbprint);
        Assert.Equal(notBefore, record.NotBefore);
        Assert.Equal(notAfter, record.NotAfter);
    }

    [Fact]
    public async Task SaveNodeAsync_keeps_initial_revision_and_increments_on_update()
    {
        using var harness = new PanelMutationHarness();

        var created = await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest
            {
                DisplayName = "Node A",
                Config = new NodeServiceConfig()
            },
            CancellationToken.None);

        Assert.Equal(1, created.DesiredRevision);
        Assert.Equal(1, (await harness.GetNodeAsync("node-a")).DesiredRevision);

        var updated = await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest
            {
                DisplayName = "Node A Updated",
                Config = new NodeServiceConfig()
            },
            CancellationToken.None);

        Assert.Equal(2, updated.DesiredRevision);
        Assert.Equal(2, (await harness.GetNodeAsync("node-a")).DesiredRevision);
    }

    [Fact]
    public async Task SaveNodeAsync_replaces_existing_advanced_config_sections()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest
            {
                DisplayName = "Node A",
                Config = new NodeServiceConfig
                {
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
            },
            CancellationToken.None);

        await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest
            {
                DisplayName = "Node A",
                Config = new NodeServiceConfig()
            },
            CancellationToken.None);

        var stored = await harness.GetNodeAsync("node-a");
        Assert.Equal(DnsModes.System, stored.Config.Dns.Mode);
        Assert.Empty(stored.Config.Dns.Servers);
        Assert.Empty(stored.Config.Outbounds);
        Assert.Empty(stored.Config.RoutingRules);
    }

    [Fact]
    public async Task SaveUserAsync_increments_only_affected_nodes_for_scoped_user_changes()
    {
        using var harness = new PanelMutationHarness();
        await harness.CreateNodeAsync("node-a");
        await harness.CreateNodeAsync("node-b");

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(["node-a"]),
            CancellationToken.None);

        Assert.Equal(2, (await harness.GetNodeAsync("node-a")).DesiredRevision);
        Assert.Equal(1, (await harness.GetNodeAsync("node-b")).DesiredRevision);

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(["node-b"]),
            CancellationToken.None);

        Assert.Equal(3, (await harness.GetNodeAsync("node-a")).DesiredRevision);
        Assert.Equal(2, (await harness.GetNodeAsync("node-b")).DesiredRevision);
    }

    [Fact]
    public async Task SaveUserAsync_increments_all_nodes_for_global_user_changes()
    {
        using var harness = new PanelMutationHarness();
        await harness.CreateNodeAsync("node-a");
        await harness.CreateNodeAsync("node-b");

        await harness.MutationService.SaveUserAsync(
            "user-global",
            CreateUserRequest(Array.Empty<string>()),
            CancellationToken.None);

        Assert.Equal(2, (await harness.GetNodeAsync("node-a")).DesiredRevision);
        Assert.Equal(2, (await harness.GetNodeAsync("node-b")).DesiredRevision);
    }

    [Fact]
    public async Task SaveUserAsync_persists_device_limit()
    {
        using var harness = new PanelMutationHarness();

        var saved = await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with
            {
                DeviceLimit = 3
            },
            CancellationToken.None);

        Assert.Equal(3, saved.DeviceLimit);
        Assert.Equal(3, (await harness.GetUserAsync("user-a")).DeviceLimit);
    }

    [Fact]
    public async Task SaveUserAsync_persists_cycle_and_preserves_existing_cycle_when_request_omits_it()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with
            {
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    Cycle = "month",
                    TransferEnableBytes = 1024
                }
            },
            CancellationToken.None);

        var updated = await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with
            {
                DisplayName = "Updated User",
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    TransferEnableBytes = 2048
                }
            },
            CancellationToken.None);

        Assert.Equal("month", updated.Subscription.Cycle);
        Assert.Equal("month", (await harness.GetUserAsync("user-a")).Cycle);
    }

    [Fact]
    public async Task CompleteOrderAsync_applies_plan_cycle_and_quota_to_user()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePlanAsync(
            "plan-a",
            new UpsertPlanRequest
            {
                Name = "Pro Plan",
                GroupId = 2,
                TransferEnableBytes = 536870912000L,
                MonthPrice = 20m
            },
            CancellationToken.None);

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()),
            CancellationToken.None);

        var order = await harness.MutationService.CreateOrderAsync(
            "user-a",
            "plan-a",
            "month",
            20m,
            cancellationToken: CancellationToken.None);

        await harness.MutationService.CompleteOrderAsync(order.OrderId, CancellationToken.None);

        var user = await harness.GetUserAsync("user-a");

        Assert.Equal("Pro Plan", user.PlanName);
        Assert.Equal("month", user.Cycle);
        Assert.Equal(536870912000L, user.TransferEnableBytes);
        Assert.Equal(2, user.GroupId);
    }

    [Fact]
    public async Task CompleteOrderAsync_reset_price_only_resets_traffic()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePlanAsync(
            "reset-pack",
            new UpsertPlanRequest
            {
                Name = "Reset Pack",
                GroupId = 1,
                TransferEnableBytes = 107374182400L,
                ResetPrice = 5m
            },
            CancellationToken.None);

        var expiresAt = DateTimeOffset.UtcNow.AddDays(20);
        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with
            {
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    Cycle = "month",
                    TransferEnableBytes = 107374182400L,
                    ExpiresAt = expiresAt
                }
            },
            CancellationToken.None);

        await harness.DatabaseService.FSql.InsertOrUpdate<TrafficRecordEntity>()
            .SetSource(
                new TrafficRecordEntity
                {
                    UserId = "user-a",
                    UploadBytes = 100,
                    DownloadBytes = 200
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        var order = await harness.MutationService.CreateOrderAsync(
            "user-a",
            "reset-pack",
            "reset_price",
            5m,
            cancellationToken: CancellationToken.None);

        await harness.MutationService.CompleteOrderAsync(order.OrderId, CancellationToken.None);

        var user = await harness.GetUserAsync("user-a");
        var traffic = await harness.DatabaseService.FSql.Select<TrafficRecordEntity>()
            .Where(item => item.UserId == "user-a")
            .FirstAsync(CancellationToken.None);

        Assert.Equal("starter", user.PlanName);
        Assert.Equal("month", user.Cycle);
        Assert.Equal(107374182400L, user.TransferEnableBytes);
        Assert.NotNull(traffic);
        Assert.Equal(0L, traffic!.UploadBytes);
        Assert.Equal(0L, traffic.DownloadBytes);
    }

    [Fact]
    public async Task PanelHttpsRuntime_returns_self_signed_certificate_when_no_formal_certificate_is_bound()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePanelHttpsSettingsAsync(
            new PanelHttpsSettingsFormInput
            {
                Enabled = true,
                CertificateId = string.Empty,
                ListenAddress = "0.0.0.0",
                Port = 443,
                RedirectHttpToHttps = false
            },
            CancellationToken.None);

        var snapshot = harness.GetPanelHttpsSnapshot();
        var options = harness.CreatePanelHttpsAuthenticationOptions();

        Assert.Null(snapshot.Certificate);
        Assert.NotNull(options.ServerCertificate);
        Assert.Contains("CN=NodePanel Temporary TLS", options.ServerCertificate!.Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PanelHttpsRuntime_falls_back_to_self_signed_certificate_when_selected_certificate_has_no_pfx()
    {
        using var harness = new PanelMutationHarness();

        await harness.DatabaseService.FSql.InsertOrUpdate<PanelCertificateEntity>()
            .SetSource(
                new PanelCertificateEntity
                {
                    CertificateId = "panel-cert",
                    DisplayName = "Panel Certificate",
                    Domain = "panel.example.com",
                    AltNames = ["alt.example.com"],
                    PfxBase64 = string.Empty,
                    CreatedAt = DateTimeOffset.UtcNow,
                    UpdatedAt = DateTimeOffset.UtcNow
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        await harness.MutationService.SavePanelHttpsSettingsAsync(
            new PanelHttpsSettingsFormInput
            {
                Enabled = true,
                CertificateId = "panel-cert",
                ListenAddress = "0.0.0.0",
                Port = 443,
                RedirectHttpToHttps = false
            },
            CancellationToken.None);

        var snapshot = harness.GetPanelHttpsSnapshot();
        var options = harness.CreatePanelHttpsAuthenticationOptions();

        Assert.Null(snapshot.Certificate);
        Assert.Contains("panel.example.com", snapshot.FallbackServerNames);
        Assert.Contains("alt.example.com", snapshot.FallbackServerNames);
        Assert.Contains("自签证书", snapshot.LastError, StringComparison.Ordinal);
        Assert.NotNull(options.ServerCertificate);
        Assert.Contains("CN=NodePanel Temporary TLS", options.ServerCertificate!.Subject, StringComparison.OrdinalIgnoreCase);
    }

    private static UpsertUserRequest CreateUserRequest(IReadOnlyList<string> nodeIds)
        => new()
        {
            DisplayName = "Demo User",
            SubscriptionToken = "sub-token",
            TrojanPassword = "trojan-password",
            Enabled = true,
            BytesPerSecond = 2048,
            DeviceLimit = 0,
            NodeIds = nodeIds,
            Subscription = new PanelUserSubscriptionProfile
            {
                PlanName = "starter",
                TransferEnableBytes = 1024
            }
        };

    private static byte[] CreateTestCertificatePfx(
        string commonName,
        string password,
        out string thumbprint,
        out DateTimeOffset notBefore,
        out DateTimeOffset notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var start = DateTimeOffset.UtcNow.AddMinutes(-5);
        var end = start.AddDays(30);

        using var certificate = request.CreateSelfSigned(start, end);
        var exported = certificate.Export(X509ContentType.Pfx, password);
        using var exportable = X509CertificateLoader.LoadPkcs12(
            exported,
            password,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

        thumbprint = exportable.Thumbprint ?? string.Empty;
        notBefore = new DateTimeOffset(exportable.NotBefore);
        notAfter = new DateTimeOffset(exportable.NotAfter);
        return exported;
    }

    private sealed class PanelMutationHarness : IDisposable
    {
        private readonly string _rootPath;
        private readonly PanelHttpsRuntime _panelHttpsRuntime;

        public PanelMutationHarness()
        {
            _rootPath = Path.Combine(Path.GetTempPath(), "np-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_rootPath);

            var dbPath = Path.Combine(_rootPath, "panel.db");
            DatabaseService = new DatabaseService(
                new StaticOptionsMonitor<PanelOptions>(
                    new PanelOptions
                    {
                        DbType = "sqlite",
                        DbConnectionString = $"Data Source={dbPath}"
                    }));
            _panelHttpsRuntime = new PanelHttpsRuntime(
                new PanelOptions
                {
                    DbType = "sqlite",
                    DbConnectionString = $"Data Source={dbPath}"
                });

            var snapshotBuilder = new PanelSnapshotBuilder(DatabaseService);
            var pushService = new ControlPlanePushService(
                snapshotBuilder,
                new NodeConnectionRegistry(),
                NullLogger<ControlPlanePushService>.Instance);

            MutationService = new PanelMutationService(DatabaseService, pushService, _panelHttpsRuntime);
        }

        public DatabaseService DatabaseService { get; }

        public PanelMutationService MutationService { get; }

        public PanelHttpsRuntimeSnapshot GetPanelHttpsSnapshot()
            => _panelHttpsRuntime.GetSnapshot();

        public SslServerAuthenticationOptions CreatePanelHttpsAuthenticationOptions()
            => _panelHttpsRuntime.CreateAuthenticationOptions();

        public async Task CreateNodeAsync(string nodeId)
        {
            await MutationService.SaveNodeAsync(
                nodeId,
                new UpsertNodeRequest
                {
                    DisplayName = nodeId,
                    Config = new NodeServiceConfig()
                },
                CancellationToken.None);
        }

        public async Task<NodeEntity> GetNodeAsync(string nodeId)
            => await DatabaseService.FSql.Select<NodeEntity>().Where(x => x.NodeId == nodeId).FirstAsync(CancellationToken.None)
               ?? throw new InvalidOperationException($"Node '{nodeId}' was not found.");

        public async Task<UserEntity> GetUserAsync(string userId)
            => await DatabaseService.FSql.Select<UserEntity>().Where(x => x.UserId == userId).FirstAsync(CancellationToken.None)
               ?? throw new InvalidOperationException($"User '{userId}' was not found.");

        public void Dispose()
        {
            _panelHttpsRuntime.Dispose();
            DatabaseService.Dispose();
            if (Directory.Exists(_rootPath))
            {
                Directory.Delete(_rootPath, recursive: true);
            }
        }
    }

    private sealed class StaticOptionsMonitor<TOptions> : IOptionsMonitor<TOptions>
    {
        public StaticOptionsMonitor(TOptions currentValue)
        {
            CurrentValue = currentValue;
        }

        public TOptions CurrentValue { get; }

        public TOptions Get(string? name) => CurrentValue;

        public IDisposable OnChange(Action<TOptions, string?> listener) => NoopDisposable.Instance;
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static NoopDisposable Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}

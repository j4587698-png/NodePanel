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

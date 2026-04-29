using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
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
    public async Task DeleteNodeAsync_deletes_offline_node_and_preserves_explicit_user_scope()
    {
        using var harness = new PanelMutationHarness();
        await harness.CreateNodeAsync("node-a");
        await harness.CreateNodeAsync("node-b");
        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(["node-a", "node-b"]),
            CancellationToken.None);
        await harness.MutationService.SaveUserAsync(
            "user-b",
            CreateUserRequest(["node-a"]),
            CancellationToken.None);

        var deleted = await harness.MutationService.DeleteNodeAsync("node-a", CancellationToken.None);

        Assert.True(deleted);
        Assert.False(await harness.DatabaseService.FSql.Select<NodeEntity>()
            .Where(x => x.NodeId == "node-a")
            .AnyAsync(CancellationToken.None));
        Assert.Equal(["node-b"], (await harness.GetUserAsync("user-a")).NodeIds);
        Assert.Equal(["node-a"], (await harness.GetUserAsync("user-b")).NodeIds);
    }

    [Fact]
    public async Task DeleteNodeAsync_rejects_connected_node()
    {
        using var harness = new PanelMutationHarness();
        await harness.CreateNodeAsync("node-a");
        harness.NodeConnectionRegistry.RecordHeartbeat("node-a", DateTimeOffset.UtcNow);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            harness.MutationService.DeleteNodeAsync("node-a", CancellationToken.None));

        Assert.Contains("当前在线", exception.Message, StringComparison.Ordinal);
        Assert.True(await harness.DatabaseService.FSql.Select<NodeEntity>()
            .Where(x => x.NodeId == "node-a")
            .AnyAsync(CancellationToken.None));
    }

    [Fact]
    public async Task SaveServerGroupAsync_updates_node_memberships_from_group_editor()
    {
        using var harness = new PanelMutationHarness();
        await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest { DisplayName = "Node A", Config = new NodeServiceConfig() },
            CancellationToken.None);
        await harness.MutationService.SaveNodeAsync(
            "node-b",
            new UpsertNodeRequest { DisplayName = "Node B", Config = new NodeServiceConfig() },
            CancellationToken.None);
        await harness.MutationService.SaveNodeAsync(
            "node-c",
            new UpsertNodeRequest { DisplayName = "Node C", GroupIds = [7, 9], Config = new NodeServiceConfig() },
            CancellationToken.None);

        await harness.MutationService.SaveServerGroupAsync(7, "VIP", ["node-a", "node-c"], CancellationToken.None);

        Assert.Equal([7], (await harness.GetNodeAsync("node-a")).GroupIds);
        Assert.Empty((await harness.GetNodeAsync("node-b")).GroupIds);
        Assert.Equal([7, 9], (await harness.GetNodeAsync("node-c")).GroupIds);

        await harness.MutationService.SaveServerGroupAsync(7, "VIP", ["node-b"], CancellationToken.None);

        Assert.Empty((await harness.GetNodeAsync("node-a")).GroupIds);
        Assert.Equal([7], (await harness.GetNodeAsync("node-b")).GroupIds);
        Assert.Equal([9], (await harness.GetNodeAsync("node-c")).GroupIds);
    }

    [Fact]
    public async Task DeleteServerGroupAsync_removes_group_membership_from_nodes()
    {
        using var harness = new PanelMutationHarness();
        await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest { DisplayName = "Node A", GroupIds = [7, 9], Config = new NodeServiceConfig() },
            CancellationToken.None);
        await harness.MutationService.SaveServerGroupAsync(7, "VIP", ["node-a"], CancellationToken.None);

        await harness.MutationService.DeleteServerGroupAsync(7, CancellationToken.None);

        Assert.Equal([9], (await harness.GetNodeAsync("node-a")).GroupIds);
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
    public async Task SaveUserAsync_persists_extended_user_fields()
    {
        using var harness = new PanelMutationHarness();

        var saved = await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with
            {
                InviteUserId = "inviter-a",
                CommissionBalance = 12.34m,
                CommissionRate = 35,
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    TransferEnableBytes = 1024,
                    PurchaseUrl = "https://panel.example.com/plan/starter",
                    PortalNotice = "Portal notice"
                }
            },
            CancellationToken.None);

        var stored = await harness.GetUserAsync("user-a");

        Assert.Equal("inviter-a", saved.InviteUserId);
        Assert.Equal(12.34m, saved.CommissionBalance);
        Assert.Equal(35, saved.CommissionRate);
        Assert.Equal("https://panel.example.com/plan/starter", saved.Subscription.PurchaseUrl);
        Assert.Equal("Portal notice", saved.Subscription.PortalNotice);
        Assert.Equal("inviter-a", stored.InviteUserId);
        Assert.Equal(12.34m, stored.CommissionBalance);
        Assert.Equal(35, stored.CommissionRate);
        Assert.Equal("https://panel.example.com/plan/starter", stored.PurchaseUrl);
        Assert.Equal("Portal notice", stored.PortalNotice);
    }

    [Fact]
    public async Task SaveUserAsync_generates_missing_access_secrets_and_hashes_login_password()
    {
        using var harness = new PanelMutationHarness();

        var saved = await harness.MutationService.SaveUserAsync(
            "user-a",
            new UpsertUserRequest
            {
                Email = "user@example.com",
                LoginPassword = "Portal#123",
                DisplayName = "Demo User",
                Enabled = true,
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    TransferEnableBytes = 1024
                }
            },
            CancellationToken.None);

        var stored = await harness.GetUserAsync("user-a");
        var hasher = new PasswordHasher<UserEntity>();

        Assert.Equal("user@example.com", saved.Email);
        Assert.NotEmpty(saved.SubscriptionToken);
        Assert.NotEmpty(saved.TrojanPassword);
        Assert.NotEmpty(saved.V2rayUuid);
        Assert.False(string.IsNullOrWhiteSpace(stored.PasswordHash));
        Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(stored, stored.PasswordHash, "Portal#123"));
    }

    [Fact]
    public async Task CreateInviteCodeAsync_generates_codes_until_the_user_reaches_the_limit()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with { Email = "user@example.com" },
            CancellationToken.None);

        var first = await harness.MutationService.CreateInviteCodeAsync("user-a", 2, CancellationToken.None);
        var second = await harness.MutationService.CreateInviteCodeAsync("user-a", 2, CancellationToken.None);
        var stored = await harness.DatabaseService.FSql.Select<InviteCodeEntity>()
            .Where(x => x.UserId == "user-a")
            .ToListAsync(CancellationToken.None);

        Assert.Equal("user-a", first.UserId);
        Assert.Equal("user-a", second.UserId);
        Assert.NotEqual(first.Code, second.Code);
        Assert.Equal(2, stored.Count);
    }

    [Fact]
    public async Task CreateInviteCodeAsync_rejects_generation_when_the_limit_is_reached()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with { Email = "user@example.com" },
            CancellationToken.None);

        await harness.MutationService.CreateInviteCodeAsync("user-a", 1, CancellationToken.None);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => harness.MutationService.CreateInviteCodeAsync("user-a", 1, CancellationToken.None));

        Assert.Contains("邀请码", exception.Message);
    }

    [Fact]
    public async Task BuildUserReferralCenterAsync_aggregates_invite_codes_invitees_and_commissions()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveUserAsync(
            "inviter",
            CreateUserRequest(Array.Empty<string>()) with
            {
                Email = "inviter@example.com",
                DisplayName = "Inviter",
                CommissionBalance = 6.66m,
                CommissionRate = 20
            },
            CancellationToken.None);

        await harness.MutationService.SaveSettingsAsync(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [PanelAuthSettingKeys.RequireInviteCodeForRegistration] = "true",
                [PanelAuthSettingKeys.MaxInviteCodesPerUser] = "2"
            },
            CancellationToken.None);

        var firstCode = await harness.MutationService.CreateInviteCodeAsync("inviter", 2, CancellationToken.None);
        var secondCode = await harness.MutationService.CreateInviteCodeAsync("inviter", 2, CancellationToken.None);
        var createdAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        await harness.DatabaseService.FSql.Insert(
                new UserEntity
                {
                    UserId = "invitee-a",
                    Email = "invitee@example.com",
                    PasswordHash = "hash",
                    DisplayName = "Invitee",
                    SubscriptionToken = "sub-token",
                    TrojanPassword = "trojan-password",
                    V2rayUuid = Guid.NewGuid().ToString("D"),
                    InviteUserId = "inviter",
                    AppliedInviteCode = firstCode.Code,
                    CreatedAt = createdAt
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        await harness.DatabaseService.FSql.Insert(
                new CommissionLogEntity
                {
                    LogId = Guid.NewGuid().ToString("N"),
                    InviteUserId = "inviter",
                    OrderId = "order-1",
                    TradeAmount = 100m,
                    CommissionAmount = 20m,
                    CreatedAt = createdAt
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        var queryService = harness.CreateQueryService();
        var model = await queryService.BuildUserReferralCenterAsync("inviter", CancellationToken.None);

        Assert.True(model.InviteOnlyRegistrationEnabled);
        Assert.Equal(2, model.MaxInviteCodes);
        Assert.Equal("2", model.MaxInviteCodesText);
        Assert.Equal("0", model.RemainingInviteCodesText);
        Assert.False(model.CanGenerateInviteCode);
        Assert.Equal(2, model.InviteCodeCount);
        Assert.Equal(1, model.InvitedUserCount);
        Assert.Equal(6.66m, model.CommissionBalance);
        Assert.Equal(20m, model.CommissionTotal);
        Assert.Equal(20, model.CommissionRate);

        var firstCodeView = Assert.Single(model.InviteCodes, item => item.Code == firstCode.Code);
        var secondCodeView = Assert.Single(model.InviteCodes, item => item.Code == secondCode.Code);
        var invitee = Assert.Single(model.Invitees);
        var commission = Assert.Single(model.CommissionLogs);

        Assert.Equal(1, firstCodeView.UsageCount);
        Assert.NotEqual("-", firstCodeView.LastUsedAtText);
        Assert.Equal(0, secondCodeView.UsageCount);
        Assert.Equal("-", secondCodeView.LastUsedAtText);
        Assert.Equal("Invitee", invitee.DisplayName);
        Assert.Equal(firstCode.Code, invitee.AppliedInviteCode);
        Assert.Equal("order-1", commission.OrderId);
        Assert.Equal(100m, commission.TradeAmount);
        Assert.Equal(20m, commission.CommissionAmount);
    }

    [Fact]
    public async Task ResetUserSubscriptionTokenAsync_rotates_only_subscription_token()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()) with
            {
                Email = "user@example.com",
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    TransferEnableBytes = 1024
                }
            },
            CancellationToken.None);

        var before = await harness.GetUserAsync("user-a");
        var updated = await harness.MutationService.ResetUserSubscriptionTokenAsync("user-a", CancellationToken.None);
        var after = await harness.GetUserAsync("user-a");

        Assert.NotEqual(before.SubscriptionToken, updated.SubscriptionToken);
        Assert.Equal(updated.SubscriptionToken, after.SubscriptionToken);
        Assert.Equal(before.Email, after.Email);
        Assert.Equal(before.TrojanPassword, after.TrojanPassword);
        Assert.Equal(before.V2rayUuid, after.V2rayUuid);
        Assert.Equal(before.PlanName, after.PlanName);
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
    public async Task CompleteOrderAsync_preserves_existing_user_metadata()
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
            CreateUserRequest(Array.Empty<string>()) with
            {
                InviteUserId = "inviter-a",
                CommissionBalance = 8.5m,
                CommissionRate = 15,
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = "starter",
                    Cycle = "month",
                    TransferEnableBytes = 1024,
                    PurchaseUrl = "https://panel.example.com/upgrade",
                    PortalNotice = "Existing portal notice"
                }
            },
            CancellationToken.None);

        var order = await harness.MutationService.CreateOrderAsync(
            "user-a",
            "plan-a",
            "month",
            20m,
            cancellationToken: CancellationToken.None);

        await harness.MutationService.CompleteOrderAsync(order.OrderId, CancellationToken.None);

        var user = await harness.GetUserAsync("user-a");

        Assert.Equal("inviter-a", user.InviteUserId);
        Assert.Equal(8.5m, user.CommissionBalance);
        Assert.Equal(15, user.CommissionRate);
        Assert.Equal("https://panel.example.com/upgrade", user.PurchaseUrl);
        Assert.Equal("Existing portal notice", user.PortalNotice);
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

        await harness.DatabaseService.FSql.InsertOrUpdate<ScopedTrafficRecordEntity>()
            .SetSource(
                new ScopedTrafficRecordEntity
                {
                    UserId = "user-a",
                    Protocol = "trojan",
                    InboundTag = "in-trojan",
                    UploadBytes = 60,
                    DownloadBytes = 40
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        await harness.DatabaseService.FSql.InsertOrUpdate<ScopedTrafficRecordEntity>()
            .SetSource(
                new ScopedTrafficRecordEntity
                {
                    UserId = "user-a",
                    Protocol = "vless",
                    InboundTag = "in-vless",
                    UploadBytes = 30,
                    DownloadBytes = 20
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
        var scopedTraffic = await harness.DatabaseService.FSql.Select<ScopedTrafficRecordEntity>()
            .Where(item => item.UserId == "user-a")
            .OrderBy(item => item.Protocol)
            .ToListAsync(CancellationToken.None);

        Assert.Equal("starter", user.PlanName);
        Assert.Equal("month", user.Cycle);
        Assert.Equal(107374182400L, user.TransferEnableBytes);
        Assert.NotNull(traffic);
        Assert.Equal(0L, traffic!.UploadBytes);
        Assert.Equal(0L, traffic.DownloadBytes);
        Assert.NotNull(traffic.LastResetAt);
        Assert.Collection(
            scopedTraffic,
            item =>
            {
                Assert.Equal("trojan", item.Protocol);
                Assert.Equal("in-trojan", item.InboundTag);
                Assert.Equal(0L, item.UploadBytes);
                Assert.Equal(0L, item.DownloadBytes);
                Assert.NotNull(item.LastResetAt);
            },
            item =>
            {
                Assert.Equal("vless", item.Protocol);
                Assert.Equal("in-vless", item.InboundTag);
                Assert.Equal(0L, item.UploadBytes);
                Assert.Equal(0L, item.DownloadBytes);
                Assert.NotNull(item.LastResetAt);
            });
    }

    [Fact]
    public async Task NetworkAccountingService_process_traffic_persists_scoped_records_without_losing_user_totals()
    {
        using var harness = new PanelMutationHarness();
        var trojanRuntimeKey = RuntimeUserKeys.Create("trojan", "in-a", "shared-user");
        var vlessRuntimeKey = RuntimeUserKeys.Create("vless", "in-b", "shared-user");

        await harness.MutationService.SaveNodeAsync(
            "node-a",
            new UpsertNodeRequest
            {
                DisplayName = "Node A",
                TrafficMultiplier = 2.0m,
                Config = new NodeServiceConfig()
            },
            CancellationToken.None);

        var service = new NetworkAccountingService(
            harness.DatabaseService,
            harness.MutationService,
            NullLogger<NetworkAccountingService>.Instance);

        service.EnqueueTrafficDelta(
            "node-a",
            [
                new UserTrafficDelta
                {
                    RuntimeKey = trojanRuntimeKey,
                    Protocol = "trojan",
                    InboundTag = "in-a",
                    UserId = "shared-user",
                    UploadBytes = 100,
                    DownloadBytes = 20
                },
                new UserTrafficDelta
                {
                    RuntimeKey = trojanRuntimeKey,
                    Protocol = "trojan",
                    InboundTag = "in-a",
                    UserId = "shared-user",
                    UploadBytes = 25,
                    DownloadBytes = 5
                },
                new UserTrafficDelta
                {
                    RuntimeKey = vlessRuntimeKey,
                    Protocol = "vless",
                    InboundTag = "in-b",
                    UserId = "shared-user",
                    UploadBytes = 40,
                    DownloadBytes = 10
                }
            ]);

        await InvokeProcessTrafficAsync(service);

        var traffic = await harness.DatabaseService.FSql.Select<TrafficRecordEntity>()
            .Where(item => item.UserId == "shared-user")
            .FirstAsync(CancellationToken.None);
        var scopedTraffic = await harness.DatabaseService.FSql.Select<ScopedTrafficRecordEntity>()
            .Where(item => item.UserId == "shared-user")
            .OrderBy(item => item.Protocol)
            .ToListAsync(CancellationToken.None);

        Assert.NotNull(traffic);
        Assert.Equal(330L, traffic!.UploadBytes);
        Assert.Equal(70L, traffic.DownloadBytes);
        Assert.Collection(
            scopedTraffic,
            item =>
            {
                Assert.Equal("trojan", item.Protocol);
                Assert.Equal("in-a", item.InboundTag);
                Assert.Equal("shared-user", item.UserId);
                Assert.Equal(250L, item.UploadBytes);
                Assert.Equal(50L, item.DownloadBytes);
            },
            item =>
            {
                Assert.Equal("vless", item.Protocol);
                Assert.Equal("in-b", item.InboundTag);
                Assert.Equal("shared-user", item.UserId);
                Assert.Equal(80L, item.UploadBytes);
                Assert.Equal(20L, item.DownloadBytes);
            });
    }

    [Fact]
    public async Task BuildStateViewAsync_exposes_persisted_scoped_traffic_records_by_user()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SaveUserAsync(
            "user-a",
            CreateUserRequest(Array.Empty<string>()),
            CancellationToken.None);

        await harness.MutationService.SaveUserAsync(
            "user-b",
            CreateUserRequest(Array.Empty<string>()) with
            {
                DisplayName = "User B",
                SubscriptionToken = "sub-token-b",
                TrojanPassword = "trojan-password-b"
            },
            CancellationToken.None);

        await harness.DatabaseService.FSql.InsertOrUpdate<ScopedTrafficRecordEntity>()
            .SetSource(
                new ScopedTrafficRecordEntity
                {
                    UserId = "user-a",
                    Protocol = "vless",
                    InboundTag = "in-b",
                    UploadBytes = 20,
                    DownloadBytes = 10
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        await harness.DatabaseService.FSql.InsertOrUpdate<ScopedTrafficRecordEntity>()
            .SetSource(
                new ScopedTrafficRecordEntity
                {
                    UserId = "user-a",
                    Protocol = "trojan",
                    InboundTag = "in-a",
                    UploadBytes = 50,
                    DownloadBytes = 5
                })
            .ExecuteAffrowsAsync(CancellationToken.None);

        var view = await harness.CreateQueryService().BuildStateViewAsync(CancellationToken.None);

        Assert.True(view.ScopedTrafficRecordsByUser.ContainsKey("user-a"));
        Assert.True(view.ScopedTrafficRecordsByUser.ContainsKey("user-b"));
        Assert.Collection(
            view.ScopedTrafficRecordsByUser["user-a"],
            item =>
            {
                Assert.Equal("trojan", item.Protocol);
                Assert.Equal("in-a", item.InboundTag);
                Assert.Equal(RuntimeUserKeys.Create("trojan", "in-a", "user-a"), item.RuntimeKey);
                Assert.Equal(50L, item.UploadBytes);
                Assert.Equal(5L, item.DownloadBytes);
            },
            item =>
            {
                Assert.Equal("vless", item.Protocol);
                Assert.Equal("in-b", item.InboundTag);
                Assert.Equal(RuntimeUserKeys.Create("vless", "in-b", "user-a"), item.RuntimeKey);
                Assert.Equal(20L, item.UploadBytes);
                Assert.Equal(10L, item.DownloadBytes);
            });
        Assert.Empty(view.ScopedTrafficRecordsByUser["user-b"]);
    }

    [Fact]
    public void UserEntity_to_record_accepts_legacy_csv_node_ids()
    {
        var entity = new UserEntity
        {
            UserId = "user-a",
            InviteUserId = "inviter-a",
            CommissionBalance = 3.21m,
            CommissionRate = 25,
            PurchaseUrl = "https://panel.example.com/upgrade",
            PortalNotice = "Existing portal notice",
            NodeIdsJson = "node-b, node-a, node-b"
        };

        var record = entity.ToRecord();

        Assert.Equal(["node-b", "node-a"], record.NodeIds);
        Assert.Equal("inviter-a", record.InviteUserId);
        Assert.Equal(3.21m, record.CommissionBalance);
        Assert.Equal(25, record.CommissionRate);
        Assert.Equal("https://panel.example.com/upgrade", record.Subscription.PurchaseUrl);
        Assert.Equal("Existing portal notice", record.Subscription.PortalNotice);
    }

    [Fact]
    public async Task PanelHttpsRuntime_returns_self_signed_certificate_when_no_formal_certificate_is_bound()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePanelHttpsSettingsAsync(
            new PanelHttpsSettingsFormInput
            {
                CertificateId = string.Empty,
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
                CertificateId = "panel-cert",
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

    [Fact]
    public async Task PanelHttpsRuntime_redirects_http_requests_to_the_configured_https_endpoint()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePanelHttpsSettingsAsync(
            new PanelHttpsSettingsFormInput
            {
                CertificateId = string.Empty,
                RedirectHttpToHttps = true
            },
            CancellationToken.None);

        harness.MarkPanelHttpsListenerConfigured(8443);

        var request = new DefaultHttpContext().Request;
        request.Scheme = Uri.UriSchemeHttp;
        request.Host = new HostString("panel.example.com");
        request.Path = "/admin";
        request.QueryString = new QueryString("?tab=https");

        Assert.True(harness.ShouldRedirectHttp("/admin"));
        Assert.False(harness.ShouldRedirectHttp("/.well-known/acme-challenge/token"));
        Assert.False(harness.ShouldRedirectHttp("/control/ws"));
        Assert.Equal("https://panel.example.com:8443/admin?tab=https", harness.BuildPanelHttpsRedirectUri(request).ToString());
    }

    [Fact]
    public async Task PanelHttpsRuntime_redirects_ipv6_http_requests_to_the_configured_https_endpoint()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePanelHttpsSettingsAsync(
            new PanelHttpsSettingsFormInput
            {
                CertificateId = string.Empty,
                RedirectHttpToHttps = true
            },
            CancellationToken.None);

        harness.MarkPanelHttpsListenerConfigured(8443);

        var request = new DefaultHttpContext().Request;
        request.Scheme = Uri.UriSchemeHttp;
        request.Host = HostString.FromUriComponent("https://[2001:db8::10]:8080");
        request.PathBase = "/panel";
        request.Path = "/admin";
        request.QueryString = new QueryString("?tab=https");

        Assert.True(harness.TryBuildPanelHttpsRedirectUri(request, out var redirectUri));
        Assert.NotNull(redirectUri);
        Assert.Equal("https://[2001:db8::10]:8443/panel/admin?tab=https", redirectUri!.ToString());
    }

    [Fact]
    public async Task PanelHttpsRuntime_skips_redirect_when_request_host_is_invalid()
    {
        using var harness = new PanelMutationHarness();

        await harness.MutationService.SavePanelHttpsSettingsAsync(
            new PanelHttpsSettingsFormInput
            {
                CertificateId = string.Empty,
                RedirectHttpToHttps = true
            },
            CancellationToken.None);

        harness.MarkPanelHttpsListenerConfigured(8443);

        var request = new DefaultHttpContext().Request;
        request.Scheme = Uri.UriSchemeHttp;
        request.Host = new HostString("bad host");
        request.Path = "/admin";

        Assert.False(harness.TryBuildPanelHttpsRedirectUri(request, out var redirectUri));
        Assert.Null(redirectUri);
    }

    [Theory]
    [InlineData("vless", "vless-tcp-tls")]
    [InlineData("vmess", "vmess-tcp-tls")]
    public async Task PanelSnapshotBuilder_injects_uuid_users_for_v2ray_inbounds(string protocol, string tag)
    {
        using var harness = new PanelMutationHarness();
        var nodeId = $"node-{protocol}";
        const string userId = "user-v2ray";
        var uuid = Guid.NewGuid().ToString("D");

        await harness.MutationService.SaveNodeAsync(
            nodeId,
            new UpsertNodeRequest
            {
                DisplayName = nodeId,
                Protocol = protocol,
                Config = new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = tag,
                            Enabled = true,
                            Protocol = protocol,
                            Transport = InboundTransports.Tls,
                            TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                            TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                            ListenAddress = "0.0.0.0",
                            Port = 443,
                            Users =
                            [
                                new TrojanUserConfig
                                {
                                    UserId = userId,
                                    Uuid = Guid.NewGuid().ToString("D")
                                }
                            ]
                        }
                    ]
                }
            },
            CancellationToken.None);

        await harness.MutationService.SaveUserAsync(
            userId,
            CreateUserRequest([nodeId]) with
            {
                V2rayUuid = uuid
            },
            CancellationToken.None);

        var snapshotBuilder = new PanelSnapshotBuilder(harness.DatabaseService);
        var result = await snapshotBuilder.TryBuildAsync(nodeId, CancellationToken.None);

        Assert.True(result.Success);
        var inbound = Assert.Single(result.Config.Inbounds);
        var user = Assert.Single(inbound.Users);
        Assert.Equal(protocol, InboundProtocols.Normalize(inbound.Protocol));
        Assert.Equal(userId, user.UserId);
        Assert.Equal(uuid, user.Uuid);
    }

    [Fact]
    public async Task PanelSnapshotBuilder_injects_shadowsocks_users_and_clears_legacy_shadowsocks_user_collection()
    {
        using var harness = new PanelMutationHarness();
        const string nodeId = "node-ss";
        const string userId = "user-ss";

        await harness.MutationService.SaveNodeAsync(
            nodeId,
            new UpsertNodeRequest
            {
                DisplayName = "node-ss",
                Protocol = InboundProtocols.Shadowsocks,
                Config = new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "shadowsocks-tcp",
                            Enabled = true,
                            Protocol = InboundProtocols.Shadowsocks,
                            Transport = InboundTransports.Tcp,
                            TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                            ListenAddress = "0.0.0.0",
                            Port = 8388,
                            Users =
                            [
                                new TrojanUserConfig
                                {
                                    UserId = userId,
                                    Cipher = ShadowsocksCipherTypes.Aes128Gcm,
                                    Password = "legacy-password"
                                }
                            ],
                            ShadowsocksUsers =
                            [
                                new ShadowsocksUserConfig
                                {
                                    UserId = userId,
                                    Cipher = ShadowsocksCipherTypes.Aes128Gcm,
                                    Password = "legacy-password"
                                }
                            ]
                        }
                    ]
                }
            },
            CancellationToken.None);

        await harness.MutationService.SaveUserAsync(
            userId,
            CreateUserRequest([nodeId]) with
            {
                ShadowsocksCipher = ShadowsocksCipherTypes.ChaCha20Poly1305,
                ShadowsocksPassword = "ss-secret"
            },
            CancellationToken.None);

        var snapshotBuilder = new PanelSnapshotBuilder(harness.DatabaseService);
        var result = await snapshotBuilder.TryBuildAsync(nodeId, CancellationToken.None);

        Assert.True(result.Success);
        var inbound = Assert.Single(result.Config.Inbounds);
        var user = Assert.Single(inbound.Users);
        Assert.Equal(InboundProtocols.Shadowsocks, InboundProtocols.Normalize(inbound.Protocol));
        Assert.Equal(userId, user.UserId);
        Assert.Equal(ShadowsocksCipherTypes.ChaCha20Poly1305, user.Cipher);
        Assert.Equal("ss-secret", user.Password);
        Assert.Empty(inbound.ShadowsocksUsers);
    }

    [Fact]
    public async Task SubscriptionCatalogService_builds_manual_vless_endpoints_for_httpupgrade_grpc_and_splithttp()
    {
        using var harness = new PanelMutationHarness();
        const string nodeId = "node-edge";
        const string userId = "user-edge";
        const string uuid = "11111111-1111-1111-1111-111111111111";

        await harness.MutationService.SaveNodeAsync(
            nodeId,
            new UpsertNodeRequest
            {
                DisplayName = "Edge",
                Protocol = InboundProtocols.Vless,
                SubscriptionHost = "edge.example.com",
                SubscriptionSni = "sni.example.com",
                Config = new NodeServiceConfig
                {
                    Inbounds =
                    [
                        new InboundConfig
                        {
                            Tag = "vless-httpupgrade",
                            Enabled = true,
                            Protocol = InboundProtocols.Vless,
                            Transport = InboundTransports.HttpUpgrade,
                            TransportProtocol = RuntimeInternetTransportProtocols.HttpUpgrade,
                            TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                            ListenAddress = "0.0.0.0",
                            Port = 8443,
                            Host = "cdn.example.com",
                            Path = "/upgrade"
                        },
                        new InboundConfig
                        {
                            Tag = "vless-grpc",
                            Enabled = true,
                            Protocol = InboundProtocols.Vless,
                            Transport = InboundTransports.Grpc,
                            TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                            TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                            ListenAddress = "0.0.0.0",
                            Port = 443,
                            GrpcServiceName = "/grpc"
                        },
                        new InboundConfig
                        {
                            Tag = "vless-splithttp",
                            Enabled = true,
                            Protocol = InboundProtocols.Vless,
                            Transport = InboundTransports.SplitHttp,
                            TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                            TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                            ListenAddress = "0.0.0.0",
                            Port = 443,
                            Host = "cdn-split.example.com",
                            Path = "/xhttp"
                        }
                    ]
                }
            },
            CancellationToken.None);

        await harness.MutationService.SaveUserAsync(
            userId,
            CreateUserRequest([nodeId]) with
            {
                V2rayUuid = uuid
            },
            CancellationToken.None);

        var service = new SubscriptionCatalogService(harness.DatabaseService);
        var result = await service.TryBuildByUserIdAsync(userId, CancellationToken.None);

        Assert.True(result.Success, result.Error);
        Assert.Equal(3, result.Catalog.Endpoints.Count);

        var httpUpgrade = Assert.Single(
            result.Catalog.Endpoints,
            static endpoint => string.Equals(endpoint.Transport, InboundTransports.HttpUpgrade, StringComparison.Ordinal));
        var grpc = Assert.Single(
            result.Catalog.Endpoints,
            static endpoint => string.Equals(endpoint.Transport, InboundTransports.Grpc, StringComparison.Ordinal));
        var splitHttp = Assert.Single(
            result.Catalog.Endpoints,
            static endpoint => string.Equals(endpoint.Transport, InboundTransports.SplitHttp, StringComparison.Ordinal));

        Assert.Equal("Edge-httpupgrade", httpUpgrade.Label);
        Assert.Equal("cdn.example.com", httpUpgrade.WsHost);
        Assert.Contains("type=httpupgrade", service.BuildUri(result.Catalog.User, httpUpgrade), StringComparison.Ordinal);

        Assert.Equal("Edge-grpc", grpc.Label);
        Assert.Equal("/grpc", grpc.GrpcServiceName);
        Assert.Contains("type=grpc", service.BuildUri(result.Catalog.User, grpc), StringComparison.Ordinal);
        Assert.Contains("serviceName=%2Fgrpc", service.BuildUri(result.Catalog.User, grpc), StringComparison.Ordinal);

        Assert.Equal("Edge-splithttp", splitHttp.Label);
        Assert.Equal("cdn-split.example.com", splitHttp.WsHost);
        Assert.Contains("type=splithttp", service.BuildUri(result.Catalog.User, splitHttp), StringComparison.Ordinal);
        Assert.Contains("host=cdn-split.example.com", service.BuildUri(result.Catalog.User, splitHttp), StringComparison.Ordinal);
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

    private static async Task InvokeProcessTrafficAsync(NetworkAccountingService service)
    {
        var method = typeof(NetworkAccountingService).GetMethod("ProcessTrafficAsync", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(method);

        var task = method!.Invoke(service, [CancellationToken.None]) as Task;
        Assert.NotNull(task);

        await task!;
    }

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
            NodeConnectionRegistry = new NodeConnectionRegistry();

            var snapshotBuilder = new PanelSnapshotBuilder(DatabaseService);
            var pushService = new ControlPlanePushService(
                snapshotBuilder,
                NodeConnectionRegistry,
                NullLogger<ControlPlanePushService>.Instance);

            MutationService = new PanelMutationService(DatabaseService, pushService, NodeConnectionRegistry, _panelHttpsRuntime);
        }

        public DatabaseService DatabaseService { get; }

        public NodeConnectionRegistry NodeConnectionRegistry { get; }

        public PanelMutationService MutationService { get; }

        public PanelHttpsRuntimeSnapshot GetPanelHttpsSnapshot()
            => _panelHttpsRuntime.GetSnapshot();

        public SslServerAuthenticationOptions CreatePanelHttpsAuthenticationOptions()
            => _panelHttpsRuntime.CreateAuthenticationOptions();

        public PanelQueryService CreateQueryService()
            => new(DatabaseService, new NodeConnectionRegistry(), new PanelCertificateProgressTracker());

        public void MarkPanelHttpsListenerConfigured(int? httpsPort)
            => _panelHttpsRuntime.MarkListenerConfigured(httpsPort);

        public bool ShouldRedirectHttp(PathString requestPath)
            => _panelHttpsRuntime.ShouldRedirectHttp(requestPath);

        public Uri BuildPanelHttpsRedirectUri(HttpRequest request)
            => _panelHttpsRuntime.BuildRedirectUri(request);

        public bool TryBuildPanelHttpsRedirectUri(HttpRequest request, out Uri? redirectUri)
            => _panelHttpsRuntime.TryBuildRedirectUri(request, out redirectUri);

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

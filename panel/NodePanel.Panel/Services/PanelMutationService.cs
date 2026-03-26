using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelMutationService
{
    private readonly ControlPlanePushService _controlPlanePushService;
    private readonly DatabaseService _db;
    private readonly PanelHttpsRuntime _panelHttpsRuntime;

    public PanelMutationService(DatabaseService db, ControlPlanePushService controlPlanePushService, PanelHttpsRuntime panelHttpsRuntime)
    {
        _db = db;
        _controlPlanePushService = controlPlanePushService;
        _panelHttpsRuntime = panelHttpsRuntime;
    }

    public async Task SaveServerGroupAsync(int groupId, string name, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        var existing = await _db.FSql.Select<ServerGroupEntity>().Where(x => x.GroupId == groupId).FirstAsync(cancellationToken);
        var entity = existing ?? new ServerGroupEntity { GroupId = groupId };
        entity.Name = name;
        await _db.FSql.InsertOrUpdate<ServerGroupEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);
    }

    public async Task DeleteServerGroupAsync(int groupId, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) return;
        var usersUsing = await _db.FSql.Select<UserEntity>().Where(u => u.GroupId == groupId).CountAsync(cancellationToken);
        var plansUsing = await _db.FSql.Select<PlanEntity>().Where(p => p.GroupId == groupId).CountAsync(cancellationToken);
        if (usersUsing > 0 || plansUsing > 0)
        {
            throw new InvalidOperationException($"不能删除组 {groupId}，因为有 {usersUsing} 个用户和 {plansUsing} 个套餐正在使用它。");
        }
        await _db.FSql.Delete<ServerGroupEntity>().Where(g => g.GroupId == groupId).ExecuteAffrowsAsync(cancellationToken);
    }

    public async Task<PanelNodeRecord> SaveNodeAsync(string nodeId, UpsertNodeRequest request, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        var existing = await _db.FSql.Select<NodeEntity>().Where(x => x.NodeId == nodeId).FirstAsync(cancellationToken);
        var entity = existing ?? new NodeEntity { NodeId = nodeId };

        entity.DisplayName = request.DisplayName;
        entity.Protocol = request.Protocol;
        entity.TrafficMultiplier = request.TrafficMultiplier;
        entity.Enabled = request.Enabled;
        entity.GroupIds = request.GroupIds;
        entity.SubscriptionHost = request.SubscriptionHost;
        entity.SubscriptionSni = request.SubscriptionSni;
        entity.SubscriptionRegion = request.SubscriptionRegion;
        entity.SubscriptionTags = request.SubscriptionTags;
        entity.SubscriptionAllowInsecure = request.SubscriptionAllowInsecure;
        entity.Config = NormalizeNodeConfig(request.Config);
        entity.DesiredRevision = existing is null ? 1 : NextDesiredRevision(existing.DesiredRevision);
        
        await _db.FSql.InsertOrUpdate<NodeEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);

        await _controlPlanePushService.PushSnapshotsAsync(new[] { nodeId }, cancellationToken).ConfigureAwait(false);
        return entity.ToRecord();
    }

    public async Task<PanelUserRecord> SaveUserAsync(string userId, UpsertUserRequest request, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        var existing = await _db.FSql.Select<UserEntity>().Where(x => x.UserId == userId).FirstAsync(cancellationToken);
        var entity = existing ?? new UserEntity { UserId = userId };
        var originalNodeIds = existing?.NodeIds.ToArray();

        entity.DisplayName = request.DisplayName;
        entity.SubscriptionToken = request.SubscriptionToken;
        entity.TrojanPassword = request.TrojanPassword;
        entity.V2rayUuid = NormalizeUuid(request.V2rayUuid, existing?.V2rayUuid);
        entity.InviteUserId = NodeFormValueCodec.TrimOrEmpty(request.InviteUserId);
        entity.CommissionBalance = request.CommissionBalance;
        entity.CommissionRate = Math.Clamp(request.CommissionRate, 0, 100);
        entity.GroupId = request.GroupId;
        entity.Enabled = request.Enabled;
        entity.BytesPerSecond = request.BytesPerSecond;
        entity.DeviceLimit = Math.Max(0, request.DeviceLimit);
        entity.NodeIds = request.NodeIds;
        entity.PlanName = request.Subscription.PlanName;
        entity.Cycle = string.IsNullOrWhiteSpace(request.Subscription.Cycle)
            ? existing?.Cycle ?? string.Empty
            : request.Subscription.Cycle;
        entity.TransferEnableBytes = request.Subscription.TransferEnableBytes;
        entity.ExpiresAt = request.Subscription.ExpiresAt;
        entity.PurchaseUrl = NodeFormValueCodec.TrimOrEmpty(request.Subscription.PurchaseUrl);
        entity.PortalNotice = request.Subscription.PortalNotice ?? string.Empty;

        await _db.FSql.InsertOrUpdate<UserEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);

        var allNodeIds = await _db.FSql.Select<NodeEntity>().ToListAsync(n => n.NodeId, cancellationToken);
        var affectedNodes = ResolveAffectedNodeIds(
            allNodeIds,
            originalNodeIds,
            entity.NodeIds);

        await IncrementNodeRevisionsAsync(affectedNodes, cancellationToken).ConfigureAwait(false);

        await _controlPlanePushService.PushSnapshotsAsync(affectedNodes, cancellationToken).ConfigureAwait(false);
        return entity.ToRecord();
    }

    public async Task ResetUserTrafficAsync(string userId, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        var entity = await _db.FSql.Select<TrafficRecordEntity>().Where(x => x.UserId == userId).FirstAsync(cancellationToken)
                     ?? new TrafficRecordEntity { UserId = userId };
        
        entity.UploadBytes = 0;
        entity.DownloadBytes = 0;
        entity.LastResetAt = DateTimeOffset.UtcNow;
        
        await _db.FSql.InsertOrUpdate<TrafficRecordEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);
    }

    public async Task SavePlanAsync(string planId, UpsertPlanRequest request, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        var entity = await _db.FSql.Select<PlanEntity>().Where(x => x.PlanId == planId).FirstAsync(cancellationToken)
                     ?? new PlanEntity { PlanId = planId };
        
        entity.Name = request.Name;
        entity.GroupId = request.GroupId;
        entity.TransferEnableBytes = request.TransferEnableBytes;
        entity.MonthPrice = request.MonthPrice;
        entity.QuarterPrice = request.QuarterPrice;
        entity.HalfYearPrice = request.HalfYearPrice;
        entity.YearPrice = request.YearPrice;
        entity.OneTimePrice = request.OneTimePrice;
        entity.ResetPrice = request.ResetPrice;
        
        await _db.FSql.InsertOrUpdate<PlanEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);
    }

    public async Task DeletePlanAsync(string planId, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        await _db.FSql.Delete<PlanEntity>().Where(x => x.PlanId == planId).ExecuteAffrowsAsync(cancellationToken);
    }

    public async Task<PanelOrderRecord> CreateOrderAsync(string userId, string planId, string cycle, decimal amount, int status = 0, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");

        var orderId = Guid.NewGuid().ToString("N");
        var entity = new OrderEntity
        {
            OrderId = orderId,
            UserId = userId,
            PlanId = planId,
            Cycle = cycle,
            TradeNo = $"TR_{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{orderId[..8]}",
            TotalAmount = amount,
            Status = status,
            CreatedAt = DateTimeOffset.UtcNow,
            PaidAt = status == 1 ? DateTimeOffset.UtcNow : null
        };

        await _db.FSql.Insert(entity).ExecuteAffrowsAsync(cancellationToken);
        return entity.ToRecord();
    }

    public async Task<PanelOrderRecord?> CompleteOrderAsync(string orderId, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        var order = await _db.FSql.Select<OrderEntity>().Where(o => o.OrderId == orderId).FirstAsync(cancellationToken);
        if (order is null || order.Status == 1) return order?.ToRecord();

        order.Status = 1;
        order.PaidAt = DateTimeOffset.UtcNow;
        await _db.FSql.InsertOrUpdate<OrderEntity>().SetSource(order).ExecuteAffrowsAsync(cancellationToken);

        // Apply plan to user
        var user = await _db.FSql.Select<UserEntity>().Where(u => u.UserId == order.UserId).FirstAsync(cancellationToken);
        var plan = await _db.FSql.Select<PlanEntity>().Where(p => p.PlanId == order.PlanId).FirstAsync(cancellationToken);
        
        if (user != null && plan != null)
        {
            if (string.Equals(order.Cycle, "reset_price", StringComparison.Ordinal))
            {
                await ResetUserTrafficAsync(user.UserId, cancellationToken).ConfigureAwait(false);
                return order.ToRecord();
            }

            var targetExpiresAt = PlanPresentation.CalculateExpiresAt(order.Cycle, user.ExpiresAt);

            var request = new UpsertUserRequest
            {
                DisplayName = user.DisplayName,
                SubscriptionToken = user.SubscriptionToken,
                TrojanPassword = user.TrojanPassword,
                V2rayUuid = user.V2rayUuid,
                InviteUserId = user.InviteUserId,
                CommissionBalance = user.CommissionBalance,
                CommissionRate = user.CommissionRate,
                GroupId = plan.GroupId,
                Enabled = true,
                BytesPerSecond = user.BytesPerSecond,
                DeviceLimit = user.DeviceLimit,
                NodeIds = user.NodeIds,
                Subscription = new PanelUserSubscriptionProfile
                {
                    PlanName = plan.Name,
                    Cycle = order.Cycle,
                    TransferEnableBytes = plan.TransferEnableBytes,
                    ExpiresAt = targetExpiresAt,
                    PurchaseUrl = user.PurchaseUrl,
                    PortalNotice = user.PortalNotice
                }
            };
            await SaveUserAsync(user.UserId, request, cancellationToken).ConfigureAwait(false);

            if (!string.IsNullOrWhiteSpace(user.InviteUserId) && order.TotalAmount > 0)
            {
                var inviter = await _db.FSql.Select<UserEntity>().Where(u => u.UserId == user.InviteUserId).FirstAsync(cancellationToken);
                if (inviter != null && inviter.CommissionRate > 0)
                {
                    var commission = order.TotalAmount * (inviter.CommissionRate / 100m);
                    if (commission > 0)
                    {
                        inviter.CommissionBalance += commission;
                        await _db.FSql.Update<UserEntity>().Set(u => u.CommissionBalance, inviter.CommissionBalance).Where(u => u.UserId == inviter.UserId).ExecuteAffrowsAsync(cancellationToken);
                        
                        await _db.FSql.Insert(new CommissionLogEntity
                        {
                            LogId = Guid.NewGuid().ToString("N"),
                            InviteUserId = inviter.UserId,
                            OrderId = order.OrderId,
                            TradeAmount = order.TotalAmount,
                            CommissionAmount = commission,
                            CreatedAt = DateTimeOffset.UtcNow
                        }).ExecuteAffrowsAsync(cancellationToken);
                    }
                }
            }
        }

        return order.ToRecord();
    }

    public async Task SaveSettingsAsync(Dictionary<string, string> settings, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");
        
        foreach (var (key, value) in settings)
        {
            var entity = await _db.FSql.Select<SettingEntity>().Where(x => x.Key == key).FirstAsync(cancellationToken)
                         ?? new SettingEntity { Key = key };
            
            entity.Value = value;
            await _db.FSql.InsertOrUpdate<SettingEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);
        }
    }

    public async Task<PanelCertificateRecord> SaveCertificateAsync(string certificateId, UpsertPanelCertificateRequest request, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");

        var existing = await _db.FSql.Select<PanelCertificateEntity>().Where(item => item.CertificateId == certificateId).FirstAsync(cancellationToken);
        var entity = existing ?? new PanelCertificateEntity
        {
            CertificateId = certificateId,
            CreatedAt = DateTimeOffset.UtcNow
        };

        entity.DisplayName = request.DisplayName;
        entity.Enabled = request.Enabled;
        entity.Domain = request.Domain;
        entity.AltNames = request.AltNames;
        entity.Email = request.Email;
        entity.AcmeDirectoryUrl = request.AcmeDirectoryUrl;
        entity.ChallengeType = request.ChallengeType;
        entity.RenewBeforeDays = request.RenewBeforeDays;
        entity.CheckIntervalMinutes = request.CheckIntervalMinutes;
        entity.UseStaging = request.UseStaging;
        entity.PfxPassword = request.PfxPassword;
        entity.DnsProvider = request.DnsProvider;
        entity.DnsZone = request.DnsZone;
        entity.DnsApiToken = request.DnsApiToken;
        entity.DnsAccessKeyId = request.DnsAccessKeyId;
        entity.DnsAccessKeySecret = request.DnsAccessKeySecret;
        entity.DnsHookPresentCommand = request.DnsHookPresentCommand;
        entity.DnsHookPresentArguments = request.DnsHookPresentArguments;
        entity.DnsHookCleanupCommand = request.DnsHookCleanupCommand;
        entity.DnsHookCleanupArguments = request.DnsHookCleanupArguments;
        entity.EnvironmentVariables = request.EnvironmentVariables;
        entity.UpdatedAt = DateTimeOffset.UtcNow;

        await _db.FSql.InsertOrUpdate<PanelCertificateEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);
        return entity.ToRecord();
    }

    public async Task SavePanelHttpsSettingsAsync(PanelHttpsSettingsFormInput form, CancellationToken cancellationToken)
    {
        await SaveSettingsAsync(
                form.ToSettings().ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal),
                cancellationToken)
            .ConfigureAwait(false);
        await _panelHttpsRuntime.RefreshAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>> PushNodesUsingPanelCertificateAsync(string certificateId, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured) return Array.Empty<string>();

        var nodes = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken);
        var affectedNodeIds = nodes
            .Where(node =>
            {
                var certificate = node.Config.Certificate;
                return CertificateModes.Normalize(certificate.Mode) == CertificateModes.PanelDistributed &&
                       string.Equals(certificate.PanelCertificateId, certificateId, StringComparison.Ordinal);
            })
            .Select(static node => node.NodeId)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        await IncrementNodeRevisionsAsync(affectedNodeIds, cancellationToken).ConfigureAwait(false);
        await _controlPlanePushService.PushSnapshotsAsync(affectedNodeIds, cancellationToken).ConfigureAwait(false);
        return affectedNodeIds;
    }

    public Task<bool> RequestCertificateRenewalAsync(string nodeId, string requestedBy, CancellationToken cancellationToken)
        => _controlPlanePushService.RequestCertificateRenewalAsync(nodeId, requestedBy, cancellationToken);

    private async Task IncrementNodeRevisionsAsync(IReadOnlyList<string> nodeIds, CancellationToken cancellationToken)
    {
        foreach (var nodeId in nodeIds)
        {
            var entity = await _db.FSql.Select<NodeEntity>().Where(x => x.NodeId == nodeId).FirstAsync(cancellationToken);
            if (entity is null)
            {
                continue;
            }

            entity.DesiredRevision = NextDesiredRevision(entity.DesiredRevision);
            await _db.FSql.InsertOrUpdate<NodeEntity>().SetSource(entity).ExecuteAffrowsAsync(cancellationToken);
        }
    }

    private static IReadOnlyList<string> ResolveAffectedNodeIds(
        IReadOnlyList<string> allNodeIds,
        IReadOnlyList<string>? originalNodeIds,
        IReadOnlyList<string> updatedNodeIds)
    {
        var normalizedAllNodeIds = NormalizeNodeIds(allNodeIds);
        var normalizedUpdatedNodeIds = NormalizeNodeIds(updatedNodeIds);
        var originalExists = originalNodeIds is not null;
        var normalizedOriginalNodeIds = NormalizeNodeIds(originalNodeIds ?? Array.Empty<string>());

        var originalIsGlobal = originalExists && normalizedOriginalNodeIds.Count == 0;
        var updatedIsGlobal = normalizedUpdatedNodeIds.Count == 0;
        if (originalIsGlobal || updatedIsGlobal)
        {
            return normalizedAllNodeIds;
        }

        return normalizedOriginalNodeIds
            .Concat(normalizedUpdatedNodeIds)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static nodeId => nodeId, StringComparer.Ordinal)
            .ToArray();
    }

    private static int NextDesiredRevision(int currentRevision)
        => currentRevision > 0 ? currentRevision + 1 : 1;

    private static string NormalizeUuid(string? requested, string? current)
    {
        if (Guid.TryParse(requested?.Trim(), out var parsedRequested))
        {
            return parsedRequested.ToString("D");
        }

        if (Guid.TryParse(current?.Trim(), out var parsedCurrent))
        {
            return parsedCurrent.ToString("D");
        }

        return Guid.NewGuid().ToString("D");
    }

    private static IReadOnlyList<string> NormalizeNodeIds(IReadOnlyList<string> nodeIds)
        => nodeIds
            .Where(static nodeId => !string.IsNullOrWhiteSpace(nodeId))
            .Select(static nodeId => nodeId.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static nodeId => nodeId, StringComparer.Ordinal)
            .ToArray();

    private static NodeServiceConfig NormalizeNodeConfig(NodeServiceConfig requested)
    {
        var requestedConfig = NodeServiceConfigInbounds.LiftLegacyTrojanScope(requested);

        return requestedConfig with
        {
            Users = Array.Empty<TrojanUserConfig>(),
            Fallbacks = Array.Empty<TrojanFallbackConfig>()
        };
    }
}

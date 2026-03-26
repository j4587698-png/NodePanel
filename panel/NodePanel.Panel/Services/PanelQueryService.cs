using NodePanel.ControlPlane.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelQueryService
{
    private readonly NodeConnectionRegistry _nodeConnectionRegistry;
    private readonly DatabaseService _db;
    private readonly PanelCertificateProgressTracker _panelCertificateProgressTracker;

    public PanelQueryService(
        DatabaseService db,
        NodeConnectionRegistry nodeConnectionRegistry,
        PanelCertificateProgressTracker panelCertificateProgressTracker)
    {
        _db = db;
        _nodeConnectionRegistry = nodeConnectionRegistry;
        _panelCertificateProgressTracker = panelCertificateProgressTracker;
    }

    public async Task<PanelStateView> BuildStateViewAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return new PanelStateView
        {
            Nodes = Array.Empty<PanelNodeView>(),
            Users = Array.Empty<PanelUserRecord>(),
            Plans = Array.Empty<PanelPlanRecord>(),
            Orders = Array.Empty<PanelOrderRecord>(),
            Settings = new Dictionary<string, string>(),
            TrafficSummaries = new Dictionary<string, PanelUserTrafficSummary>()
        };

        var nodes = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken);
        var users = await _db.FSql.Select<UserEntity>().ToListAsync(cancellationToken);
        var plans = await _db.FSql.Select<PlanEntity>().ToListAsync(cancellationToken);
        var orders = await _db.FSql.Select<OrderEntity>().ToListAsync(cancellationToken);
        var records = await _db.FSql.Select<TrafficRecordEntity>().ToListAsync(cancellationToken);
        var settings = await _db.FSql.Select<SettingEntity>().ToListAsync(cancellationToken);

        var stateNodes = nodes.Select(n => n.ToRecord()).ToArray();
        var stateUsers = users.Select(u => u.ToRecord()).ToArray();
        
        var state = new PanelState
        {
            Nodes = stateNodes,
            Users = stateUsers,
            Plans = plans.Select(p => p.ToRecord()).ToArray(),
            Orders = orders.Select(o => o.ToRecord()).ToArray(),
            TrafficRecords = records.Select(r => r.ToRecord()).ToArray(),
            Settings = settings.Select(s => new PanelSettingRecord { Key = s.Key, Value = s.Value }).ToArray()
        };

        var runtime = _nodeConnectionRegistry.GetAllRuntime();

        return new PanelStateView
        {
            Nodes = state.Nodes
                .Select(node =>
                {
                    var runtimeSnapshot = runtime.TryGetValue(node.NodeId, out var snapshot)
                        ? snapshot
                        : new NodeRuntimeSnapshot();

                    return new PanelNodeView
                    {
                        Definition = node,
                        Runtime = runtimeSnapshot,
                        CanRequestCertificateRenewal = CanRequestCertificateRenewal(node),
                        CertificateAlert = BuildCertificateAlert(node, runtimeSnapshot)
                    };
                })
                .OrderBy(static node => node.Definition.NodeId, StringComparer.Ordinal)
                .ToArray(),
            Users = state.Users
                .OrderBy(static user => user.UserId, StringComparer.Ordinal)
                .ToArray(),
            Plans = state.Plans
                .OrderBy(static plan => plan.PlanId, StringComparer.Ordinal)
                .ToArray(),
            Orders = state.Orders
                .OrderByDescending(static order => order.CreatedAt)
                .ToArray(),
            Settings = state.Settings.ToDictionary(s => s.Key, s => s.Value, StringComparer.Ordinal),
            TrafficSummaries = state.Users.ToDictionary(
                static user => user.UserId,
                user => BuildUserTrafficSummary(user, state, runtime),
                StringComparer.Ordinal)
        };
    }

    public static PanelUserTrafficSummary BuildUserTrafficSummary(PanelUserRecord user, PanelState state, IReadOnlyDictionary<string, NodeRuntimeSnapshot> runtime)
    {
        var record = state.TrafficRecords?.FirstOrDefault(r => string.Equals(r.UserId, user.UserId, StringComparison.Ordinal));
        
        long uploadBytes = record?.UploadBytes ?? 0;
        long downloadBytes = record?.DownloadBytes ?? 0;

        var targetNodeIds = user.NodeIds.Count == 0
            ? state.Nodes.Select(static node => node.NodeId)
            : user.NodeIds;

        foreach (var nodeId in targetNodeIds.Distinct(StringComparer.Ordinal))
        {
            if (!runtime.TryGetValue(nodeId, out var snapshot)) continue;
            var total = snapshot.TrafficTotals.FirstOrDefault(item => string.Equals(item.UserId, user.UserId, StringComparison.Ordinal));
            if (total is null) continue;

            uploadBytes += total.UploadBytes;
            downloadBytes += total.DownloadBytes;
        }

        return new PanelUserTrafficSummary
        {
            UserId = user.UserId,
            UploadBytes = uploadBytes,
            DownloadBytes = downloadBytes
        };
    }

    public async Task<PanelUserTrafficSummary?> BuildUserTrafficSummaryAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;
        var user = await FindUserAsync(userId, cancellationToken);
        if (user is null) return null;

        var stateView = await BuildStateViewAsync(cancellationToken);
        return stateView.TrafficSummaries.GetValueOrDefault(userId);
    }

    public Task<IReadOnlyDictionary<string, string>> GetSettingsAsync(CancellationToken cancellationToken = default)
        => GetSettingsDictionaryAsync(cancellationToken);

    public async Task<PanelNodeRecord?> FindNodeAsync(string nodeId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;
        var entity = await _db.FSql.Select<NodeEntity>().Where(n => n.NodeId == nodeId).FirstAsync(cancellationToken);
        return entity?.ToRecord();
    }

    public async Task<IReadOnlyList<PanelCertificateRecord>> GetCertificatesAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<PanelCertificateRecord>();
        var entities = await _db.FSql.Select<PanelCertificateEntity>().ToListAsync(cancellationToken);
        return entities
            .Select(static entity => entity.ToRecord())
            .OrderBy(static certificate => certificate.CertificateId, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<PanelCertificateRecord?> FindCertificateAsync(string certificateId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;
        var entity = await _db.FSql.Select<PanelCertificateEntity>().Where(item => item.CertificateId == certificateId).FirstAsync(cancellationToken);
        return entity?.ToRecord();
    }

    public async Task<PanelCertificateView?> FindCertificateViewAsync(string certificateId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;

        var normalizedCertificateId = certificateId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedCertificateId))
        {
            return null;
        }

        var certificates = await GetCertificateViewsAsync(cancellationToken).ConfigureAwait(false);
        return certificates.FirstOrDefault(item => string.Equals(item.Definition.CertificateId, normalizedCertificateId, StringComparison.Ordinal));
    }

    public async Task<IReadOnlyList<PanelCertificateView>> GetCertificateViewsAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<PanelCertificateView>();

        var certificates = await _db.FSql.Select<PanelCertificateEntity>().ToListAsync(cancellationToken);
        var nodes = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken);
        var settings = await GetSettingsDictionaryAsync(cancellationToken).ConfigureAwait(false);
        var panelHttpsCertificateId = settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsCertificateId) ?? string.Empty;
        var snapshotTime = DateTimeOffset.UtcNow;

        return certificates
            .Select(entity =>
            {
                var record = entity.ToRecord();
                var boundNodeCount = nodes.Count(node =>
                {
                    var certificate = node.Config.Certificate;
                    return CertificateModes.Normalize(certificate.Mode) == CertificateModes.PanelDistributed &&
                           string.Equals(certificate.PanelCertificateId, record.CertificateId, StringComparison.Ordinal);
                });

                return new PanelCertificateView
                {
                    Definition = record,
                    BoundNodeCount = boundNodeCount,
                    UsedByPanelHttps = string.Equals(panelHttpsCertificateId, record.CertificateId, StringComparison.Ordinal),
                    Progress = _panelCertificateProgressTracker.GetSnapshot(record.CertificateId),
                    SnapshotTime = snapshotTime
                };
            })
            .OrderBy(static item => item.Definition.CertificateId, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<PanelHttpsSettingsFormInput> GetPanelHttpsSettingsAsync(CancellationToken cancellationToken = default)
        => PanelHttpsSettingsFormInput.FromSettings(await GetSettingsDictionaryAsync(cancellationToken).ConfigureAwait(false));

    public async Task<PanelUserRecord?> FindUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;
        var entity = await _db.FSql.Select<UserEntity>().Where(u => u.UserId == userId).FirstAsync(cancellationToken);
        return entity?.ToRecord();
    }

    public async Task<PanelUserRecord?> FindUserByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(email);
        if (string.IsNullOrWhiteSpace(normalizedEmail))
        {
            return null;
        }

        var entity = await _db.FSql.Select<UserEntity>().Where(u => u.Email == normalizedEmail).FirstAsync(cancellationToken);
        return entity?.ToRecord();
    }

    public async Task<PanelUserRecord?> FindUserBySubscriptionTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;
        var entity = await _db.FSql.Select<UserEntity>().Where(u => u.SubscriptionToken == token).FirstAsync(cancellationToken);
        return entity?.ToRecord();
    }

    private static bool CanRequestCertificateRenewal(PanelNodeRecord node)
    {
        var mode = CertificateModes.Normalize(node.Config.Certificate.Mode);
        return mode is CertificateModes.AcmeManaged or CertificateModes.AcmeExternal;
    }

    public async Task<IReadOnlyList<TicketViewModel>> GetTicketsAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<TicketViewModel>();
        var records = await _db.FSql.Select<TicketEntity>().ToListAsync(cancellationToken);
        return records.OrderByDescending(t => t.CreatedAt).Select(r => new TicketViewModel
        {
            TicketId = r.TicketId, UserId = r.UserId, Subject = r.Subject, Level = r.Level, Status = r.Status, CreatedAt = r.CreatedAt
        }).ToArray();
    }
    
    public async Task<IReadOnlyList<ServerGroupViewModel>> GetServerGroupsAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<ServerGroupViewModel>();
        var records = await _db.FSql.Select<ServerGroupEntity>().OrderBy(t => t.GroupId).ToListAsync(cancellationToken);
        return records.Select(r => new ServerGroupViewModel
        {
            GroupId = r.GroupId, Name = r.Name, CreatedAt = r.CreatedAt
        }).ToArray();
    }
    
    public async Task<IReadOnlyList<CommissionLogViewModel>> GetCommissionLogsAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<CommissionLogViewModel>();
        var records = await _db.FSql.Select<CommissionLogEntity>().ToListAsync(cancellationToken);
        return records.OrderByDescending(t => t.CreatedAt).Select(r => new CommissionLogViewModel
        {
            LogId = r.LogId, InviteUserId = r.InviteUserId, OrderId = r.OrderId, TradeAmount = r.TradeAmount, CommissionAmount = r.CommissionAmount, CreatedAt = r.CreatedAt
        }).ToArray();
    }

    public async Task<PortalReferralCenterViewModel> BuildUserReferralCenterAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return new PortalReferralCenterViewModel();

        var normalizedUserId = NodeFormValueCodec.TrimOrEmpty(userId);
        if (string.IsNullOrWhiteSpace(normalizedUserId))
        {
            return new PortalReferralCenterViewModel();
        }

        var user = await _db.FSql.Select<UserEntity>().Where(x => x.UserId == normalizedUserId).FirstAsync(cancellationToken);
        if (user is null)
        {
            return new PortalReferralCenterViewModel();
        }

        var settings = await GetSettingsDictionaryAsync(cancellationToken).ConfigureAwait(false);
        var authSettings = PanelAuthSettings.FromSettings(settings);
        var inviteCodes = await _db.FSql.Select<InviteCodeEntity>().Where(x => x.UserId == normalizedUserId).ToListAsync(cancellationToken);
        var invitees = await _db.FSql.Select<UserEntity>().Where(x => x.InviteUserId == normalizedUserId).ToListAsync(cancellationToken);
        var commissionLogs = await _db.FSql.Select<CommissionLogEntity>().Where(x => x.InviteUserId == normalizedUserId).ToListAsync(cancellationToken);

        var usageByCode = invitees
            .Where(static item => !string.IsNullOrWhiteSpace(item.AppliedInviteCode))
            .GroupBy(static item => item.AppliedInviteCode, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.Count(), StringComparer.Ordinal);

        var lastUsedAtByCode = invitees
            .Where(static item => !string.IsNullOrWhiteSpace(item.AppliedInviteCode))
            .GroupBy(static item => item.AppliedInviteCode, StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group.Max(static item => item.CreatedAt),
                StringComparer.Ordinal);

        var inviteCodeCount = inviteCodes.Count;

        return new PortalReferralCenterViewModel
        {
            InviteOnlyRegistrationEnabled = authSettings.RequireInviteCodeForRegistration,
            MaxInviteCodes = authSettings.MaxInviteCodesPerUser,
            MaxInviteCodesText = authSettings.MaxInviteCodesPerUser > 0 ? authSettings.MaxInviteCodesPerUser.ToString() : "不限",
            RemainingInviteCodesText = authSettings.MaxInviteCodesPerUser > 0
                ? Math.Max(authSettings.MaxInviteCodesPerUser - inviteCodeCount, 0).ToString()
                : "不限",
            CanGenerateInviteCode = authSettings.MaxInviteCodesPerUser <= 0 || inviteCodeCount < authSettings.MaxInviteCodesPerUser,
            InviteCodeCount = inviteCodeCount,
            InvitedUserCount = invitees.Count,
            CommissionBalance = user.CommissionBalance,
            CommissionTotal = commissionLogs.Sum(static item => item.CommissionAmount),
            CommissionRate = Math.Clamp(user.CommissionRate, 0, 100),
            InviteCodes = inviteCodes
                .OrderByDescending(static item => item.CreatedAt)
                .Select(item => new PortalInviteCodeViewModel
                {
                    Code = item.Code,
                    CreatedAtText = FormatPortalDateTime(item.CreatedAt),
                    UsageCount = usageByCode.GetValueOrDefault(item.Code),
                    LastUsedAtText = lastUsedAtByCode.TryGetValue(item.Code, out var lastUsedAt)
                        ? FormatPortalDateTime(lastUsedAt)
                        : "-"
                })
                .ToArray(),
            Invitees = invitees
                .OrderByDescending(static item => item.CreatedAt)
                .Select(item => new PortalInviteeViewModel
                {
                    UserId = item.UserId,
                    DisplayName = string.IsNullOrWhiteSpace(item.DisplayName) ? item.UserId : item.DisplayName.Trim(),
                    Email = item.Email,
                    AppliedInviteCode = string.IsNullOrWhiteSpace(item.AppliedInviteCode) ? "-" : item.AppliedInviteCode,
                    CreatedAtText = FormatPortalDateTime(item.CreatedAt)
                })
                .ToArray(),
            CommissionLogs = commissionLogs
                .OrderByDescending(static item => item.CreatedAt)
                .Select(item => new PortalCommissionLogItemViewModel
                {
                    OrderId = item.OrderId,
                    TradeAmount = item.TradeAmount,
                    CommissionAmount = item.CommissionAmount,
                    CreatedAtText = FormatPortalDateTime(item.CreatedAt)
                })
                .ToArray()
        };
    }

    private static PanelCertificateAlertView BuildCertificateAlert(PanelNodeRecord node, NodeRuntimeSnapshot runtime)
    {
        if (!node.Enabled) return new PanelCertificateAlertView();

        var mode = CertificateModes.Normalize(node.Config.Certificate.Mode);
        var certificate = runtime.LastStatus?.Certificate;
        var requiresCertificate = NodeServiceConfigInbounds.RequiresCertificate(node.Config);

        if (!requiresCertificate && mode == CertificateModes.Disabled)
            return new PanelCertificateAlertView();

        if (!string.IsNullOrWhiteSpace(certificate?.Error))
        {
            return new PanelCertificateAlertView { IsActive = true, Severity = CertificateAlertSeverities.Error, Message = certificate.Error };
        }

        if (requiresCertificate && (certificate is null || !certificate.Available))
        {
            if (runtime.LastSeenAt is null) return new PanelCertificateAlertView();
            return new PanelCertificateAlertView
            {
                IsActive = true,
                Severity = runtime.Connected ? CertificateAlertSeverities.Error : CertificateAlertSeverities.Warning,
                Message = runtime.Connected ? "证书当前不可用，TLS/WSS 监听可能无法正常工作。" : "节点离线且证书状态未知，请确认本地证书和自动续签是否正常。"
            };
        }

        if (certificate?.NotAfter is not DateTimeOffset notAfter) return new PanelCertificateAlertView();
        var remaining = notAfter - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) return new PanelCertificateAlertView { IsActive = true, Severity = CertificateAlertSeverities.Error, Message = $"证书已过期，过期时间 {notAfter.ToLocalTime():yyyy-MM-dd HH:mm:ss}。" };
        if (remaining <= TimeSpan.FromHours(24)) return new PanelCertificateAlertView { IsActive = true, Severity = CertificateAlertSeverities.Error, Message = $"证书将在 {FormatRemaining(remaining)} 后过期，请尽快续签。" };
        if (remaining <= TimeSpan.FromDays(7)) return new PanelCertificateAlertView { IsActive = true, Severity = CertificateAlertSeverities.Warning, Message = $"证书将在 {FormatRemaining(remaining)} 后过期。" };
        
        return new PanelCertificateAlertView();
    }

    private static string FormatRemaining(TimeSpan remaining)
    {
        if (remaining.TotalDays >= 1) return $"{Math.Ceiling(remaining.TotalDays)} 天";
        if (remaining.TotalHours >= 1) return $"{Math.Ceiling(remaining.TotalHours)} 小时";
        return $"{Math.Max(1, Math.Ceiling(remaining.TotalMinutes))} 分钟";
    }
    private static string FormatPortalDateTime(DateTimeOffset value)
        => value.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    private async Task<IReadOnlyDictionary<string, string>> GetSettingsDictionaryAsync(CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured)
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        var settings = await _db.FSql.Select<SettingEntity>().ToListAsync(cancellationToken);
        return settings.ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);
    }
}

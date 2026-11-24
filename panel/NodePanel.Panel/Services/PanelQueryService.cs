using NodePanel.ControlPlane.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelQueryService
{
    private static readonly TimeSpan SettingsCacheDuration = TimeSpan.FromSeconds(5);
    private static readonly IReadOnlyDictionary<string, string> EmptySettings =
        new Dictionary<string, string>(StringComparer.Ordinal);

    private readonly NodeConnectionRegistry _nodeConnectionRegistry;
    private readonly DatabaseService _db;
    private readonly PanelCertificateProgressTracker _panelCertificateProgressTracker;
    private readonly object _settingsCacheSync = new();
    private IReadOnlyDictionary<string, string>? _settingsCache;
    private DateTimeOffset _settingsCacheExpiresAt;

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
            TrafficSummaries = new Dictionary<string, PanelUserTrafficSummary>(),
            ScopedTrafficRecordsByUser = new Dictionary<string, IReadOnlyList<PanelScopedTrafficRecord>>()
        };

        var nodesTask = _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken);
        var usersTask = _db.FSql.Select<UserEntity>().ToListAsync(cancellationToken);
        var plansTask = _db.FSql.Select<PlanEntity>().ToListAsync(cancellationToken);
        var ordersTask = _db.FSql.Select<OrderEntity>().ToListAsync(cancellationToken);
        var recordsTask = _db.FSql.Select<TrafficRecordEntity>().ToListAsync(cancellationToken);
        var scopedRecordsTask = _db.FSql.Select<ScopedTrafficRecordEntity>().ToListAsync(cancellationToken);

        await Task.WhenAll(nodesTask, usersTask, plansTask, ordersTask, recordsTask, scopedRecordsTask)
            .ConfigureAwait(false);

        var nodes = await nodesTask.ConfigureAwait(false);
        var users = await usersTask.ConfigureAwait(false);
        var plans = await plansTask.ConfigureAwait(false);
        var orders = await ordersTask.ConfigureAwait(false);
        var records = await recordsTask.ConfigureAwait(false);
        var scopedRecords = await scopedRecordsTask.ConfigureAwait(false);
        var settings = await GetSettingsDictionaryAsync(cancellationToken).ConfigureAwait(false);

        var stateNodes = nodes.Select(n => n.ToRecord()).ToArray();
        var stateUsers = users.Select(u => u.ToRecord()).ToArray();
        
        var state = new PanelState
        {
            Nodes = stateNodes,
            Users = stateUsers,
            Plans = plans.Select(p => p.ToRecord()).ToArray(),
            Orders = orders.Select(o => o.ToRecord()).ToArray(),
            TrafficRecords = records.Select(r => r.ToRecord()).ToArray(),
            ScopedTrafficRecords = scopedRecords
                .Select(static record => record.ToRecord())
                .OrderBy(static record => record.UserId, StringComparer.Ordinal)
                .ThenBy(static record => record.RuntimeKey, StringComparer.Ordinal)
                .ToArray()
        };

        var runtime = _nodeConnectionRegistry.GetAllRuntime();
        var scopedTrafficRecordsByUser = BuildScopedTrafficRecordsByUser(state);
        var trafficRecordsByUser = BuildTrafficRecordsByUser(state);

        return new PanelStateView
        {
            Nodes = state.Nodes
                .OrderBy(static node => node.NodeId, StringComparer.Ordinal)
                .Select(node => BuildNodeView(node, runtime))
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
            Settings = settings,
            TrafficSummaries = state.Users.ToDictionary(
                static user => user.UserId,
                user => BuildUserTrafficSummary(user, trafficRecordsByUser.GetValueOrDefault(user.UserId)),
                StringComparer.Ordinal),
            ScopedTrafficRecordsByUser = scopedTrafficRecordsByUser
        };
    }

    public static PanelUserTrafficSummary BuildUserTrafficSummary(PanelUserRecord user, PanelUserTrafficRecord? record)
    {
        return new PanelUserTrafficSummary
        {
            UserId = user.UserId,
            UploadBytes = record?.UploadBytes ?? 0,
            DownloadBytes = record?.DownloadBytes ?? 0
        };
    }

    private static IReadOnlyDictionary<string, PanelUserTrafficRecord> BuildTrafficRecordsByUser(PanelState state)
    {
        var recordsByUser = new Dictionary<string, PanelUserTrafficRecord>(state.TrafficRecords.Count, StringComparer.Ordinal);
        foreach (var record in state.TrafficRecords)
        {
            recordsByUser[record.UserId] = record;
        }

        return recordsByUser;
    }

    public async Task<PanelUserTrafficSummary?> BuildUserTrafficSummaryAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;

        var normalizedUserId = NodeFormValueCodec.TrimOrEmpty(userId);
        if (string.IsNullOrWhiteSpace(normalizedUserId)) return null;

        var user = await FindUserAsync(normalizedUserId, cancellationToken).ConfigureAwait(false);
        if (user is null) return null;

        var record = await _db.FSql.Select<TrafficRecordEntity>()
            .Where(item => item.UserId == normalizedUserId)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);

        return BuildUserTrafficSummary(user, record?.ToRecord());
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<PanelScopedTrafficRecord>> BuildScopedTrafficRecordsByUser(PanelState state)
    {
        var scopedRecordsByUser = state.ScopedTrafficRecords
            .GroupBy(static record => record.UserId, StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => (IReadOnlyList<PanelScopedTrafficRecord>)group
                    .OrderBy(static record => record.RuntimeKey, StringComparer.Ordinal)
                    .ToArray(),
                StringComparer.Ordinal);

        return state.Users.ToDictionary(
            static user => user.UserId,
            user => scopedRecordsByUser.GetValueOrDefault(user.UserId) ?? Array.Empty<PanelScopedTrafficRecord>(),
            StringComparer.Ordinal);
    }

    public Task<IReadOnlyDictionary<string, string>> GetSettingsAsync(CancellationToken cancellationToken = default)
        => GetSettingsDictionaryAsync(cancellationToken);

    public async Task<IReadOnlyList<PanelPlanRecord>> GetPlansAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<PanelPlanRecord>();

        var entities = await _db.FSql.Select<PlanEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        return entities
            .Select(static entity => entity.ToRecord())
            .OrderBy(static plan => plan.PlanId, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<long> CountUsersAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return 0;
        return await _db.FSql.Select<UserEntity>().CountAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<long> CountPlansAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return 0;
        return await _db.FSql.Select<PlanEntity>().CountAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PanelNodeView>> GetNodeViewsAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<PanelNodeView>();

        var entities = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        var runtime = _nodeConnectionRegistry.GetAllRuntime();

        return entities
            .Select(static entity => entity.ToRecord())
            .OrderBy(static node => node.NodeId, StringComparer.Ordinal)
            .Select(node => BuildNodeView(node, runtime))
            .ToArray();
    }

    public async Task<(IReadOnlyList<PanelUserRecord> Users, IReadOnlyDictionary<string, PanelUserTrafficSummary> TrafficSummaries, long TotalCount)>
        GetUsersWithTrafficAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured)
        {
            return (Array.Empty<PanelUserRecord>(), new Dictionary<string, PanelUserTrafficSummary>(), 0);
        }

        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);

        var countTask = _db.FSql.Select<UserEntity>().CountAsync(cancellationToken);
        var usersTask = _db.FSql.Select<UserEntity>()
            .OrderBy(static user => user.UserId)
            .Page(page, pageSize)
            .ToListAsync(cancellationToken);
        await Task.WhenAll(countTask, usersTask).ConfigureAwait(false);

        var users = (await usersTask.ConfigureAwait(false))
            .Select(static entity => entity.ToRecord())
            .ToArray();

        Dictionary<string, PanelUserTrafficRecord> trafficByUser;
        if (users.Length == 0)
        {
            trafficByUser = new Dictionary<string, PanelUserTrafficRecord>(StringComparer.Ordinal);
        }
        else
        {
            var userIds = users.Select(static user => user.UserId).ToArray();
            var records = await _db.FSql.Select<TrafficRecordEntity>()
                .Where(item => userIds.Contains(item.UserId))
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
            trafficByUser = records
                .Select(static entity => entity.ToRecord())
                .ToDictionary(static record => record.UserId, StringComparer.Ordinal);
        }

        return (users, users.ToDictionary(
            static user => user.UserId,
            user => BuildUserTrafficSummary(user, trafficByUser.GetValueOrDefault(user.UserId)),
            StringComparer.Ordinal), await countTask.ConfigureAwait(false));
    }

    public async Task<IReadOnlyList<UserActivitySummary>> GetUsersActivityAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Database is not configured.");
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);
        var usersTask = _db.FSql.Select<UserEntity>().OrderBy(user => user.UserId)
            .Page(page, pageSize).ToListAsync(cancellationToken);
        var nodesTask = _db.FSql.Select<NodeEntity>().ToListAsync(node => node.NodeId, cancellationToken);
        await Task.WhenAll(usersTask, nodesTask).ConfigureAwait(false);
        return UserActivityAggregator.Aggregate(
            (await usersTask.ConfigureAwait(false)).Select(user => user.ToRecord()).ToArray(),
            await nodesTask.ConfigureAwait(false),
            _nodeConnectionRegistry.GetAllRuntime(), DateTimeOffset.UtcNow);
    }

    public async Task<(IReadOnlyList<PanelOrderRecord> Orders, IReadOnlyList<PanelUserRecord> Users, IReadOnlyList<PanelPlanRecord> Plans, IReadOnlyDictionary<string, string> Settings, long TotalCount)>
        GetOrdersPageDataAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured)
        {
            return (Array.Empty<PanelOrderRecord>(), Array.Empty<PanelUserRecord>(), Array.Empty<PanelPlanRecord>(), EmptySettings, 0);
        }

        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);

        var countTask = _db.FSql.Select<OrderEntity>().CountAsync(cancellationToken);
        var settingsTask = GetSettingsAsync(cancellationToken);
        var hasLegacyDates = await _db.FSql.Select<OrderEntity>()
            .Where(order => order.CreatedAtUnixMilliseconds == null).AnyAsync(cancellationToken).ConfigureAwait(false);
        var ordersTask = hasLegacyDates
            ? GetLegacyOrdersPageAsync(page, pageSize, cancellationToken)
            : _db.FSql.Select<OrderEntity>()
                .OrderByDescending(static order => order.CreatedAtUnixMilliseconds)
                .OrderBy(static order => order.OrderId)
                .Page(page, pageSize)
                .ToListAsync(cancellationToken);
        await Task.WhenAll(countTask, ordersTask, settingsTask).ConfigureAwait(false);

        var orders = (await ordersTask.ConfigureAwait(false))
            .Select(static entity => entity.ToRecord())
            .ToArray();

        // Only load the users and plans referenced by this page instead of the whole tables.
        var userIds = orders
            .Select(static order => order.UserId)
            .Where(static userId => !string.IsNullOrWhiteSpace(userId))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var planIds = orders
            .Select(static order => order.PlanId)
            .Where(static planId => !string.IsNullOrWhiteSpace(planId))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Task<List<UserEntity>> usersTask = userIds.Length == 0
            ? Task.FromResult(new List<UserEntity>())
            : _db.FSql.Select<UserEntity>()
                .Where(item => userIds.Contains(item.UserId))
                .ToListAsync(cancellationToken);
        Task<List<PlanEntity>> plansTask = planIds.Length == 0
            ? Task.FromResult(new List<PlanEntity>())
            : _db.FSql.Select<PlanEntity>()
                .Where(item => planIds.Contains(item.PlanId))
                .ToListAsync(cancellationToken);
        await Task.WhenAll(usersTask, plansTask).ConfigureAwait(false);

        return (
            orders,
            (await usersTask.ConfigureAwait(false))
                .Select(static entity => entity.ToRecord())
                .OrderBy(static user => user.UserId, StringComparer.Ordinal)
                .ToArray(),
            (await plansTask.ConfigureAwait(false))
                .Select(static entity => entity.ToRecord())
                .OrderBy(static plan => plan.PlanId, StringComparer.Ordinal)
                .ToArray(),
            await settingsTask.ConfigureAwait(false),
            await countTask.ConfigureAwait(false));
    }

    private async Task<List<OrderEntity>> GetLegacyOrdersPageAsync(int page, int pageSize, CancellationToken cancellationToken)
    {
        var records = await _db.FSql.Select<OrderEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        return records.OrderByDescending(order => order.CreatedAt).ThenBy(order => order.OrderId, StringComparer.Ordinal)
            .Skip((int)Math.Min(int.MaxValue, (long)(page - 1) * pageSize)).Take(pageSize).ToList();
    }

    public async Task<PanelPlanRecord?> FindPlanAsync(string planId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;

        var normalizedPlanId = NodeFormValueCodec.TrimOrEmpty(planId);
        if (string.IsNullOrWhiteSpace(normalizedPlanId))
        {
            return null;
        }

        var entity = await _db.FSql.Select<PlanEntity>()
            .Where(item => item.PlanId == normalizedPlanId)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);
        return entity?.ToRecord();
    }

    public async Task<IReadOnlyList<PanelNodeRecord>> GetNodesAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<PanelNodeRecord>();

        var entities = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        return entities
            .Select(static entity => entity.ToRecord())
            .OrderBy(static node => node.NodeId, StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<IReadOnlyList<PanelOrderRecord>> GetOrdersForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        var normalizedUserId = NodeFormValueCodec.TrimOrEmpty(userId);
        if (!_db.IsConfigured || string.IsNullOrWhiteSpace(normalizedUserId)) return Array.Empty<PanelOrderRecord>();

        var entities = await _db.FSql.Select<OrderEntity>()
            .Where(item => item.UserId == normalizedUserId)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return entities
            .Select(static entity => entity.ToRecord())
            .OrderByDescending(static order => order.CreatedAt)
            .ToArray();
    }

    public async Task<PanelNodeRecord?> FindNodeAsync(string nodeId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;
        var entity = await _db.FSql.Select<NodeEntity>().Where(n => n.NodeId == nodeId).FirstAsync(cancellationToken);
        return entity?.ToRecord();
    }

    public async Task<PanelNodeView?> FindNodeViewAsync(string nodeId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return null;

        var normalizedNodeId = NodeFormValueCodec.TrimOrEmpty(nodeId);
        if (string.IsNullOrWhiteSpace(normalizedNodeId)) return null;

        var entity = await _db.FSql.Select<NodeEntity>()
            .Where(n => n.NodeId == normalizedNodeId)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);
        if (entity is null) return null;

        var node = entity.ToRecord();
        return BuildNodeView(node, _nodeConnectionRegistry.GetRuntime(node.NodeId));
    }

    private static PanelNodeView BuildNodeView(PanelNodeRecord node, IReadOnlyDictionary<string, NodeRuntimeSnapshot> runtime)
    {
        var runtimeSnapshot = runtime.TryGetValue(node.NodeId, out var snapshot)
            ? snapshot
            : new NodeRuntimeSnapshot();

        return BuildNodeView(node, runtimeSnapshot);
    }

    private static PanelNodeView BuildNodeView(PanelNodeRecord node, NodeRuntimeSnapshot runtimeSnapshot)
    {
        return new PanelNodeView
        {
            Definition = node,
            Runtime = runtimeSnapshot,
            CanRequestCertificateRenewal = CanRequestCertificateRenewal(node),
            CertificateAlert = BuildCertificateAlert(node, runtimeSnapshot)
        };
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

        var entity = await _db.FSql.Select<PanelCertificateEntity>()
            .Where(item => item.CertificateId == normalizedCertificateId)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);
        if (entity is null)
        {
            return null;
        }

        var nodes = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        var settings = await GetSettingsDictionaryAsync(cancellationToken).ConfigureAwait(false);
        var panelHttpsCertificateId = settings.GetValueOrDefault(PanelSettingKeys.PanelHttpsCertificateId) ?? string.Empty;

        return BuildCertificateView(entity.ToRecord(), nodes, panelHttpsCertificateId, DateTimeOffset.UtcNow);
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
            .Select(entity => BuildCertificateView(entity.ToRecord(), nodes, panelHttpsCertificateId, snapshotTime))
            .OrderBy(static item => item.Definition.CertificateId, StringComparer.Ordinal)
            .ToArray();
    }

    private PanelCertificateView BuildCertificateView(
        PanelCertificateRecord record,
        IReadOnlyList<NodeEntity> nodes,
        string panelHttpsCertificateId,
        DateTimeOffset snapshotTime)
    {
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

    public async Task<PagedListViewModel<TicketViewModel>> GetTicketsAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);
        if (!_db.IsConfigured) return new() { Items = Array.Empty<TicketViewModel>(), Page = page, PageSize = pageSize };
        var countTask = _db.FSql.Select<TicketEntity>().CountAsync(cancellationToken);
        var hasLegacyDates = await _db.FSql.Select<TicketEntity>()
            .Where(item => item.CreatedAtUnixMilliseconds == null).AnyAsync(cancellationToken).ConfigureAwait(false);
        var recordsTask = hasLegacyDates
            ? GetLegacyTicketsPageAsync(page, pageSize, cancellationToken)
            : _db.FSql.Select<TicketEntity>()
                .OrderByDescending(t => t.CreatedAtUnixMilliseconds).OrderBy(t => t.TicketId)
                .Page(page, pageSize).ToListAsync(cancellationToken);
        await Task.WhenAll(countTask, recordsTask).ConfigureAwait(false);
        return new() { Page = page, PageSize = pageSize, TotalCount = await countTask.ConfigureAwait(false),
            Items = (await recordsTask.ConfigureAwait(false)).Select(r => new TicketViewModel
        {
            TicketId = r.TicketId, UserId = r.UserId, Subject = r.Subject, Level = r.Level, Status = r.Status, CreatedAt = r.CreatedAt
        }).ToArray() };
    }

    private async Task<List<TicketEntity>> GetLegacyTicketsPageAsync(int page, int pageSize, CancellationToken cancellationToken)
    {
        var records = await _db.FSql.Select<TicketEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        return records.OrderByDescending(ticket => ticket.CreatedAt).ThenBy(ticket => ticket.TicketId, StringComparer.Ordinal)
            .Skip((int)Math.Min(int.MaxValue, (long)(page - 1) * pageSize)).Take(pageSize).ToList();
    }

    public async Task<IReadOnlyList<ServerGroupViewModel>> GetNodeGroupsAsync(IReadOnlyList<int> groupIds, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured || groupIds.Count == 0) return Array.Empty<ServerGroupViewModel>();
        var ids = groupIds.ToArray();
        var records = await _db.FSql.Select<ServerGroupEntity>()
            .Where(group => ids.Contains(group.GroupId))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return records.Select(group => new ServerGroupViewModel { GroupId = group.GroupId, Name = group.Name }).ToArray();
    }
    
    public async Task<IReadOnlyList<ServerGroupViewModel>> GetServerGroupsAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return Array.Empty<ServerGroupViewModel>();
        var records = await _db.FSql.Select<ServerGroupEntity>().OrderBy(t => t.GroupId).ToListAsync(cancellationToken);
        var nodes = await _db.FSql.Select<NodeEntity>().ToListAsync(cancellationToken);

        // GroupIds parses JSON on every access, so read it once per node.
        var nodeCountByGroup = new Dictionary<int, int>();
        foreach (var node in nodes)
        {
            foreach (var groupId in node.GroupIds.Distinct())
            {
                nodeCountByGroup[groupId] = nodeCountByGroup.GetValueOrDefault(groupId) + 1;
            }
        }

        return records.Select(r => new ServerGroupViewModel
        {
            GroupId = r.GroupId,
            Name = r.Name,
            CreatedAt = r.CreatedAt,
            NodeCount = nodeCountByGroup.GetValueOrDefault(r.GroupId)
        }).ToArray();
    }
    
    public async Task<PagedListViewModel<CommissionLogViewModel>> GetCommissionLogsAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);
        if (!_db.IsConfigured) return new() { Items = Array.Empty<CommissionLogViewModel>(), Page = page, PageSize = pageSize };
        var countTask = _db.FSql.Select<CommissionLogEntity>().CountAsync(cancellationToken);
        var hasLegacyDates = await _db.FSql.Select<CommissionLogEntity>()
            .Where(item => item.CreatedAtUnixMilliseconds == null).AnyAsync(cancellationToken).ConfigureAwait(false);
        var recordsTask = hasLegacyDates
            ? GetLegacyCommissionsPageAsync(page, pageSize, cancellationToken)
            : _db.FSql.Select<CommissionLogEntity>()
                .OrderByDescending(t => t.CreatedAtUnixMilliseconds).OrderBy(t => t.LogId)
                .Page(page, pageSize).ToListAsync(cancellationToken);
        await Task.WhenAll(countTask, recordsTask).ConfigureAwait(false);
        return new() { Page = page, PageSize = pageSize, TotalCount = await countTask.ConfigureAwait(false),
            Items = (await recordsTask.ConfigureAwait(false)).Select(r => new CommissionLogViewModel
        {
            LogId = r.LogId, InviteUserId = r.InviteUserId, OrderId = r.OrderId, TradeAmount = r.TradeAmount, CommissionAmount = r.CommissionAmount, CreatedAt = r.CreatedAt
        }).ToArray() };
    }

    private async Task<List<CommissionLogEntity>> GetLegacyCommissionsPageAsync(int page, int pageSize, CancellationToken cancellationToken)
    {
        var records = await _db.FSql.Select<CommissionLogEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        return records.OrderByDescending(log => log.CreatedAt).ThenBy(log => log.LogId, StringComparer.Ordinal)
            .Skip((int)Math.Min(int.MaxValue, (long)(page - 1) * pageSize)).Take(pageSize).ToList();
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

        return await BuildUserReferralCenterAsync(user.ToRecord(), cancellationToken).ConfigureAwait(false);
    }

    public async Task<PortalReferralCenterViewModel> BuildUserReferralCenterAsync(PanelUserRecord user, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return new PortalReferralCenterViewModel();

        var normalizedUserId = NodeFormValueCodec.TrimOrEmpty(user.UserId);
        if (string.IsNullOrWhiteSpace(normalizedUserId))
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

    public void InvalidateSettingsCache()
    {
        lock (_settingsCacheSync)
        {
            _settingsCache = null;
            _settingsCacheExpiresAt = default;
        }
    }

    private async Task<IReadOnlyDictionary<string, string>> GetSettingsDictionaryAsync(CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured)
        {
            return EmptySettings;
        }

        var now = DateTimeOffset.UtcNow;
        lock (_settingsCacheSync)
        {
            if (_settingsCache is not null && now < _settingsCacheExpiresAt)
            {
                return _settingsCache;
            }
        }

        var settings = await _db.FSql.Select<SettingEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        var dictionary = settings.ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal);

        lock (_settingsCacheSync)
        {
            _settingsCache = dictionary;
            _settingsCacheExpiresAt = DateTimeOffset.UtcNow + SettingsCacheDuration;
        }

        return dictionary;
    }
}

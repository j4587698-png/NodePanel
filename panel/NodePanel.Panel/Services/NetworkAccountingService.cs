using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;
using System.Collections.Concurrent;

namespace NodePanel.Panel.Services;

public sealed class NetworkAccountingService : BackgroundService
{
    private readonly DatabaseService _db;
    private readonly PanelMutationService _panelMutationService;
    private readonly ILogger<NetworkAccountingService> _logger;
    private readonly ConcurrentQueue<(string NodeId, UserTrafficDelta Delta)> _trafficQueue = new();

    public NetworkAccountingService(DatabaseService db, PanelMutationService panelMutationService, ILogger<NetworkAccountingService> logger)
    {
        _db = db;
        _panelMutationService = panelMutationService;
        _logger = logger;
    }

    public void EnqueueTrafficDelta(string nodeId, IReadOnlyList<UserTrafficDelta> deltas)
    {
        foreach (var d in deltas)
        {
            _trafficQueue.Enqueue((nodeId, d));
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            
            try
            {
                if (_db.IsConfigured)
                {
                    await ProcessTrafficAsync(stoppingToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing traffic accounting.");
            }
        }
    }

    private async Task ProcessTrafficAsync(CancellationToken cancellationToken)
    {
        var nodeMultipliers = await _db.FSql.Select<NodeEntity>().ToDictionaryAsync(n => n.NodeId, n => n.TrafficMultiplier, cancellationToken);

        var aggregatedUsers = new Dictionary<string, TrafficAggregate>(StringComparer.Ordinal);
        var aggregatedScoped = new Dictionary<string, ScopedTrafficAggregate>(StringComparer.Ordinal);
        while (_trafficQueue.TryDequeue(out var tuple))
        {
            var multiplier = nodeMultipliers.TryGetValue(tuple.NodeId, out var m) ? m : 1.0m;
            var scope = ResolveTrafficScope(tuple.Delta);
            if (scope.UserId.Length == 0)
            {
                continue;
            }

            var up = ScaleTraffic(tuple.Delta.UploadBytes, multiplier);
            var down = ScaleTraffic(tuple.Delta.DownloadBytes, multiplier);

            AddUserTraffic(aggregatedUsers, scope.UserId, up, down);
            if (scope.Protocol.Length > 0 && scope.InboundTag.Length > 0)
            {
                AddScopedTraffic(aggregatedScoped, scope, up, down);
            }
        }

        if (aggregatedUsers.Count > 0)
        {
            foreach (var aggregate in aggregatedUsers.Values)
            {
                var record = await _db.FSql.Select<TrafficRecordEntity>().Where(t => t.UserId == aggregate.UserId).FirstAsync(cancellationToken)
                             ?? new TrafficRecordEntity { UserId = aggregate.UserId, UploadBytes = 0, DownloadBytes = 0 };
                record.UploadBytes += aggregate.UploadBytes;
                record.DownloadBytes += aggregate.DownloadBytes;
                await _db.FSql.InsertOrUpdate<TrafficRecordEntity>().SetSource(record).ExecuteAffrowsAsync(cancellationToken);
            }
        }

        if (aggregatedScoped.Count > 0)
        {
            foreach (var aggregate in aggregatedScoped.Values)
            {
                var record = await _db.FSql.Select<ScopedTrafficRecordEntity>()
                    .Where(t => t.UserId == aggregate.UserId &&
                                t.Protocol == aggregate.Protocol &&
                                t.InboundTag == aggregate.InboundTag)
                    .FirstAsync(cancellationToken)
                             ?? new ScopedTrafficRecordEntity
                             {
                                 UserId = aggregate.UserId,
                                 Protocol = aggregate.Protocol,
                                 InboundTag = aggregate.InboundTag,
                                 UploadBytes = 0,
                                 DownloadBytes = 0
                             };
                record.UserId = aggregate.UserId;
                record.Protocol = aggregate.Protocol;
                record.InboundTag = aggregate.InboundTag;
                record.UploadBytes += aggregate.UploadBytes;
                record.DownloadBytes += aggregate.DownloadBytes;
                await _db.FSql.InsertOrUpdate<ScopedTrafficRecordEntity>().SetSource(record).ExecuteAffrowsAsync(cancellationToken);
            }
        }

        // Evaluate limits
        var users = await _db.FSql.Select<UserEntity>().ToListAsync(cancellationToken);
        var tRecords = await _db.FSql.Select<TrafficRecordEntity>().ToListAsync(cancellationToken);
        
        foreach (var userEntity in users)
        {
            if (!userEntity.Enabled) continue;

            var tRecord = tRecords.FirstOrDefault(t => t.UserId == userEntity.UserId);

            var totalUsed = tRecord != null ? tRecord.UploadBytes + tRecord.DownloadBytes : 0;
            bool shouldDisable = false;
            
            // Check Data limits
            if (userEntity.TransferEnableBytes > 0 && totalUsed >= userEntity.TransferEnableBytes)
            {
                shouldDisable = true;
                _logger.LogInformation("Disabling user {UserId} due to traffic limit.", userEntity.UserId);
            }
            
            // Check Expiry
            if (userEntity.ExpiresAt.HasValue && DateTimeOffset.UtcNow >= userEntity.ExpiresAt.Value)
            {
                shouldDisable = true;
                _logger.LogInformation("Disabling user {UserId} due to expiration.", userEntity.UserId);
            }

            if (shouldDisable)
            {
                userEntity.Enabled = false;
                await _db.FSql.InsertOrUpdate<UserEntity>().SetSource(userEntity).ExecuteAffrowsAsync(cancellationToken);
                
                // Inform nodes that user is disabled
                var allNodes = await _db.FSql.Select<NodeEntity>().ToListAsync(n => n.NodeId, cancellationToken);
                var affectedNodes = userEntity.NodeIds.Count == 0 ? allNodes : userEntity.NodeIds;
                
                // We shouldn't inject ControlPlanePushService here easily without circular dependency? Let's check. Wait... I can just use DI wrapper in mutate.
                // Actually, I can just use MutateService's SaveUser which fires everything, but it takes UpsertUserRequest.
                // It's easy:
                var record = userEntity.ToRecord();
                var req = new UpsertUserRequest
                {
                    Email = record.Email,
                    DisplayName = record.DisplayName,
                    SubscriptionToken = record.SubscriptionToken,
                    TrojanPassword = record.TrojanPassword,
                    V2rayUuid = record.V2rayUuid,
                    ShadowsocksCipher = record.ShadowsocksCipher,
                    ShadowsocksPassword = record.ShadowsocksPassword,
                    InviteUserId = record.InviteUserId,
                    CommissionBalance = record.CommissionBalance,
                    CommissionRate = record.CommissionRate,
                    GroupId = record.GroupId,
                    Enabled = false,
                    BytesPerSecond = record.BytesPerSecond,
                    DeviceLimit = record.DeviceLimit,
                    Subscription = record.Subscription,
                    NodeIds = record.NodeIds
                };
                await _panelMutationService.SaveUserAsync(userEntity.UserId, req, cancellationToken);
            }
        }
    }

    private static void AddUserTraffic(
        IDictionary<string, TrafficAggregate> aggregatedUsers,
        string userId,
        long uploadBytes,
        long downloadBytes)
    {
        if (aggregatedUsers.TryGetValue(userId, out var existing))
        {
            aggregatedUsers[userId] = existing with
            {
                UploadBytes = existing.UploadBytes + uploadBytes,
                DownloadBytes = existing.DownloadBytes + downloadBytes
            };
            return;
        }

        aggregatedUsers[userId] = new TrafficAggregate(userId, uploadBytes, downloadBytes);
    }

    private static void AddScopedTraffic(
        IDictionary<string, ScopedTrafficAggregate> aggregatedScoped,
        TrafficScope scope,
        long uploadBytes,
        long downloadBytes)
    {
        if (aggregatedScoped.TryGetValue(scope.RuntimeKey, out var existing))
        {
            aggregatedScoped[scope.RuntimeKey] = existing with
            {
                UploadBytes = existing.UploadBytes + uploadBytes,
                DownloadBytes = existing.DownloadBytes + downloadBytes
            };
            return;
        }

        aggregatedScoped[scope.RuntimeKey] = new ScopedTrafficAggregate(
            scope.UserId,
            scope.Protocol,
            scope.InboundTag,
            uploadBytes,
            downloadBytes);
    }

    private static long ScaleTraffic(long value, decimal multiplier)
        => (long)(value * multiplier);

    private static TrafficScope ResolveTrafficScope(UserTrafficDelta delta)
    {
        var normalizedUserId = string.IsNullOrWhiteSpace(delta.UserId) ? string.Empty : delta.UserId.Trim();
        var normalizedProtocol = string.IsNullOrWhiteSpace(delta.Protocol) ? string.Empty : delta.Protocol.Trim().ToLowerInvariant();
        var normalizedInboundTag = string.IsNullOrWhiteSpace(delta.InboundTag) ? string.Empty : delta.InboundTag.Trim();
        var normalizedRuntimeKey = string.IsNullOrWhiteSpace(delta.RuntimeKey) ? string.Empty : delta.RuntimeKey.Trim();
        var computedRuntimeKey = RuntimeUserKeys.Create(normalizedProtocol, normalizedInboundTag, normalizedUserId);

        if (RuntimeUserKeys.TryParse(normalizedRuntimeKey, out var parsedProtocol, out var parsedInboundTag, out var parsedUserId))
        {
            normalizedProtocol = normalizedProtocol.Length == 0 ? parsedProtocol : normalizedProtocol;
            normalizedInboundTag = normalizedInboundTag.Length == 0 ? parsedInboundTag : normalizedInboundTag;
            normalizedUserId = normalizedUserId.Length == 0 ? parsedUserId : normalizedUserId;
            normalizedRuntimeKey = RuntimeUserKeys.Create(normalizedProtocol, normalizedInboundTag, normalizedUserId);
        }
        else if (computedRuntimeKey.IndexOf('\0') >= 0)
        {
            normalizedRuntimeKey = computedRuntimeKey;
        }
        else if (normalizedRuntimeKey.Length == 0)
        {
            normalizedRuntimeKey = computedRuntimeKey;
        }

        return new TrafficScope(normalizedRuntimeKey, normalizedUserId, normalizedProtocol, normalizedInboundTag);
    }

    private readonly record struct TrafficAggregate(string UserId, long UploadBytes, long DownloadBytes);

    private readonly record struct ScopedTrafficAggregate(
        string UserId,
        string Protocol,
        string InboundTag,
        long UploadBytes,
        long DownloadBytes);

    private readonly record struct TrafficScope(string RuntimeKey, string UserId, string Protocol, string InboundTag);
}

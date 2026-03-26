using NodePanel.ControlPlane.Protocol;
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

        var aggregated = new Dictionary<string, UserTrafficDelta>(StringComparer.Ordinal);
        while (_trafficQueue.TryDequeue(out var tuple))
        {
            var multiplier = nodeMultipliers.TryGetValue(tuple.NodeId, out var m) ? m : 1.0m;
            long up = (long)(tuple.Delta.UploadBytes * multiplier);
            long down = (long)(tuple.Delta.DownloadBytes * multiplier);

            if (aggregated.TryGetValue(tuple.Delta.UserId, out var existing))
            {
                aggregated[tuple.Delta.UserId] = new UserTrafficDelta
                {
                    UserId = tuple.Delta.UserId,
                    UploadBytes = existing.UploadBytes + up,
                    DownloadBytes = existing.DownloadBytes + down
                };
            }
            else
            {
                aggregated[tuple.Delta.UserId] = new UserTrafficDelta
                {
                    UserId = tuple.Delta.UserId,
                    UploadBytes = up,
                    DownloadBytes = down
                };
            }
        }

        if (aggregated.Count > 0)
        {
            // Update individual records
            foreach (var delta in aggregated.Values)
            {
                var record = await _db.FSql.Select<TrafficRecordEntity>().Where(t => t.UserId == delta.UserId).FirstAsync(cancellationToken)
                             ?? new TrafficRecordEntity { UserId = delta.UserId, UploadBytes = 0, DownloadBytes = 0 };
                record.UploadBytes += delta.UploadBytes;
                record.DownloadBytes += delta.DownloadBytes;
                await _db.FSql.InsertOrUpdate<TrafficRecordEntity>().SetSource(record).ExecuteAffrowsAsync(cancellationToken);
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
}

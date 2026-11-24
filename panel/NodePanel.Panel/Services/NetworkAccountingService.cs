using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NodePanel.Panel.Services;

public sealed class NetworkAccountingService : BackgroundService
{
    private readonly DatabaseService _db;
    private readonly PanelMutationService _panelMutationService;
    private readonly ILogger<NetworkAccountingService> _logger;
    private int _hasPending = 1;
    private long _nextReceiptCleanupAt;

    public NetworkAccountingService(DatabaseService db, PanelMutationService panelMutationService, ILogger<NetworkAccountingService> logger)
    {
        _db = db;
        _panelMutationService = panelMutationService;
        _logger = logger;
    }

    public async Task EnqueueTrafficDeltaAsync(string nodeId, IReadOnlyList<UserTrafficDelta> deltas, CancellationToken cancellationToken, string? batchId = null)
    {
        if (deltas.Count == 0)
        {
            if (batchId is not null) throw new InvalidOperationException("A telemetry batch cannot be empty.");
            return;
        }

        if (batchId is not null && !Guid.TryParseExact(batchId, "N", out _))
            throw new InvalidOperationException("Invalid telemetry batch ID.");

        var json = JsonSerializer.Serialize(deltas.ToList(), ControlPlaneJsonSerializerContext.Default.ListUserTrafficDelta);
        var batch = new PendingTrafficBatchEntity
        {
            BatchId = batchId ?? Guid.NewGuid().ToString("N"),
            NodeId = nodeId,
            PayloadJson = json,
            CreatedAtUnixMilliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };
        if (batchId is null)
        {
            await _db.FSql.Insert(batch).ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
            await _db.TrafficWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                _db.FSql.CodeFirst.SyncStructure<ReceivedTrafficBatchEntity>();
                _db.FSql.CodeFirst.SyncStructure<PendingTrafficBatchEntity>();
                using var connection = await _db.FSql.Ado.MasterPool.GetAsync(cancellationToken).ConfigureAwait(false);
                await using var transaction = await connection.Value.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
                var existing = await _db.FSql.Select<ReceivedTrafficBatchEntity>().WithTransaction(transaction)
                    .Where(item => item.BatchId == batchId).FirstAsync(cancellationToken).ConfigureAwait(false);
                if (existing is not null)
                {
                    if (!string.Equals(existing.NodeId, nodeId, StringComparison.Ordinal) ||
                        !string.Equals(existing.PayloadHash, hash, StringComparison.Ordinal))
                        throw new InvalidOperationException($"Telemetry batch {batchId} was reused with different content.");
                    Volatile.Write(ref _hasPending, 1);
                    return;
                }

                await _db.FSql.Insert(new ReceivedTrafficBatchEntity
                    {
                        BatchId = batchId,
                        NodeId = nodeId,
                        PayloadHash = hash,
                        ReceivedAtUnixMilliseconds = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    })
                    .WithTransaction(transaction).ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
                await _db.FSql.Insert(batch).WithTransaction(transaction).ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _db.TrafficWriteLock.Release();
            }
        }
        Volatile.Write(ref _hasPending, 1);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(
                Volatile.Read(ref _hasPending) != 0
                    ? TimeSpan.FromSeconds(5)
                    : TimeSpan.FromMinutes(1),
                stoppingToken);
            
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

    internal async Task ProcessTrafficAsync(CancellationToken cancellationToken)
    {
        var nodeMultipliers = await _db.FSql.Select<NodeEntity>().ToDictionaryAsync(n => n.NodeId, n => n.TrafficMultiplier, cancellationToken);

        var pending = await _db.FSql.Select<PendingTrafficBatchEntity>()
            .OrderBy(batch => batch.CreatedAtUnixMilliseconds)
            .OrderBy(batch => batch.BatchId)
            .Limit(10).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var batch in pending)
        {
            await WriteTrafficBatchAsync(batch, nodeMultipliers, cancellationToken).ConfigureAwait(false);
        }
        if (Environment.TickCount64 >= _nextReceiptCleanupAt)
        {
            await PruneTrafficReceiptsAsync(DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false);
            _nextReceiptCleanupAt = Environment.TickCount64 + (long)TimeSpan.FromMinutes(1).TotalMilliseconds;
        }
        // Clear before checking so an enqueue racing with this read cannot be lost.
        Volatile.Write(ref _hasPending, 0);
        if (await _db.FSql.Select<PendingTrafficBatchEntity>().AnyAsync(cancellationToken).ConfigureAwait(false))
            Volatile.Write(ref _hasPending, 1);

        await _db.TrafficWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Evaluate limits
            var users = await _db.FSql.Select<UserEntity>().Where(user => user.Enabled).ToListAsync(cancellationToken);
            var tRecordsByUser = new Dictionary<string, TrafficRecordEntity>(StringComparer.Ordinal);
            foreach (var userIds in users.Where(user => user.TransferEnableBytes > 0)
                         .Select(user => user.UserId).Chunk(500))
            {
                var records = await _db.FSql.Select<TrafficRecordEntity>()
                    .Where(record => userIds.Contains(record.UserId)).ToListAsync(cancellationToken);
                foreach (var record in records) tRecordsByUser[record.UserId] = record;
            }

            var usersToDisable = new List<UserEntity>();
            foreach (var userEntity in users)
            {
                if (!userEntity.Enabled) continue;

                var tRecord = tRecordsByUser.GetValueOrDefault(userEntity.UserId);
                var totalUsed = tRecord is null ? 0 : tRecord.UploadBytes + tRecord.DownloadBytes;
                var expired = userEntity.ExpiresAt.HasValue && DateTimeOffset.UtcNow >= userEntity.ExpiresAt.Value;
                var exhausted = userEntity.TransferEnableBytes > 0 && totalUsed >= userEntity.TransferEnableBytes;
                if (expired || exhausted)
                {
                    userEntity.DisableReason = expired ? "expired" : "traffic";
                    usersToDisable.Add(userEntity);
                }
            }

            await _panelMutationService.DisableUsersForAccountingAsync(usersToDisable, cancellationToken).ConfigureAwait(false);
            if (usersToDisable.Count > 0)
                _logger.LogInformation("Disabled {UserCount} users due to traffic limits or expiration.", usersToDisable.Count);
        }
        finally
        {
            _db.TrafficWriteLock.Release();
        }
    }

    internal async Task PruneTrafficReceiptsAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        await _db.TrafficWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _db.FSql.CodeFirst.SyncStructure<ReceivedTrafficBatchEntity>();
            _db.FSql.CodeFirst.SyncStructure<PendingTrafficBatchEntity>();
            var nowMilliseconds = now.ToUnixTimeMilliseconds();
            await _db.FSql.Update<ReceivedTrafficBatchEntity>()
                .Set(receipt => receipt.ReceivedAtUnixMilliseconds, nowMilliseconds)
                .Where(receipt => receipt.ReceivedAtUnixMilliseconds == null)
                .ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
            var cutoff = now.AddMinutes(-10).ToUnixTimeMilliseconds();
            await _db.FSql.Delete<ReceivedTrafficBatchEntity>()
                .Where(receipt => receipt.ReceivedAtUnixMilliseconds <= cutoff)
                .Where("NOT EXISTS (SELECT 1 FROM np_pending_traffic_batches AS pending WHERE pending.BatchId = np_received_traffic_batches.BatchId)")
                .ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _db.TrafficWriteLock.Release();
        }
    }

    private async Task WriteTrafficBatchAsync(
        PendingTrafficBatchEntity batch,
        IReadOnlyDictionary<string, decimal> nodeMultipliers,
        CancellationToken cancellationToken)
    {
        var aggregatedUsers = new Dictionary<string, TrafficAggregate>(StringComparer.Ordinal);
        var aggregatedScoped = new Dictionary<string, ScopedTrafficAggregate>(StringComparer.Ordinal);
        var deltas = JsonSerializer.Deserialize(batch.PayloadJson, ControlPlaneJsonSerializerContext.Default.ListUserTrafficDelta)
            ?? throw new InvalidOperationException($"Traffic batch {batch.BatchId} has an empty payload.");
        foreach (var delta in deltas)
        {
            var multiplier = nodeMultipliers.TryGetValue(batch.NodeId, out var m) ? m : 1.0m;
            var scope = ResolveTrafficScope(delta);
            if (scope.UserId.Length == 0)
            {
                continue;
            }

            var up = ScaleTraffic(delta.UploadBytes, multiplier);
            var down = ScaleTraffic(delta.DownloadBytes, multiplier);

            AddUserTraffic(aggregatedUsers, scope.UserId, up, down);
            if (scope.Protocol.Length > 0 && scope.InboundTag.Length > 0)
            {
                AddScopedTraffic(aggregatedScoped, scope, up, down);
            }
        }

        await _db.TrafficWriteLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _db.FSql.CodeFirst.SyncStructure<PendingTrafficBatchEntity>();
            _db.FSql.CodeFirst.SyncStructure<TrafficRecordEntity>();
            _db.FSql.CodeFirst.SyncStructure<ScopedTrafficRecordEntity>();
            using var connection = await _db.FSql.Ado.MasterPool.GetAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = await connection.Value.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var claimed = await _db.FSql.Delete<PendingTrafficBatchEntity>().WithTransaction(transaction)
                .Where(record => record.BatchId == batch.BatchId).ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
            if (claimed == 0) return;

            if (aggregatedUsers.Count > 0)
            {
                var trafficRecords = new List<TrafficRecordEntity>();
                foreach (var userIds in aggregatedUsers.Keys.Chunk(500))
                {
                    trafficRecords.AddRange(await _db.FSql.Select<TrafficRecordEntity>().WithTransaction(transaction)
                        .Where(record => userIds.Contains(record.UserId)).ToListAsync(cancellationToken));
                }
                var trafficByUser = trafficRecords.ToDictionary(static record => record.UserId, StringComparer.Ordinal);
                var changedRecords = new List<TrafficRecordEntity>(aggregatedUsers.Count);

                foreach (var aggregate in aggregatedUsers.Values)
                {
                    var record = trafficByUser.TryGetValue(aggregate.UserId, out var existing)
                        ? existing
                        : new TrafficRecordEntity { UserId = aggregate.UserId, UploadBytes = 0, DownloadBytes = 0 };

                    record.UploadBytes += aggregate.UploadBytes;
                    record.DownloadBytes += aggregate.DownloadBytes;
                    changedRecords.Add(record);
                }

                await _db.FSql.InsertOrUpdate<TrafficRecordEntity>()
                    .WithTransaction(transaction)
                    .SetSource(changedRecords)
                    .ExecuteAffrowsAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            if (aggregatedScoped.Count > 0)
            {
                var scopedRecords = new List<ScopedTrafficRecordEntity>();
                foreach (var userIds in aggregatedUsers.Keys.Chunk(500))
                {
                    scopedRecords.AddRange(await _db.FSql.Select<ScopedTrafficRecordEntity>().WithTransaction(transaction)
                        .Where(record => userIds.Contains(record.UserId)).ToListAsync(cancellationToken));
                }
                var scopedByKey = scopedRecords.ToDictionary(
                    static record => BuildScopedKey(record.UserId, record.Protocol, record.InboundTag),
                    StringComparer.Ordinal);
                var changedRecords = new List<ScopedTrafficRecordEntity>(aggregatedScoped.Count);

                foreach (var aggregate in aggregatedScoped.Values)
                {
                    var key = BuildScopedKey(aggregate.UserId, aggregate.Protocol, aggregate.InboundTag);
                    var record = scopedByKey.TryGetValue(key, out var existing)
                        ? existing
                        : new ScopedTrafficRecordEntity
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
                    changedRecords.Add(record);
                }

                await _db.FSql.InsertOrUpdate<ScopedTrafficRecordEntity>()
                    .WithTransaction(transaction)
                    .SetSource(changedRecords)
                    .ExecuteAffrowsAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _db.TrafficWriteLock.Release();
        }
    }

    private static string BuildScopedKey(string userId, string protocol, string inboundTag)
        => userId + "\0" + protocol + "\0" + inboundTag;

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

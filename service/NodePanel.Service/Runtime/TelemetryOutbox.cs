using System.Text.Json;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Service.Configuration;

namespace NodePanel.Service.Runtime;

public sealed class TelemetryOutbox
{
    private readonly string _directory;
    private readonly string _nodeId;
    private readonly string _controlPlaneUrl;
    private readonly SortedDictionary<string, PendingTelemetryBatch> _pending = new(StringComparer.Ordinal);
    private bool _loaded;
    private long _lastTicks;

    public TelemetryOutbox(NodePanelOptions options, PersistedNodeConfigStore configStore)
    {
        _directory = configStore.Path + ".telemetry";
        _nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId.Trim();
        _controlPlaneUrl = options.ControlPlane.Url?.Trim() ?? string.Empty;
    }

    public IReadOnlyCollection<PendingTelemetryBatch> Pending
    {
        get { EnsureLoaded(); return _pending.Values; }
    }

    public async Task AppendAsync(IReadOnlyList<UserTrafficDelta> traffic, CancellationToken cancellationToken)
    {
        if (traffic.Count == 0) return;
        EnsureLoaded();
        Directory.CreateDirectory(_directory);
        var id = Guid.NewGuid().ToString("N");
        var ticks = Math.Max(DateTime.UtcNow.Ticks, _lastTicks + 1);
        var filename = $"{ticks:D19}-{id}.json";
        var path = Path.Combine(_directory, filename);
        var tempPath = path + ".tmp";
        var batch = new PendingTelemetryBatch
        {
            BatchId = id,
            NodeId = _nodeId,
            ControlPlaneUrl = _controlPlaneUrl,
            Traffic = traffic.ToList()
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(batch, ServiceRuntimeJsonSerializerContext.Default.PendingTelemetryBatch);
        await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, useAsync: true))
        {
            await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }
        File.Move(tempPath, path);
        _pending.Add(filename, batch);
        _lastTicks = ticks;
    }

    public void RemoveAcknowledged(string batchId)
    {
        EnsureLoaded();
        var entry = _pending.FirstOrDefault(item => string.Equals(item.Value.BatchId, batchId, StringComparison.Ordinal));
        if (entry.Key is null) throw new InvalidOperationException($"Unknown telemetry batch {batchId}.");
        File.Delete(Path.Combine(_directory, entry.Key));
        _pending.Remove(entry.Key);
    }

    private void EnsureLoaded()
    {
        if (_loaded) return;
        var pending = new SortedDictionary<string, PendingTelemetryBatch>(StringComparer.Ordinal);
        if (Directory.Exists(_directory))
        {
            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                var name = Path.GetFileName(path);
                var batch = JsonSerializer.Deserialize(File.ReadAllBytes(path), ServiceRuntimeJsonSerializerContext.Default.PendingTelemetryBatch)
                    ?? throw new InvalidOperationException($"Telemetry outbox file {path} is empty.");
                if (!Guid.TryParseExact(batch.BatchId, "N", out _) ||
                    !string.Equals(batch.NodeId, _nodeId, StringComparison.Ordinal) ||
                    !string.Equals(batch.ControlPlaneUrl, _controlPlaneUrl, StringComparison.Ordinal) ||
                    batch.Traffic is null || batch.Traffic.Count == 0 ||
                    name.Length != 57 || name[19] != '-' ||
                    !long.TryParse(name.AsSpan(0, 19), out var ticks) ||
                    !string.Equals(name.Substring(20, 32), batch.BatchId, StringComparison.Ordinal))
                    throw new InvalidOperationException($"Invalid or incompatible telemetry outbox file {path}.");
                pending.Add(name, batch);
                _lastTicks = Math.Max(_lastTicks, ticks);
            }
        }
        foreach (var item in pending) _pending.Add(item.Key, item.Value);
        _loaded = true;
    }
}

public sealed record PendingTelemetryBatch
{
    public required string BatchId { get; init; }
    public required string NodeId { get; init; }
    public required string ControlPlaneUrl { get; init; }
    public required List<UserTrafficDelta> Traffic { get; init; }
}

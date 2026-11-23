using System.Threading.Channels;

namespace NodePanel.Panel.Services;

/// <summary>
/// Coalescing queue for control-plane snapshot pushes. A node appears at most once
/// while it is waiting, so repeated saves in quick succession collapse into one push.
/// </summary>
public sealed class ControlPlanePushQueue
{
    private readonly Channel<string> _channel;
    private readonly HashSet<string> _pending = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    public ControlPlanePushQueue()
    {
        _channel = Channel.CreateUnbounded<string>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    }

    public bool TryEnqueue(string nodeId)
    {
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            return false;
        }

        lock (_sync)
        {
            if (!_pending.Add(nodeId))
            {
                return false;
            }
        }

        if (_channel.Writer.TryWrite(nodeId))
        {
            return true;
        }

        lock (_sync)
        {
            _pending.Remove(nodeId);
        }

        return false;
    }

    public int Enqueue(IEnumerable<string> nodeIds)
    {
        var count = 0;
        foreach (var nodeId in nodeIds)
        {
            if (TryEnqueue(nodeId))
            {
                count++;
            }
        }

        return count;
    }

    public async ValueTask<IReadOnlyList<string>> ReadBatchAsync(int maxCount, CancellationToken cancellationToken)
    {
        var batch = new List<string>(Math.Min(maxCount, 16));
        while (batch.Count == 0)
        {
            if (!await _channel.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return Array.Empty<string>();
            }

            while (batch.Count < maxCount && _channel.Reader.TryRead(out var nodeId))
            {
                lock (_sync)
                {
                    _pending.Remove(nodeId);
                }

                batch.Add(nodeId);
            }
        }

        return batch;
    }
}

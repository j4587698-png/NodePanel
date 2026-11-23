namespace NodePanel.Service.Runtime;

public sealed class TelemetryDeliveryState
{
    private readonly object _sync = new();
    private bool _ready;
    private string? _waitingId;
    private TaskCompletionSource<bool>? _waiting;

    public bool IsReady { get { lock (_sync) return _ready; } }

    public void SetReady()
    {
        lock (_sync) _ready = true;
    }

    public void Disconnect()
    {
        lock (_sync)
        {
            _ready = false;
            _waiting?.TrySetResult(false);
        }
    }

    public Task<bool> BeginWait(string batchId)
    {
        lock (_sync)
        {
            if (_waiting is not null) throw new InvalidOperationException("A telemetry acknowledgment is already pending.");
            _waitingId = batchId;
            _waiting = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            return _waiting.Task;
        }
    }

    public void Acknowledge(string batchId)
    {
        lock (_sync)
        {
            if (string.Equals(_waitingId, batchId, StringComparison.Ordinal))
                _waiting?.TrySetResult(true);
        }
    }

    public void EndWait(string batchId)
    {
        lock (_sync)
        {
            if (string.Equals(_waitingId, batchId, StringComparison.Ordinal))
            {
                _waitingId = null;
                _waiting = null;
            }
        }
    }
}

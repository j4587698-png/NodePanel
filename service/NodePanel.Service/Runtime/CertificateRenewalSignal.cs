namespace NodePanel.Service.Runtime;

public sealed class CertificateRenewalSignal
{
    private readonly object _sync = new();
    private TaskCompletionSource<int> _signal = CreateSignal();
    private CertificateRenewalRequestSnapshot _snapshot = new();

    public CertificateRenewalRequestSnapshot GetSnapshot() => Volatile.Read(ref _snapshot);

    public void Request(string source)
    {
        lock (_sync)
        {
            var next = _snapshot with
            {
                Version = _snapshot.Version + 1,
                RequestedAt = DateTimeOffset.UtcNow,
                Source = string.IsNullOrWhiteSpace(source) ? "unknown" : source.Trim()
            };

            _snapshot = next;
            var completed = _signal;
            _signal = CreateSignal();
            completed.TrySetResult(next.Version);
        }
    }

    public Task WaitForChangeAsync(int knownVersion, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_snapshot.Version != knownVersion)
            {
                return Task.CompletedTask;
            }

            return _signal.Task.WaitAsync(cancellationToken);
        }
    }

    private static TaskCompletionSource<int> CreateSignal()
        => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

public sealed record CertificateRenewalRequestSnapshot
{
    public int Version { get; init; }

    public DateTimeOffset? RequestedAt { get; init; }

    public string Source { get; init; } = string.Empty;
}

using System.Collections.Concurrent;

namespace NodePanel.Service.Acme;

public sealed class AcmeHttpChallengeStore
{
    private readonly ConcurrentDictionary<string, string> _responses = new(StringComparer.Ordinal);
    private readonly object _listenerSync = new();
    private TaskCompletionSource<int> _listenerSignal = CreateSignal();
    private AcmeHttpChallengeListenerSnapshot _listener = new();

    public AcmeHttpChallengeListenerSnapshot GetListenerSnapshot() => Volatile.Read(ref _listener);

    public void PutResponse(string token, string keyAuthorization)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyAuthorization);

        _responses[token] = keyAuthorization;
    }

    public void RemoveResponse(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        _responses.TryRemove(token, out _);
    }

    public bool TryGetResponse(string token, out string keyAuthorization)
        => _responses.TryGetValue(token, out keyAuthorization!);

    public void ReportListener(AcmeHttpChallengeListenerSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        lock (_listenerSync)
        {
            var current = _listener;
            var changed = current.IsListening != snapshot.IsListening ||
                          current.Port != snapshot.Port ||
                          !string.Equals(current.ListenAddress, snapshot.ListenAddress, StringComparison.Ordinal) ||
                          !string.Equals(current.LastError, snapshot.LastError, StringComparison.Ordinal);

            _listener = snapshot with
            {
                Version = changed ? current.Version + 1 : current.Version
            };

            if (!changed)
            {
                return;
            }

            var completed = _listenerSignal;
            _listenerSignal = CreateSignal();
            completed.TrySetResult(_listener.Version);
        }
    }

    public Task WaitForListenerChangeAsync(int knownVersion, CancellationToken cancellationToken)
    {
        lock (_listenerSync)
        {
            if (_listener.Version != knownVersion)
            {
                return Task.CompletedTask;
            }

            return _listenerSignal.Task.WaitAsync(cancellationToken);
        }
    }

    private static TaskCompletionSource<int> CreateSignal()
        => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

public sealed record AcmeHttpChallengeListenerSnapshot
{
    public int Version { get; init; }

    public bool IsListening { get; init; }

    public string ListenAddress { get; init; } = string.Empty;

    public int Port { get; init; }

    public string LastError { get; init; } = string.Empty;
}

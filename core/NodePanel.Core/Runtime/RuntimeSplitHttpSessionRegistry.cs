namespace NodePanel.Core.Runtime;

// Aligns with xray-core transport/internet/splithttp/hub.go:
// pending sessions are reaped if the downlink GET never establishes within TTL.
internal sealed class RuntimeSplitHttpSessionRegistry : IDisposable
{
    public static readonly TimeSpan DefaultPendingConnectionTtl = TimeSpan.FromSeconds(30);

    private readonly object _syncRoot = new();
    private readonly Dictionary<string, RuntimeSplitHttpServerSession> _sessions = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly int _maxBufferedPosts;
    private readonly TimeSpan _pendingConnectionTtl;

    private bool _disposed;

    public RuntimeSplitHttpSessionRegistry(
        int maxBufferedPosts,
        TimeSpan? pendingConnectionTtl = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxBufferedPosts);

        var normalizedPendingConnectionTtl = pendingConnectionTtl ?? DefaultPendingConnectionTtl;
        if (normalizedPendingConnectionTtl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(pendingConnectionTtl));
        }

        _maxBufferedPosts = maxBufferedPosts;
        _pendingConnectionTtl = normalizedPendingConnectionTtl;
    }

    public int ActiveSessions
    {
        get
        {
            lock (_syncRoot)
            {
                return _sessions.Count;
            }
        }
    }

    public RuntimeSplitHttpServerSession GetOrCreate(string sessionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);

        RuntimeSplitHttpServerSession session;
        var created = false;
        var normalizedSessionId = sessionId.Trim();

        lock (_syncRoot)
        {
            ThrowIfDisposedNoLock();

            if (_sessions.TryGetValue(normalizedSessionId, out session!))
            {
                return session;
            }

            session = new RuntimeSplitHttpServerSession(
                normalizedSessionId,
                new RuntimeSplitHttpUploadQueue(_maxBufferedPosts));
            _sessions[normalizedSessionId] = session;
            created = true;
        }

        if (created)
        {
            _ = ReapPendingSessionAsync(session);
        }

        return session;
    }

    public bool TryGet(string sessionId, out RuntimeSplitHttpServerSession? session)
    {
        session = null;
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return false;
        }

        lock (_syncRoot)
        {
            if (_disposed)
            {
                return false;
            }

            return _sessions.TryGetValue(sessionId.Trim(), out session);
        }
    }

    public bool TryRemove(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return false;
        }

        return TryRemoveCore(sessionId.Trim(), expectedSession: null, out _);
    }

    public void Dispose()
    {
        RuntimeSplitHttpServerSession[] sessionsToClose;
        lock (_syncRoot)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            sessionsToClose = _sessions.Values.ToArray();
            _sessions.Clear();
        }

        _disposeCts.Cancel();
        _disposeCts.Dispose();

        for (var index = 0; index < sessionsToClose.Length; index++)
        {
            sessionsToClose[index].Close();
        }
    }

    private async Task ReapPendingSessionAsync(RuntimeSplitHttpServerSession session)
    {
        try
        {
            await Task.Delay(_pendingConnectionTtl, _disposeCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        if (session.IsFullyConnected)
        {
            return;
        }

        TryRemoveCore(session.SessionId, session, out _);
    }

    private bool TryRemoveCore(
        string sessionId,
        RuntimeSplitHttpServerSession? expectedSession,
        out RuntimeSplitHttpServerSession? removedSession)
    {
        removedSession = null;

        lock (_syncRoot)
        {
            if (_disposed ||
                !_sessions.TryGetValue(sessionId, out var currentSession))
            {
                return false;
            }

            if (expectedSession is not null &&
                !ReferenceEquals(currentSession, expectedSession))
            {
                return false;
            }

            _sessions.Remove(sessionId);
            removedSession = currentSession;
        }

        removedSession.Close();
        return true;
    }

    private void ThrowIfDisposedNoLock()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

internal sealed class RuntimeSplitHttpServerSession
{
    private int _closed;
    private int _fullyConnected;

    public RuntimeSplitHttpServerSession(
        string sessionId,
        RuntimeSplitHttpUploadQueue uploadQueue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        ArgumentNullException.ThrowIfNull(uploadQueue);

        SessionId = sessionId.Trim();
        UploadQueue = uploadQueue;
    }

    public string SessionId { get; }

    public RuntimeSplitHttpUploadQueue UploadQueue { get; }

    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    public bool IsFullyConnected => Volatile.Read(ref _fullyConnected) != 0;

    public bool MarkFullyConnected()
    {
        if (IsClosed)
        {
            return false;
        }

        Interlocked.Exchange(ref _fullyConnected, 1);
        return !IsClosed;
    }

    internal void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        UploadQueue.Complete();
    }
}

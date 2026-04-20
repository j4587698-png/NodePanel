namespace NodePanel.Core.Runtime;

public interface IRuntimeSessionRegistry
{
    int ActiveSessions { get; }

    IDisposable OpenSession(string userId);

    bool TryOpenSession(string userId, string? remoteIp, int deviceLimit, out IDisposable? lease);

    IReadOnlyList<UserSessionSnapshot> CreateSnapshot();
}

public sealed class SessionRegistry : IRuntimeSessionRegistry
{
    private readonly object _syncRoot = new();
    private readonly Dictionary<string, UserSessionState> _perUser = new(StringComparer.Ordinal);

    private int _activeSessions;

    public int ActiveSessions => Volatile.Read(ref _activeSessions);

    public IDisposable OpenSession(string userId)
    {
        if (!TryOpenSession(userId, remoteIp: null, deviceLimit: 0, out var lease) || lease is null)
        {
            throw new InvalidOperationException($"Failed to open a session for user '{userId}'.");
        }

        return lease;
    }

    public bool TryOpenSession(string userId, string? remoteIp, int deviceLimit, out IDisposable? lease)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var normalizedUserId = userId.Trim();
        var normalizedRemoteIp = NormalizeRemoteIp(remoteIp);
        var normalizedDeviceLimit = Math.Max(0, deviceLimit);

        lock (_syncRoot)
        {
            if (!_perUser.TryGetValue(normalizedUserId, out var state))
            {
                state = new UserSessionState();
                _perUser[normalizedUserId] = state;
            }

            if (!string.IsNullOrWhiteSpace(normalizedRemoteIp) &&
                normalizedDeviceLimit > 0 &&
                !state.SessionsByIp.ContainsKey(normalizedRemoteIp) &&
                state.SessionsByIp.Count >= normalizedDeviceLimit)
            {
                lease = null;
                return false;
            }

            state.TotalSessions++;
            if (!string.IsNullOrWhiteSpace(normalizedRemoteIp))
            {
                state.SessionsByIp.TryGetValue(normalizedRemoteIp, out var currentIpSessions);
                state.SessionsByIp[normalizedRemoteIp] = currentIpSessions + 1;
            }
        }

        Interlocked.Increment(ref _activeSessions);
        lease = new SessionLease(this, normalizedUserId, normalizedRemoteIp);
        return true;
    }

    public IReadOnlyList<UserSessionSnapshot> CreateSnapshot()
    {
        lock (_syncRoot)
        {
            if (_perUser.Count == 0)
            {
                return Array.Empty<UserSessionSnapshot>();
            }

            var items = new List<UserSessionSnapshot>(_perUser.Count);
            foreach (var pair in _perUser)
            {
                if (pair.Value.TotalSessions <= 0)
                {
                    continue;
                }

                var remoteIps = pair.Value.SessionsByIp.Keys
                    .OrderBy(static value => value, StringComparer.Ordinal)
                    .ToArray();
                items.Add(CreateSnapshot(pair.Key, pair.Value.TotalSessions, remoteIps));
            }

            items.Sort(static (left, right) => string.Compare(left.RuntimeKey, right.RuntimeKey, StringComparison.Ordinal));
            return items;
        }
    }

    private void CloseSession(string userId, string? remoteIp)
    {
        var shouldDecrement = false;

        lock (_syncRoot)
        {
            if (!_perUser.TryGetValue(userId, out var state))
            {
                return;
            }

            if (state.TotalSessions > 0)
            {
                state.TotalSessions--;
                shouldDecrement = true;
            }

            if (!string.IsNullOrWhiteSpace(remoteIp) &&
                state.SessionsByIp.TryGetValue(remoteIp, out var currentIpSessions))
            {
                if (currentIpSessions <= 1)
                {
                    state.SessionsByIp.Remove(remoteIp);
                }
                else
                {
                    state.SessionsByIp[remoteIp] = currentIpSessions - 1;
                }
            }

            if (state.TotalSessions == 0)
            {
                _perUser.Remove(userId);
            }
        }

        if (shouldDecrement)
        {
            Interlocked.Decrement(ref _activeSessions);
        }
    }

    private static string NormalizeRemoteIp(string? remoteIp)
        => string.IsNullOrWhiteSpace(remoteIp) ? string.Empty : remoteIp.Trim();

    private static UserSessionSnapshot CreateSnapshot(
        string runtimeKey,
        int activeSessions,
        IReadOnlyList<string> remoteIps)
    {
        var normalizedRuntimeKey = runtimeKey.Trim();
        return RuntimeUserKeys.TryParse(normalizedRuntimeKey, out var protocol, out var inboundTag, out var userId)
            ? new UserSessionSnapshot
            {
                RuntimeKey = normalizedRuntimeKey,
                Protocol = protocol,
                InboundTag = inboundTag,
                UserId = userId,
                ActiveSessions = activeSessions,
                RemoteIps = remoteIps
            }
            : new UserSessionSnapshot
            {
                RuntimeKey = normalizedRuntimeKey,
                UserId = normalizedRuntimeKey,
                ActiveSessions = activeSessions,
                RemoteIps = remoteIps
            };
    }

    private sealed class UserSessionState
    {
        public Dictionary<string, int> SessionsByIp { get; } = new(StringComparer.Ordinal);

        public int TotalSessions { get; set; }
    }

    private sealed class SessionLease : IDisposable
    {
        private readonly SessionRegistry _registry;
        private readonly string _userId;
        private readonly string _remoteIp;
        private int _disposed;

        public SessionLease(SessionRegistry registry, string userId, string remoteIp)
        {
            _registry = registry;
            _userId = userId;
            _remoteIp = remoteIp;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1)
            {
                return;
            }

            _registry.CloseSession(_userId, _remoteIp);
        }
    }
}

using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class TrojanUserValidator
{
    private readonly Lock _sync = new();

    private Snapshot _snapshot = Snapshot.Empty;

    public TrojanUserValidator(IReadOnlyList<TrojanUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        Replace(users);
    }

    public int Count => Volatile.Read(ref _snapshot).TypedUsers.Count;

    public IReadOnlyList<TrojanUser> GetUsers()
        => Volatile.Read(ref _snapshot).TypedUsers;

    public bool TryGetUser(string userId, out TrojanUser? user)
        => Volatile.Read(ref _snapshot).ByUserId.TryGetValue(NormalizeUserId(userId), out user);

    public bool TryGetUserByHash(string passwordHash, out TrojanUser? user)
        => Volatile.Read(ref _snapshot).ByHash.TryGetValue(NormalizeHash(passwordHash), out user);

    public bool TryAuthenticate(string passwordHash, out TrojanUser? user)
        => TryGetUserByHash(passwordHash, out user);

    public void AddUser(TrojanUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            Volatile.Write(ref _snapshot, CreateSnapshot([.. snapshot.TypedUsers, user]));
        }
    }

    public bool RemoveUser(string userId)
    {
        var normalizedUserId = NormalizeUserId(userId);
        if (normalizedUserId.Length == 0)
        {
            return false;
        }

        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            if (!snapshot.ByUserId.ContainsKey(normalizedUserId))
            {
                return false;
            }

            Volatile.Write(
                ref _snapshot,
                CreateSnapshot(snapshot.TypedUsers.Where(user => !string.Equals(user.UserId, normalizedUserId, StringComparison.Ordinal))));
            return true;
        }
    }

    public void Replace(IEnumerable<TrojanUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            Volatile.Write(ref _snapshot, CreateSnapshot(users));
        }
    }

    private static Snapshot CreateSnapshot(IEnumerable<TrojanUser> users)
    {
        var typedUsers = users
            .Where(static user => user is not null)
            .ToArray();

        var byUserId = new Dictionary<string, TrojanUser>(typedUsers.Length, StringComparer.Ordinal);
        var byHash = new Dictionary<string, TrojanUser>(typedUsers.Length, StringComparer.Ordinal);
        foreach (var user in typedUsers)
        {
            byUserId[NormalizeUserId(user.UserId)] = user;
            byHash[NormalizeHash(user.PasswordHash)] = user;
        }

        return new Snapshot(typedUsers, byUserId, byHash);
    }

    private static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();

    private static string NormalizeHash(string? passwordHash)
        => string.IsNullOrWhiteSpace(passwordHash)
            ? string.Empty
            : passwordHash.Trim().ToLowerInvariant();

    private sealed record Snapshot(
        IReadOnlyList<TrojanUser> TypedUsers,
        IReadOnlyDictionary<string, TrojanUser> ByUserId,
        IReadOnlyDictionary<string, TrojanUser> ByHash)
    {
        public static readonly Snapshot Empty = new(
            Array.Empty<TrojanUser>(),
            new Dictionary<string, TrojanUser>(StringComparer.Ordinal),
            new Dictionary<string, TrojanUser>(StringComparer.Ordinal));
    }
}

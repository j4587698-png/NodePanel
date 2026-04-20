using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VmessTimedUserValidator
{
    private readonly Lock _sync = new();
    private readonly VmessAuthIdDecoderHolder _decoderHolder;
    private readonly Func<ulong> _fallbackBehaviorSeedFactory;

    private Snapshot _snapshot = Snapshot.Empty;
    private ulong _behaviorSeed;
    private bool _behaviorSeedFrozen;

    public VmessTimedUserValidator(IReadOnlyList<VmessUser> users)
        : this(users, new VmessAuthIdHistory(), static () => GoMathRandom.PackageLevelNextUInt64())
    {
    }

    internal VmessTimedUserValidator(
        IReadOnlyList<VmessUser> users,
        VmessAuthIdHistory authIdHistory,
        Func<ulong> fallbackBehaviorSeedFactory)
    {
        ArgumentNullException.ThrowIfNull(users);

        _decoderHolder = new VmessAuthIdDecoderHolder(authIdHistory ?? throw new ArgumentNullException(nameof(authIdHistory)));
        _fallbackBehaviorSeedFactory = fallbackBehaviorSeedFactory ?? throw new ArgumentNullException(nameof(fallbackBehaviorSeedFactory));
        Replace(users);
    }

    public int Count => Volatile.Read(ref _snapshot).TypedUsers.Count;

    public ulong BehaviorSeed
    {
        get
        {
            lock (_sync)
            {
                if (_behaviorSeedFrozen)
                {
                    return _behaviorSeed;
                }

                _behaviorSeedFrozen = true;
                if (_behaviorSeed == 0)
                {
                    _behaviorSeed = _fallbackBehaviorSeedFactory();
                }

                return _behaviorSeed;
            }
        }
    }

    public IReadOnlyList<VmessUser> GetUsers()
        => Volatile.Read(ref _snapshot).TypedUsers;

    public bool TryGetUser(string userId, out VmessUser? user)
        => Volatile.Read(ref _snapshot).ByUserId.TryGetValue(userId, out user);

    public bool TryGetUserByUuid(string uuid, out VmessUser? user)
        => Volatile.Read(ref _snapshot).ByUuid.TryGetValue(uuid, out user);

    public void AddUser(VmessUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            _decoderHolder.AddUser(user);
            if (!_behaviorSeedFrozen)
            {
                _behaviorSeed = VmessHandshakeDrainer.AccumulateBehaviorSeed(_behaviorSeed, user);
            }

            Volatile.Write(ref _snapshot, CreateSnapshot([.. snapshot.TypedUsers, user]));
        }
    }

    public bool RemoveUser(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            return false;
        }

        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            if (!snapshot.ByUserId.ContainsKey(userId))
            {
                return false;
            }

            var removedUser = snapshot.ByUserId[userId];
            _decoderHolder.RemoveUser(removedUser.CmdKey);
            Volatile.Write(
                ref _snapshot,
                CreateSnapshot(snapshot.TypedUsers.Where(user => !string.Equals(user.UserId, userId, StringComparison.Ordinal))));
            return true;
        }
    }

    public void Replace(IEnumerable<VmessUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            var typedUsers = users
                .Where(static user => user is not null)
                .ToArray();
            _decoderHolder.Replace(typedUsers);
            _behaviorSeed = 0;
            _behaviorSeedFrozen = false;
            for (var index = 0; index < typedUsers.Length; index++)
            {
                _behaviorSeed = VmessHandshakeDrainer.AccumulateBehaviorSeed(_behaviorSeed, typedUsers[index]);
            }

            Volatile.Write(ref _snapshot, CreateSnapshot(typedUsers));
        }
    }

    public bool TryMatchUser(
        ReadOnlySpan<byte> authId,
        out VmessUser? user,
        out Exception? error)
    {
        return _decoderHolder.TryMatchUser(authId, out user, out error);
    }

    private static Snapshot CreateSnapshot(IEnumerable<VmessUser> users)
    {
        var typedUsers = users
            .Where(static user => user is not null)
            .ToArray();

        var byUserId = new Dictionary<string, VmessUser>(typedUsers.Length, StringComparer.Ordinal);
        var byUuid = new Dictionary<string, VmessUser>(typedUsers.Length, StringComparer.OrdinalIgnoreCase);
        foreach (var user in typedUsers)
        {
            byUserId[user.UserId] = user;
            byUuid[user.Uuid] = user;
        }

        return new Snapshot(typedUsers, byUserId, byUuid);
    }

    private sealed record Snapshot(
        IReadOnlyList<VmessUser> TypedUsers,
        IReadOnlyDictionary<string, VmessUser> ByUserId,
        IReadOnlyDictionary<string, VmessUser> ByUuid)
    {
        public static readonly Snapshot Empty = new(
            Array.Empty<VmessUser>(),
            new Dictionary<string, VmessUser>(StringComparer.Ordinal),
            new Dictionary<string, VmessUser>(StringComparer.OrdinalIgnoreCase));
    }
}

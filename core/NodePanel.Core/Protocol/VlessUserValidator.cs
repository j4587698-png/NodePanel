using System.Buffers.Binary;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VlessUserValidator
{
    private readonly Lock _sync = new();

    private Snapshot _snapshot = Snapshot.Empty;

    public VlessUserValidator(IReadOnlyList<VlessUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        Replace(users);
    }

    public int Count => Volatile.Read(ref _snapshot).TypedUsers.Count;

    public IReadOnlyList<VlessUser> GetUsers()
        => Volatile.Read(ref _snapshot).TypedUsers;

    public bool TryGetUser(string userId, out VlessUser? user)
        => Volatile.Read(ref _snapshot).ByUserId.TryGetValue(NormalizeUserId(userId), out user);

    public bool TryGetUserByUuid(string uuid, out VlessUser? user)
    {
        if (!TryCreateProcessedUuidKey(uuid, out var uuidKey))
        {
            user = null;
            return false;
        }

        return Volatile.Read(ref _snapshot).ByProcessedUuid.TryGetValue(uuidKey, out user);
    }

    public bool TryResolveUser(string uuid, out VlessUser? user)
        => TryGetUserByUuid(uuid, out user);

    public void AddUser(VlessUser user)
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

    public void Replace(IEnumerable<VlessUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            Volatile.Write(ref _snapshot, CreateSnapshot(users));
        }
    }

    private static Snapshot CreateSnapshot(IEnumerable<VlessUser> users)
    {
        var typedUsers = users
            .Where(static user => user is not null)
            .ToArray();

        var byUserId = new Dictionary<string, VlessUser>(typedUsers.Length, StringComparer.Ordinal);
        var byProcessedUuid = new Dictionary<ProcessedUuidKey, VlessUser>(typedUsers.Length);
        foreach (var user in typedUsers)
        {
            byUserId[NormalizeUserId(user.UserId)] = user;
            byProcessedUuid[CreateProcessedUuidKey(user.Uuid)] = user;
        }

        return new Snapshot(typedUsers, byUserId, byProcessedUuid);
    }

    private static ProcessedUuidKey CreateProcessedUuidKey(string uuid)
    {
        if (!TryCreateProcessedUuidKey(uuid, out var uuidKey))
        {
            throw new InvalidOperationException("VLESS user requires a valid uuid.");
        }

        return uuidKey;
    }

    private static bool TryCreateProcessedUuidKey(string? uuid, out ProcessedUuidKey uuidKey)
    {
        Span<byte> uuidBytes = stackalloc byte[16];
        if (!ProtocolUuid.TryWriteBytes(uuid, uuidBytes))
        {
            uuidKey = default;
            return false;
        }

        uuidBytes[6] = 0;
        uuidBytes[7] = 0;
        uuidKey = new ProcessedUuidKey(
            BinaryPrimitives.ReadUInt64BigEndian(uuidBytes[..8]),
            BinaryPrimitives.ReadUInt64BigEndian(uuidBytes[8..16]));
        return true;
    }

    private static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();

    private sealed record Snapshot(
        IReadOnlyList<VlessUser> TypedUsers,
        IReadOnlyDictionary<string, VlessUser> ByUserId,
        IReadOnlyDictionary<ProcessedUuidKey, VlessUser> ByProcessedUuid)
    {
        public static readonly Snapshot Empty = new(
            Array.Empty<VlessUser>(),
            new Dictionary<string, VlessUser>(StringComparer.Ordinal),
            new Dictionary<ProcessedUuidKey, VlessUser>());
    }

    private readonly record struct ProcessedUuidKey(ulong High, ulong Low);
}

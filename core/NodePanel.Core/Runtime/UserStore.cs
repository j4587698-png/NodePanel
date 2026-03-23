namespace NodePanel.Core.Runtime;

public sealed class UserStore
{
    private UserSnapshot _snapshot = UserSnapshot.Empty;

    public int KnownUsers => Volatile.Read(ref _snapshot).ByUserId.Count;

    public void Replace(IReadOnlyList<IRuntimeUserDefinition> users)
    {
        var byUserId = new Dictionary<string, UserEntry>(users.Count, StringComparer.Ordinal);

        foreach (var user in users)
        {
            if (string.IsNullOrWhiteSpace(user.UserId))
            {
                continue;
            }

            var userId = user.UserId.Trim();
            if (string.IsNullOrWhiteSpace(userId))
            {
                continue;
            }

            byUserId[userId] = new UserEntry
            {
                UserId = userId,
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            };
        }

        Volatile.Write(ref _snapshot, new UserSnapshot(byUserId));
    }

    private sealed record UserSnapshot(IReadOnlyDictionary<string, UserEntry> ByUserId)
    {
        public static readonly UserSnapshot Empty = new(new Dictionary<string, UserEntry>(StringComparer.Ordinal));
    }

    private sealed record UserEntry
    {
        public required string UserId { get; init; }

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }
}

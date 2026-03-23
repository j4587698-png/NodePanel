using System.Buffers.Binary;

namespace NodePanel.Core.Protocol;

internal sealed class VmessAuthIdHistory
{
    private static readonly TimeSpan DefaultEntryLifetime = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan DefaultCleanupInterval = TimeSpan.FromSeconds(30);

    private readonly Lock _sync = new();
    private readonly Dictionary<AuthIdKey, DateTimeOffset> _entries = new(128);
    private readonly TimeSpan _entryLifetime;
    private readonly TimeSpan _cleanupInterval;
    private readonly Func<DateTimeOffset> _utcNow;

    private DateTimeOffset _nextCleanupAt;

    public VmessAuthIdHistory()
        : this(DefaultEntryLifetime, DefaultCleanupInterval, static () => DateTimeOffset.UtcNow)
    {
    }

    internal VmessAuthIdHistory(
        TimeSpan entryLifetime,
        TimeSpan cleanupInterval,
        Func<DateTimeOffset> utcNow)
    {
        if (entryLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(entryLifetime), entryLifetime, "Entry lifetime must be positive.");
        }

        if (cleanupInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(cleanupInterval), cleanupInterval, "Cleanup interval must be positive.");
        }

        _entryLifetime = entryLifetime;
        _cleanupInterval = cleanupInterval;
        _utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
        _nextCleanupAt = DateTimeOffset.MinValue;
    }

    public bool TryRegister(ReadOnlySpan<byte> authId)
    {
        var key = AuthIdKey.Create(authId);

        lock (_sync)
        {
            var now = _utcNow();
            if (_entries.TryGetValue(key, out var existingExpiration) &&
                existingExpiration > now)
            {
                return false;
            }

            if (now >= _nextCleanupAt)
            {
                RemoveExpiredEntries(now);
                _nextCleanupAt = now + _cleanupInterval;
            }

            _entries[key] = now + _entryLifetime;
            return true;
        }
    }

    private void RemoveExpiredEntries(DateTimeOffset now)
    {
        if (_entries.Count == 0)
        {
            return;
        }

        foreach (var pair in _entries.ToArray())
        {
            if (pair.Value <= now)
            {
                _entries.Remove(pair.Key);
            }
        }
    }

    private readonly record struct AuthIdKey(ulong High, ulong Low)
    {
        public static AuthIdKey Create(ReadOnlySpan<byte> authId)
        {
            if (authId.Length < 16)
            {
                throw new ArgumentOutOfRangeException(nameof(authId), "VMess auth id must be 16 bytes.");
            }

            return new AuthIdKey(
                BinaryPrimitives.ReadUInt64BigEndian(authId[..8]),
                BinaryPrimitives.ReadUInt64BigEndian(authId[8..16]));
        }
    }
}

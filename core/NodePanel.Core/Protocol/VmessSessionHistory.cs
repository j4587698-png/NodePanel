using System.Buffers.Binary;

namespace NodePanel.Core.Protocol;

internal sealed class VmessSessionHistory
{
    private static readonly TimeSpan DefaultEntryLifetime = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan DefaultCleanupInterval = TimeSpan.FromSeconds(30);

    private readonly Lock _sync = new();
    private readonly Dictionary<VmessSessionId, DateTimeOffset> _entries = new(128);
    private readonly TimeSpan _entryLifetime;
    private readonly TimeSpan _cleanupInterval;
    private readonly Func<DateTimeOffset> _utcNow;

    private DateTimeOffset _nextCleanupAt;

    public VmessSessionHistory()
        : this(DefaultEntryLifetime, DefaultCleanupInterval, static () => DateTimeOffset.UtcNow)
    {
    }

    internal VmessSessionHistory(
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

    public bool TryRegister(VmessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var sessionId = VmessSessionId.Create(request);

        lock (_sync)
        {
            var now = _utcNow();
            if (_entries.TryGetValue(sessionId, out var existingExpiration) &&
                existingExpiration > now)
            {
                return false;
            }

            if (now >= _nextCleanupAt)
            {
                RemoveExpiredEntries(now);
                _nextCleanupAt = now + _cleanupInterval;
            }

            _entries[sessionId] = now + _entryLifetime;
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

    private readonly record struct VmessSessionId(
        ulong User0,
        ulong User1,
        ulong Key0,
        ulong Key1,
        ulong Nonce0,
        ulong Nonce1)
    {
        public static VmessSessionId Create(VmessRequest request)
        {
            if (request.RequestBodyKey.Length < 16)
            {
                throw new ArgumentOutOfRangeException(nameof(request), "VMess request body key must be 16 bytes.");
            }

            if (request.RequestBodyIv.Length < 16)
            {
                throw new ArgumentOutOfRangeException(nameof(request), "VMess request body IV must be 16 bytes.");
            }

            Span<byte> userBytes = stackalloc byte[16];
            if (!ProtocolUuid.TryWriteBytes(request.User.Uuid, userBytes))
            {
                throw new InvalidOperationException("VMess user UUID is invalid.");
            }

            return new VmessSessionId(
                BinaryPrimitives.ReadUInt64BigEndian(userBytes[..8]),
                BinaryPrimitives.ReadUInt64BigEndian(userBytes[8..16]),
                BinaryPrimitives.ReadUInt64BigEndian(request.RequestBodyKey.AsSpan(0, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(request.RequestBodyKey.AsSpan(8, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(request.RequestBodyIv.AsSpan(0, 8)),
                BinaryPrimitives.ReadUInt64BigEndian(request.RequestBodyIv.AsSpan(8, 8)));
        }
    }
}

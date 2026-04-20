using System.Buffers.Binary;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class VmessAuthIdDecoderHolder
{
    private readonly Lock _sync = new();
    private readonly VmessAuthIdHistory _authIdHistory;

    private Snapshot _snapshot = Snapshot.Empty;

    public VmessAuthIdDecoderHolder()
        : this(new VmessAuthIdHistory())
    {
    }

    internal VmessAuthIdDecoderHolder(VmessAuthIdHistory authIdHistory)
    {
        _authIdHistory = authIdHistory ?? throw new ArgumentNullException(nameof(authIdHistory));
    }

    public void AddUser(VmessUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (user.CmdKey.Length != 16)
        {
            return;
        }

        var item = CreateItem(user);
        var key = DecoderKey.Create(item.Decoder.AuthIdKey);

        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            var byKey = new Dictionary<DecoderKey, VmessAuthIdDecoderItem>(snapshot.ByKey);
            byKey[key] = item;
            Volatile.Write(ref _snapshot, CreateSnapshot(byKey.Values));
        }
    }

    public void RemoveUser(ReadOnlySpan<byte> cmdKey)
    {
        if (cmdKey.Length != 16)
        {
            return;
        }

        var key = DecoderKey.Create(VmessAuthIdMatcher.DeriveAuthIdKey(cmdKey));
        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            if (!snapshot.ByKey.ContainsKey(key))
            {
                return;
            }

            Volatile.Write(
                ref _snapshot,
                CreateSnapshot(snapshot.Decoders.Where(item => DecoderKey.Create(item.Decoder.AuthIdKey) != key)));
        }
    }

    public void Replace(IEnumerable<VmessUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            Volatile.Write(
                ref _snapshot,
                CreateSnapshot(
                    users
                        .Where(static user => user is not null && user.CmdKey.Length == 16)
                        .Select(CreateItem)));
        }
    }

    public bool TryMatchUser(
        ReadOnlySpan<byte> authId,
        out VmessUser? user,
        out Exception? error)
    {
        var decoders = Volatile.Read(ref _snapshot).Decoders;
        for (var index = 0; index < decoders.Count; index++)
        {
            var decoder = decoders[index];
            var outcome = decoder.Decoder.Match(authId, _authIdHistory);
            switch (outcome)
            {
                case VmessAuthIdMatchOutcome.InvalidChecksum:
                    continue;

                case VmessAuthIdMatchOutcome.Valid:
                    user = decoder.User;
                    error = null;
                    return true;

                default:
                    user = null;
                    error = VmessAuthIdMatcher.CreateException(outcome);
                    return false;
            }
        }

        user = null;
        error = VmessAuthIdMatcher.CreateException(VmessAuthIdMatchOutcome.InvalidChecksum);
        return false;
    }

    private static Snapshot CreateSnapshot(IEnumerable<VmessAuthIdDecoderItem> items)
    {
        var decoders = items
            .Where(static item => item.User is not null && item.User.CmdKey.Length == 16)
            .ToArray();
        var byKey = new Dictionary<DecoderKey, VmessAuthIdDecoderItem>(decoders.Length);
        foreach (var item in decoders)
        {
            byKey[DecoderKey.Create(item.Decoder.AuthIdKey)] = item;
        }

        return new Snapshot(decoders, byKey);
    }

    private static VmessAuthIdDecoderItem CreateItem(VmessUser user)
        => new(new VmessAuthIdDecoder(user.CmdKey), user);

    private sealed record Snapshot(
        IReadOnlyList<VmessAuthIdDecoderItem> Decoders,
        IReadOnlyDictionary<DecoderKey, VmessAuthIdDecoderItem> ByKey)
    {
        public static readonly Snapshot Empty = new(
            Array.Empty<VmessAuthIdDecoderItem>(),
            new Dictionary<DecoderKey, VmessAuthIdDecoderItem>());
    }

    private readonly record struct DecoderKey(ulong High, ulong Low)
    {
        public static DecoderKey Create(ReadOnlySpan<byte> authIdKey)
        {
            if (authIdKey.Length < 16)
            {
                throw new ArgumentOutOfRangeException(nameof(authIdKey), "VMess auth id key must be 16 bytes.");
            }

            return new DecoderKey(
                BinaryPrimitives.ReadUInt64BigEndian(authIdKey[..8]),
                BinaryPrimitives.ReadUInt64BigEndian(authIdKey[8..16]));
        }
    }

    private sealed record VmessAuthIdDecoderItem(VmessAuthIdDecoder Decoder, VmessUser User);
}

internal sealed class VmessAuthIdDecoder
{
    public byte[] AuthIdKey { get; }

    public VmessAuthIdDecoder(ReadOnlySpan<byte> cmdKey)
    {
        AuthIdKey = VmessAuthIdMatcher.DeriveAuthIdKey(cmdKey);
    }

    public VmessAuthIdMatchOutcome Match(ReadOnlySpan<byte> authId, VmessAuthIdHistory authIdHistory)
        => VmessAuthIdMatcher.Match(authId, AuthIdKey, authIdHistory);
}

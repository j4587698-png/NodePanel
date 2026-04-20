using System.Security.Cryptography;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class ShadowsocksInboundRuntimeState
{
    private readonly Lock _sync = new();
    private ShadowsocksInboundUserValidator _userValidator;

    public ShadowsocksInboundRuntimeState(IReadOnlyList<ShadowsocksUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);
        _userValidator = new ShadowsocksInboundUserValidator(users);
    }

    internal void BindUserValidator(ShadowsocksInboundUserValidator userValidator)
    {
        ArgumentNullException.ThrowIfNull(userValidator);

        lock (_sync)
        {
            _userValidator = userValidator;
        }
    }

    internal bool TryMatchTcpUser(
        ReadOnlySpan<byte> initialPayload,
        out ShadowsocksUser? user,
        out ShadowsocksAccount? account)
        => Volatile.Read(ref _userValidator).TryMatchTcpUser(initialPayload, out user, out account);

    internal bool TryDecodeUdpPacket(
        ReadOnlySpan<byte> payload,
        out ShadowsocksUser? user,
        out ShadowsocksAccount? account,
        out ShadowsocksUdpPacket? packet)
        => Volatile.Read(ref _userValidator).TryDecodeUdpPacket(payload, out user, out account, out packet);
}

internal sealed class ShadowsocksInboundUserValidator
{
    private readonly Lock _sync = new();

    private Snapshot _snapshot = Snapshot.Empty;

    public ShadowsocksInboundUserValidator(IReadOnlyList<ShadowsocksUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);
        Replace(users);
    }

    public int Count => Volatile.Read(ref _snapshot).CompiledUsers.Count;

    public IReadOnlyList<ShadowsocksUser> GetUsers()
        => Volatile.Read(ref _snapshot).TypedUsers;

    public bool TryGetUser(string userId, out ShadowsocksUser? user)
    {
        if (Volatile.Read(ref _snapshot).ByUserId.TryGetValue(NormalizeUserId(userId), out var compiledUser))
        {
            user = compiledUser.User;
            return true;
        }

        user = null;
        return false;
    }

    public void AddUser(ShadowsocksUser user)
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

    public void Replace(IEnumerable<ShadowsocksUser> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            Volatile.Write(ref _snapshot, CreateSnapshot(users));
        }
    }

    public bool TryMatchTcpUser(
        ReadOnlySpan<byte> initialPayload,
        out ShadowsocksUser? user,
        out ShadowsocksAccount? account)
    {
        foreach (var compiledUser in Volatile.Read(ref _snapshot).CompiledUsers)
        {
            if (!compiledUser.Account.IsAead)
            {
                user = compiledUser.User;
                account = compiledUser.Account;
                return true;
            }

            if (initialPayload.Length < compiledUser.Account.SaltSize + 18)
            {
                continue;
            }

            try
            {
                using var session = compiledUser.Account.CreateAeadSession(initialPayload[..compiledUser.Account.SaltSize]);
                var encryptedSizeFrame = initialPayload.Slice(compiledUser.Account.SaltSize, session.EncryptedSizeBytes);
                var encryptedPayloadSize = session.DecryptSize(encryptedSizeFrame);
                if (encryptedPayloadSize < session.TagSize ||
                    encryptedPayloadSize > 8192)
                {
                    continue;
                }

                user = compiledUser.User;
                account = compiledUser.Account;
                return true;
            }
            catch (CryptographicException)
            {
            }
            catch (InvalidDataException)
            {
            }
        }

        user = null;
        account = null;
        return false;
    }

    public bool TryDecodeUdpPacket(
        ReadOnlySpan<byte> payload,
        out ShadowsocksUser? user,
        out ShadowsocksAccount? account,
        out ShadowsocksUdpPacket? packet)
    {
        foreach (var compiledUser in Volatile.Read(ref _snapshot).CompiledUsers)
        {
            try
            {
                packet = ShadowsocksProtocolCodec.DecodeUdpPacket(compiledUser.Account, payload);
                user = compiledUser.User;
                account = compiledUser.Account;
                return true;
            }
            catch (CryptographicException)
            {
            }
            catch (InvalidDataException)
            {
            }
        }

        user = null;
        account = null;
        packet = null;
        return false;
    }

    private static Snapshot CreateSnapshot(IEnumerable<ShadowsocksUser> users)
    {
        var compiledUsers = new List<CompiledShadowsocksUser>();
        var byUserId = new Dictionary<string, CompiledShadowsocksUser>(StringComparer.Ordinal);

        foreach (var user in users.Where(static user => user is not null))
        {
            var compiledUser = CompileUser(user);
            if (!compiledUser.Account.IsAead && compiledUsers.Count > 0)
            {
                throw new InvalidOperationException("Shadowsocks cipher 'none' does not support multi-user on the same inbound.");
            }

            compiledUsers.Add(compiledUser);
            byUserId[NormalizeUserId(compiledUser.User.UserId)] = compiledUser;
        }

        return new Snapshot(
            compiledUsers.Select(static item => item.User).ToArray(),
            compiledUsers.ToArray(),
            byUserId);
    }

    private static CompiledShadowsocksUser CompileUser(ShadowsocksUser user)
    {
        var normalizedUserId = NormalizeUserId(user.UserId);
        if (normalizedUserId.Length == 0)
        {
            throw new InvalidOperationException("Shadowsocks user requires a non-empty user id.");
        }

        var normalizedCipher = ShadowsocksCipherTypes.Normalize(user.Cipher);
        if (normalizedCipher.Length == 0)
        {
            throw new InvalidOperationException("Shadowsocks user requires a cipher.");
        }

        var password = user.Password?.Trim() ?? string.Empty;
        var account = ShadowsocksAccount.Create(normalizedCipher, password);
        return new CompiledShadowsocksUser(
            user with
            {
                UserId = normalizedUserId,
                Cipher = normalizedCipher,
                Password = password,
                RuntimeKey = string.IsNullOrWhiteSpace(user.RuntimeKey)
                    ? normalizedUserId
                    : user.RuntimeKey.Trim(),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            },
            account);
    }

    private static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();

    private sealed record CompiledShadowsocksUser(
        ShadowsocksUser User,
        ShadowsocksAccount Account);

    private sealed record Snapshot(
        IReadOnlyList<ShadowsocksUser> TypedUsers,
        IReadOnlyList<CompiledShadowsocksUser> CompiledUsers,
        IReadOnlyDictionary<string, CompiledShadowsocksUser> ByUserId)
    {
        public static readonly Snapshot Empty = new(
            Array.Empty<ShadowsocksUser>(),
            Array.Empty<CompiledShadowsocksUser>(),
            new Dictionary<string, CompiledShadowsocksUser>(StringComparer.Ordinal));
    }
}

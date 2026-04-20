using System.Security.Cryptography;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal sealed class Shadowsocks2022InboundRuntimeState
{
    public static Shadowsocks2022InboundRuntimeState Empty { get; } = new(
        string.Empty,
        string.Empty,
        string.Empty,
        Array.Empty<Shadowsocks2022User>());

    private readonly Lock _sync = new();
    private Shadowsocks2022InboundUserValidator _userValidator;

    public Shadowsocks2022InboundRuntimeState(
        string method,
        string key,
        string mode,
        IReadOnlyList<Shadowsocks2022User> users)
    {
        ArgumentNullException.ThrowIfNull(users);
        _userValidator = new Shadowsocks2022InboundUserValidator(method, key, mode, users);
    }

    internal void BindUserValidator(Shadowsocks2022InboundUserValidator userValidator)
    {
        ArgumentNullException.ThrowIfNull(userValidator);

        lock (_sync)
        {
            _userValidator = userValidator;
        }
    }

    internal bool TryMatchTcpUser(
        ReadOnlySpan<byte> initialPayload,
        out Shadowsocks2022User? user,
        out Shadowsocks2022Account? account)
        => Volatile.Read(ref _userValidator).TryMatchTcpUser(initialPayload, out user, out account);

    internal int GetMinimumTcpProbeBytes()
        => Volatile.Read(ref _userValidator).GetMinimumTcpProbeBytes();

    internal bool TryDecodeUdpPacket(
        ReadOnlySpan<byte> payload,
        out Shadowsocks2022User? user,
        out Shadowsocks2022Account? account,
        out ShadowsocksUdpPacket? packet)
        => Volatile.Read(ref _userValidator).TryDecodeUdpPacket(payload, out user, out account, out packet);
}

internal sealed class Shadowsocks2022InboundUserValidator
{
    private readonly Lock _sync = new();

    private Snapshot _snapshot = Snapshot.Empty;

    public Shadowsocks2022InboundUserValidator(
        string method,
        string key,
        string mode,
        IReadOnlyList<Shadowsocks2022User> users)
    {
        ArgumentNullException.ThrowIfNull(users);
        Replace(method, key, mode, users);
    }

    public int Count => Volatile.Read(ref _snapshot).TypedUsers.Count;

    public IReadOnlyList<Shadowsocks2022User> GetUsers()
        => Volatile.Read(ref _snapshot).TypedUsers;

    public int GetMinimumTcpProbeBytes()
    {
        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.SingleUser is { } singleUser)
        {
            return singleUser.Account.SaltSize + singleUser.Account.IdentityHeaderLength + 18;
        }

        if (snapshot.ManagedUsers is { } managedUsers)
        {
            return managedUsers.MaximumTcpProbeBytes;
        }

        return 64;
    }

    public bool TryGetUser(string userId, out Shadowsocks2022User? user)
    {
        if (Volatile.Read(ref _snapshot).ByUserId.TryGetValue(NormalizeUserId(userId), out var resolved))
        {
            user = resolved;
            return true;
        }

        user = null;
        return false;
    }

    public void AddUser(Shadowsocks2022User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        lock (_sync)
        {
            var snapshot = Volatile.Read(ref _snapshot);
            Volatile.Write(
                ref _snapshot,
                CreateSnapshot(
                    snapshot.Method,
                    snapshot.Key,
                    snapshot.Mode,
                    [.. snapshot.TypedUsers, user]));
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
                CreateSnapshot(
                    snapshot.Method,
                    snapshot.Key,
                    snapshot.Mode,
                    snapshot.TypedUsers.Where(user => !string.Equals(user.UserId, normalizedUserId, StringComparison.Ordinal))));
            return true;
        }
    }

    public void Replace(
        string method,
        string key,
        string mode,
        IEnumerable<Shadowsocks2022User> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            Volatile.Write(ref _snapshot, CreateSnapshot(method, key, mode, users));
        }
    }

    public bool TryMatchTcpUser(
        ReadOnlySpan<byte> initialPayload,
        out Shadowsocks2022User? user,
        out Shadowsocks2022Account? account)
    {
        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.SingleUser is { } singleUser)
        {
            return TryMatchTcpAccount(
                initialPayload,
                singleUser.User,
                singleUser.Account,
                singleUser.Account.SaltSize,
                out user,
                out account);
        }

        if (snapshot.ManagedUsers is not { } managedUsers ||
            initialPayload.Length < managedUsers.MinimumTcpProbeBytes)
        {
            user = null;
            account = null;
            return false;
        }

        try
        {
            var salt = initialPayload[..managedUsers.ServerAccount.SaltSize];
            var leadingIdentityHeader = initialPayload.Slice(
                managedUsers.ServerAccount.SaltSize,
                Shadowsocks2022Account.IdentityHeaderBytes);
            if (!managedUsers.ServerAccount.TryReadLeadingIdentityHeader(salt, leadingIdentityHeader, out var identityHash) ||
                !managedUsers.ByFirstIdentityHash.TryGetValue(Shadowsocks2022InboundGraphCompiler.ToIdentityKey(identityHash), out var candidates))
            {
                user = null;
                account = null;
                return false;
            }

            foreach (var candidate in candidates)
            {
                if (initialPayload.Length < candidate.Account.SaltSize + candidate.Account.IdentityHeaderLength + 18)
                {
                    continue;
                }

                var identityHeader = initialPayload.Slice(
                    candidate.Account.SaltSize,
                    candidate.Account.IdentityHeaderLength);
                if (!candidate.Account.TryReadIdentityHeader(salt, identityHeader, out _))
                {
                    continue;
                }

                if (TryMatchTcpAccount(
                    initialPayload,
                    candidate.User,
                    candidate.Account,
                    candidate.Account.SaltSize + candidate.Account.IdentityHeaderLength,
                    out user,
                    out account))
                {
                    return true;
                }
            }
        }
        catch (CryptographicException)
        {
        }
        catch (InvalidDataException)
        {
        }

        user = null;
        account = null;
        return false;
    }

    public bool TryDecodeUdpPacket(
        ReadOnlySpan<byte> payload,
        out Shadowsocks2022User? user,
        out Shadowsocks2022Account? account,
        out ShadowsocksUdpPacket? packet)
    {
        var snapshot = Volatile.Read(ref _snapshot);
        if (snapshot.SingleUser is { } singleUser)
        {
            try
            {
                packet = Shadowsocks2022ProtocolCodec.DecodeUdpPacket(singleUser.Account, payload);
                user = singleUser.User;
                account = singleUser.Account;
                return true;
            }
            catch (CryptographicException)
            {
            }
            catch (InvalidDataException)
            {
            }
        }

        if (snapshot.ManagedUsers is { } managedUsers &&
            payload.Length > managedUsers.MinimumUdpProbeBytes)
        {
            try
            {
                var salt = payload[..managedUsers.ServerAccount.SaltSize];
                var leadingIdentityHeader = payload.Slice(
                    managedUsers.ServerAccount.SaltSize,
                    Shadowsocks2022Account.IdentityHeaderBytes);
                if (managedUsers.ServerAccount.TryReadLeadingIdentityHeader(salt, leadingIdentityHeader, out var identityHash) &&
                    managedUsers.ByFirstIdentityHash.TryGetValue(Shadowsocks2022InboundGraphCompiler.ToIdentityKey(identityHash), out var candidates))
                {
                    foreach (var candidate in candidates)
                    {
                        try
                        {
                            packet = Shadowsocks2022ProtocolCodec.DecodeUdpPacket(candidate.Account, payload);
                            user = candidate.User;
                            account = candidate.Account;
                            return true;
                        }
                        catch (CryptographicException)
                        {
                        }
                        catch (InvalidDataException)
                        {
                        }
                    }
                }
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

    private static Snapshot CreateSnapshot(
        string method,
        string key,
        string mode,
        IEnumerable<Shadowsocks2022User> users)
    {
        var graph = Shadowsocks2022InboundGraphCompiler.Compile(method, key, mode, users);
        return new Snapshot(
            graph.Method,
            graph.Key,
            graph.Mode,
            graph.TypedUsers,
            graph.ByUserId,
            graph.SingleUser,
            graph.ManagedUsers);
    }

    private static string NormalizeUserId(string? userId)
        => Shadowsocks2022UserCompiler.NormalizeUserId(userId);

    private static bool TryMatchTcpAccount(
        ReadOnlySpan<byte> initialPayload,
        Shadowsocks2022User user,
        Shadowsocks2022Account account,
        int encryptedSizeOffset,
        out Shadowsocks2022User? resolvedUser,
        out Shadowsocks2022Account? resolvedAccount)
    {
        if (initialPayload.Length < encryptedSizeOffset + 18)
        {
            resolvedUser = null;
            resolvedAccount = null;
            return false;
        }

        try
        {
            using var session = account.CreateAeadSession(initialPayload[..account.SaltSize]);
            var encryptedSizeFrame = initialPayload.Slice(encryptedSizeOffset, session.EncryptedSizeBytes);
            var encryptedPayloadSize = session.DecryptSize(encryptedSizeFrame);
            if (encryptedPayloadSize < session.TagSize ||
                encryptedPayloadSize > 8192)
            {
                resolvedUser = null;
                resolvedAccount = null;
                return false;
            }

            resolvedUser = user;
            resolvedAccount = account;
            return true;
        }
        catch (CryptographicException)
        {
        }
        catch (InvalidDataException)
        {
        }

        resolvedUser = null;
        resolvedAccount = null;
        return false;
    }

    private sealed record Snapshot(
        string Method,
        string Key,
        string Mode,
        IReadOnlyList<Shadowsocks2022User> TypedUsers,
        IReadOnlyDictionary<string, Shadowsocks2022User> ByUserId,
        Shadowsocks2022CompiledSingleUserState? SingleUser,
        Shadowsocks2022CompiledManagedUserState? ManagedUsers)
    {
        public static readonly Snapshot Empty = new(
            string.Empty,
            string.Empty,
            string.Empty,
            Array.Empty<Shadowsocks2022User>(),
            new Dictionary<string, Shadowsocks2022User>(StringComparer.Ordinal),
            null,
            null);
    }
}

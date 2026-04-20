using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

internal static class Shadowsocks2022InboundGraphCompiler
{
    public static Shadowsocks2022CompiledInboundGraph Compile(
        string method,
        string key,
        string mode,
        IEnumerable<Shadowsocks2022User> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        var normalizedMethod = Shadowsocks2022UserCompiler.NormalizeMethod(method);
        var normalizedKey = Shadowsocks2022UserCompiler.NormalizeKey(key);
        var normalizedMode = Shadowsocks2022UserCompiler.NormalizeMode(mode);
        var compiledUsers = new List<Shadowsocks2022User>();
        var byUserId = new Dictionary<string, Shadowsocks2022User>(StringComparer.Ordinal);

        foreach (var user in users.Where(static user => user is not null))
        {
            var compiledUser = Shadowsocks2022UserCompiler.CompileRuntimeUserOrThrow(
                normalizedMode,
                normalizedKey,
                user,
                static userId => userId);
            compiledUsers.Add(compiledUser);
            byUserId[compiledUser.UserId] = compiledUser;
        }

        Shadowsocks2022CompiledSingleUserState? singleUser = null;
        Shadowsocks2022CompiledManagedUserState? managedUsers = null;
        if (Shadowsocks2022UserCompiler.IsSingleUserMode(normalizedMode))
        {
            if (compiledUsers.Count > 1)
            {
                throw new InvalidOperationException("Shadowsocks 2022 single-user inbound does not support multiple users.");
            }

            if (compiledUsers.Count == 1 &&
                normalizedMethod.Length > 0 &&
                normalizedKey.Length > 0)
            {
                singleUser = new Shadowsocks2022CompiledSingleUserState(
                    compiledUsers[0],
                    Shadowsocks2022Account.Create(normalizedMethod, normalizedKey));
            }
        }
        else if (Shadowsocks2022UserCompiler.UsesManagedUsers(normalizedMode) &&
                 compiledUsers.Count > 0 &&
                 !ShadowsocksCipherTypes.Supports2022MultiUser(normalizedMethod))
        {
            throw new InvalidOperationException("Shadowsocks 2022 multi-user and relay modes require 2022-blake3-aes-*-gcm methods.");
        }

        if (Shadowsocks2022UserCompiler.UsesManagedUsers(normalizedMode) &&
            compiledUsers.Count > 0)
        {
            managedUsers = BuildManagedUserState(normalizedMethod, normalizedKey, compiledUsers);
        }

        return new Shadowsocks2022CompiledInboundGraph(
            normalizedMethod,
            normalizedKey,
            normalizedMode,
            compiledUsers.ToArray(),
            byUserId,
            singleUser,
            managedUsers);
    }

    public static string ToIdentityKey(ReadOnlySpan<byte> identityHash)
        => Convert.ToHexString(identityHash);

    private static Shadowsocks2022CompiledManagedUserState BuildManagedUserState(
        string method,
        string key,
        IReadOnlyList<Shadowsocks2022User> users)
    {
        Shadowsocks2022UserCompiler.ValidateManagedUserServerKeyOrThrow(key);

        var byFirstIdentityHash = new Dictionary<string, List<Shadowsocks2022CompiledManagedUserEntry>>(StringComparer.Ordinal);
        var byCompositeKey = new HashSet<string>(StringComparer.Ordinal);
        var serverAccount = Shadowsocks2022Account.Create(method, key);
        foreach (var user in users)
        {
            var compositeKey = key + ":" + user.Password;
            if (!byCompositeKey.Add(compositeKey))
            {
                throw new InvalidOperationException("Shadowsocks 2022 inbound contains duplicate per-user keys.");
            }

            var account = Shadowsocks2022Account.Create(method, compositeKey);
            var identityKey = ToIdentityKey(account.FirstIdentityHash);
            if (!byFirstIdentityHash.TryGetValue(identityKey, out var entries))
            {
                entries = [];
                byFirstIdentityHash[identityKey] = entries;
            }

            entries.Add(new Shadowsocks2022CompiledManagedUserEntry(user, account));
        }

        var compiledEntries = new Dictionary<string, IReadOnlyList<Shadowsocks2022CompiledManagedUserEntry>>(StringComparer.Ordinal);
        foreach (var (identityKey, entries) in byFirstIdentityHash)
        {
            compiledEntries[identityKey] = entries.ToArray();
        }

        return new Shadowsocks2022CompiledManagedUserState(serverAccount, compiledEntries);
    }
}

internal sealed record Shadowsocks2022CompiledInboundGraph(
    string Method,
    string Key,
    string Mode,
    IReadOnlyList<Shadowsocks2022User> TypedUsers,
    IReadOnlyDictionary<string, Shadowsocks2022User> ByUserId,
    Shadowsocks2022CompiledSingleUserState? SingleUser,
    Shadowsocks2022CompiledManagedUserState? ManagedUsers);

internal sealed record Shadowsocks2022CompiledSingleUserState(
    Shadowsocks2022User User,
    Shadowsocks2022Account Account);

internal sealed record Shadowsocks2022CompiledManagedUserEntry(
    Shadowsocks2022User User,
    Shadowsocks2022Account Account);

internal sealed record Shadowsocks2022CompiledManagedUserState(
    Shadowsocks2022Account ServerAccount,
    IReadOnlyDictionary<string, IReadOnlyList<Shadowsocks2022CompiledManagedUserEntry>> ByFirstIdentityHash)
{
    public int MinimumTcpProbeBytes => ServerAccount.SaltSize + Shadowsocks2022Account.IdentityHeaderBytes + 18;

    public int MinimumUdpProbeBytes => ServerAccount.SaltSize + Shadowsocks2022Account.IdentityHeaderBytes;

    public int MaximumTcpProbeBytes
        => Math.Max(
            MinimumTcpProbeBytes,
            ByFirstIdentityHash.Count == 0
                ? MinimumTcpProbeBytes
                : ByFirstIdentityHash.Values
                    .SelectMany(static entries => entries)
                    .Max(static entry => entry.Account.SaltSize + entry.Account.IdentityHeaderLength + 18));
}

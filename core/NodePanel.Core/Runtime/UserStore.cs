using NodePanel.Core.Cryptography;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public interface IRuntimeUserStore
{
    int KnownUsers { get; }

    IReadOnlyList<IRuntimeUserDefinition> GetUsers();

    IReadOnlyList<IRuntimeUserDefinition> GetUsers(string protocol, string inboundTag);

    int GetUsersCount(string protocol, string inboundTag);

    bool TryGetUser(string protocol, string inboundTag, string userId, out IRuntimeUserDefinition? user);

    void AddUser(string protocol, string inboundTag, IRuntimeUserDefinition user);

    bool RemoveUser(string protocol, string inboundTag, string userId);

    void Replace(IReadOnlyList<IRuntimeUserDefinition> users);
}

internal interface IRuntimeUserStoreController
{
    void Reset(RuntimePlan plan);
}

public sealed class UserStore :
    IRuntimeUserStore,
    IRuntimeUserStoreController
{
    private readonly Lock _sync = new();

    private GlobalUserSnapshot _globalSnapshot = GlobalUserSnapshot.Empty;
    private ScopedRegistrySnapshot _scopedSnapshot = ScopedRegistrySnapshot.Empty;

    public int KnownUsers => Volatile.Read(ref _globalSnapshot).Users.Count;

    public IReadOnlyList<IRuntimeUserDefinition> GetUsers()
        => Volatile.Read(ref _globalSnapshot).Users;

    public IReadOnlyList<IRuntimeUserDefinition> GetUsers(string protocol, string inboundTag)
    {
        return TryGetRegistry(protocol, inboundTag, out var registry)
            ? registry.GetUsers()
            : Array.Empty<IRuntimeUserDefinition>();
    }

    public int GetUsersCount(string protocol, string inboundTag)
    {
        return TryGetRegistry(protocol, inboundTag, out var registry)
            ? registry.Count
            : 0;
    }

    public bool TryGetUser(string protocol, string inboundTag, string userId, out IRuntimeUserDefinition? user)
    {
        if (TryGetRegistry(protocol, inboundTag, out var registry))
        {
            return registry.TryGetUser(userId, out user);
        }

        user = null;
        return false;
    }

    public void AddUser(string protocol, string inboundTag, IRuntimeUserDefinition user)
    {
        ArgumentNullException.ThrowIfNull(user);

        lock (_sync)
        {
            var registry = GetRequiredRegistry(protocol, inboundTag);
            registry.AddUser(user);
            RefreshGlobalSnapshot();
        }
    }

    public bool RemoveUser(string protocol, string inboundTag, string userId)
    {
        lock (_sync)
        {
            if (!TryGetRegistry(protocol, inboundTag, out var registry) ||
                !registry.RemoveUser(userId))
            {
                return false;
            }

            RefreshGlobalSnapshot();
            return true;
        }
    }

    public void Replace(IReadOnlyList<IRuntimeUserDefinition> users)
    {
        ArgumentNullException.ThrowIfNull(users);

        lock (_sync)
        {
            Volatile.Write(ref _scopedSnapshot, ScopedRegistrySnapshot.Empty);
            Volatile.Write(ref _globalSnapshot, CreateGlobalSnapshot(users));
        }
    }

    void IRuntimeUserStoreController.Reset(RuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        lock (_sync)
        {
            var registries = new Dictionary<string, RuntimeInboundUserRegistry>(StringComparer.OrdinalIgnoreCase);

            SeedTrojanRegistries(plan, registries);
            SeedShadowsocksRegistries(plan, registries);
            SeedVlessRegistries(plan, registries);
            SeedVmessRegistries(plan, registries);

            Volatile.Write(ref _scopedSnapshot, new ScopedRegistrySnapshot(registries));
            RefreshGlobalSnapshot();
        }
    }

    private void SeedTrojanRegistries(
        RuntimePlan plan,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        var trojanPlan = plan.Plan.Inbounds.GetOrDefault(InboundProtocols.Trojan, TrojanInboundRuntimePlan.Empty);
        foreach (var listener in trojanPlan.Listeners)
        {
            foreach (var inbound in listener.Inbounds)
            {
                SeedTrojanRegistry(inbound, registries);
            }
        }
    }

    private static void SeedTrojanRegistry(
        TrojanTlsInboundRuntime? inbound,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        if (inbound is null)
        {
            return;
        }

        var registry = new TrojanInboundUserRegistry(inbound.Tag);
        registry.Replace(inbound.UsersByHash.Values);
        inbound.RuntimeState.BindUserValidator(registry.UserValidator);
        registries[CreateRegistryKey(InboundProtocols.Trojan, inbound.Tag)] = registry;
    }

    private void SeedShadowsocksRegistries(
        RuntimePlan plan,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        var shadowsocksPlan = plan.Plan.Inbounds.GetOrDefault(InboundProtocols.Shadowsocks, ShadowsocksInboundRuntimePlan.Empty);
        foreach (var inbound in shadowsocksPlan.Inbounds)
        {
            SeedShadowsocksRegistry(inbound, registries);
        }

        foreach (var inbound in shadowsocksPlan.Inbounds2022)
        {
            SeedShadowsocks2022Registry(inbound, registries);
        }
    }

    private static void SeedShadowsocksRegistry(
        ShadowsocksInboundRuntime inbound,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        var registry = new ShadowsocksInboundUserRegistry(inbound.Tag);
        registry.Replace(inbound.Users);
        inbound.RuntimeState.BindUserValidator(registry.UserValidator);
        registries[CreateRegistryKey(InboundProtocols.Shadowsocks, inbound.Tag)] = registry;
    }

    private static void SeedShadowsocks2022Registry(
        Shadowsocks2022InboundRuntime inbound,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        var registry = new Shadowsocks2022InboundUserRegistry(
            inbound.Tag,
            inbound.Method,
            inbound.Key,
            inbound.Mode);
        registry.Replace(inbound.Users);
        inbound.RuntimeState.BindUserValidator(registry.UserValidator);
        registries[CreateRegistryKey(InboundProtocols.Shadowsocks, inbound.Tag)] = registry;
    }

    private void SeedVlessRegistries(
        RuntimePlan plan,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        var vlessPlan = plan.Plan.Inbounds.GetOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty);
        foreach (var listener in vlessPlan.Listeners)
        {
            foreach (var inbound in listener.Inbounds)
            {
                SeedVlessRegistry(inbound, registries);
            }
        }
    }

    private static void SeedVlessRegistry(
        VlessTlsInboundRuntime? inbound,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        if (inbound is null)
        {
            return;
        }

        var registry = new VlessInboundUserRegistry(inbound.Tag);
        registry.Replace(inbound.UsersByUuid.Values);
        inbound.RuntimeState.BindUserValidator(registry.UserValidator);
        registries[CreateRegistryKey(InboundProtocols.Vless, inbound.Tag)] = registry;
    }

    private void SeedVmessRegistries(
        RuntimePlan plan,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        var vmessPlan = plan.Plan.Inbounds.GetOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty);
        foreach (var listener in vmessPlan.Listeners)
        {
            foreach (var inbound in listener.Inbounds)
            {
                SeedVmessRegistry(inbound, registries);
            }
        }
    }

    private static void SeedVmessRegistry(
        VmessTlsInboundRuntime? inbound,
        IDictionary<string, RuntimeInboundUserRegistry> registries)
    {
        if (inbound is null)
        {
            return;
        }

        var registry = new VmessInboundUserRegistry(inbound.Tag);
        registry.Replace(inbound.Users);
        inbound.RuntimeState.BindUserValidator(registry.UserValidator);
        registries[CreateRegistryKey(InboundProtocols.Vmess, inbound.Tag)] = registry;
    }

    private void RefreshGlobalSnapshot()
    {
        var registries = Volatile.Read(ref _scopedSnapshot).Registries.Values;
        Volatile.Write(
            ref _globalSnapshot,
            CreateGlobalSnapshot(registries.SelectMany(static registry => registry.GetUsers())));
    }

    private bool TryGetRegistry(string protocol, string inboundTag, out RuntimeInboundUserRegistry registry)
    {
        var protocolKey = NormalizeProtocol(protocol);
        var inboundTagKey = NormalizeInboundTag(inboundTag);
        if (protocolKey.Length == 0 ||
            inboundTagKey.Length == 0)
        {
            registry = default!;
            return false;
        }

        return Volatile.Read(ref _scopedSnapshot).Registries.TryGetValue(
            CreateRegistryKey(protocolKey, inboundTagKey),
            out registry!);
    }

    private RuntimeInboundUserRegistry GetRequiredRegistry(string protocol, string inboundTag)
    {
        if (TryGetRegistry(protocol, inboundTag, out var registry))
        {
            return registry;
        }

        throw new InvalidOperationException(
            $"Inbound user registry '{NormalizeProtocol(protocol)}:{NormalizeInboundTag(inboundTag)}' does not exist.");
    }

    private static GlobalUserSnapshot CreateGlobalSnapshot(IEnumerable<IRuntimeUserDefinition> users)
    {
        var items = new List<IRuntimeUserDefinition>();
        var byUserId = new Dictionary<string, IRuntimeUserDefinition>(StringComparer.Ordinal);
        foreach (var user in users)
        {
            if (user is null ||
                string.IsNullOrWhiteSpace(user.UserId))
            {
                continue;
            }

            var normalizedUserId = user.UserId.Trim();
            items.Add(user);
            byUserId[normalizedUserId] = user;
        }

        return new GlobalUserSnapshot(
            items.ToArray(),
            byUserId);
    }

    private static string NormalizeProtocol(string? protocol)
        => string.IsNullOrWhiteSpace(protocol)
            ? string.Empty
            : protocol.Trim().ToLowerInvariant();

    private static string NormalizeInboundTag(string? inboundTag)
        => string.IsNullOrWhiteSpace(inboundTag)
            ? string.Empty
            : inboundTag.Trim();

    private static string CreateRegistryKey(string protocol, string inboundTag)
        => NormalizeProtocol(protocol) + "|" + NormalizeInboundTag(inboundTag);

    private sealed record GlobalUserSnapshot(
        IReadOnlyList<IRuntimeUserDefinition> Users,
        IReadOnlyDictionary<string, IRuntimeUserDefinition> ByUserId)
    {
        public static readonly GlobalUserSnapshot Empty = new(
            Array.Empty<IRuntimeUserDefinition>(),
            new Dictionary<string, IRuntimeUserDefinition>(StringComparer.Ordinal));
    }

    private sealed record ScopedRegistrySnapshot(
        IReadOnlyDictionary<string, RuntimeInboundUserRegistry> Registries)
    {
        public static readonly ScopedRegistrySnapshot Empty = new(
            new Dictionary<string, RuntimeInboundUserRegistry>(StringComparer.OrdinalIgnoreCase));
    }

    private abstract class RuntimeInboundUserRegistry
    {
        protected RuntimeInboundUserRegistry(string protocol, string inboundTag)
        {
            Protocol = NormalizeProtocol(protocol);
            InboundTag = NormalizeInboundTag(inboundTag);
        }

        public string Protocol { get; }

        public string InboundTag { get; }

        public abstract int Count { get; }

        public abstract IReadOnlyList<IRuntimeUserDefinition> GetUsers();

        public abstract bool TryGetUser(string userId, out IRuntimeUserDefinition? user);

        public abstract void AddUser(IRuntimeUserDefinition user);

        public abstract bool RemoveUser(string userId);
    }

    private sealed class TrojanInboundUserRegistry : RuntimeInboundUserRegistry
    {
        private readonly Lock _sync = new();
        private readonly TrojanUserValidator _userValidator = new(Array.Empty<TrojanUser>());

        public TrojanInboundUserRegistry(string inboundTag)
            : base(InboundProtocols.Trojan, inboundTag)
        {
        }

        public override int Count => _userValidator.Count;

        internal TrojanUserValidator UserValidator => _userValidator;

        public override IReadOnlyList<IRuntimeUserDefinition> GetUsers()
            => _userValidator.GetUsers().Cast<IRuntimeUserDefinition>().ToArray();

        public override bool TryGetUser(string userId, out IRuntimeUserDefinition? user)
        {
            if (_userValidator.TryGetUser(NormalizeUserId(userId), out var resolved))
            {
                user = resolved;
                return true;
            }

            user = null;
            return false;
        }

        public override void AddUser(IRuntimeUserDefinition user)
        {
            var compiled = CompileTrojanUser(user);

            lock (_sync)
            {
                if (_userValidator.TryGetUser(compiled.UserId, out _))
                {
                    throw new InvalidOperationException($"Trojan user '{compiled.UserId}' already exists on inbound '{InboundTag}'.");
                }

                if (_userValidator.TryGetUserByHash(compiled.PasswordHash, out _))
                {
                    throw new InvalidOperationException($"Trojan password hash already exists on inbound '{InboundTag}'.");
                }

                _userValidator.AddUser(compiled);
            }
        }

        public override bool RemoveUser(string userId)
        {
            var normalizedUserId = NormalizeUserId(userId);
            if (normalizedUserId.Length == 0)
            {
                return false;
            }

            lock (_sync)
            {
                return _userValidator.RemoveUser(normalizedUserId);
            }
        }

        public void Replace(IEnumerable<TrojanUser> users)
        {
            ArgumentNullException.ThrowIfNull(users);

            lock (_sync)
            {
                _userValidator.Replace(CompileTrojanUsers(users));
            }
        }

        private TrojanUser[] CompileTrojanUsers(IEnumerable<TrojanUser> users)
            => users
                .Where(static user => user is not null)
                .Select(CompileTrojanUser)
                .ToArray();

        private TrojanUser CompileTrojanUser(IRuntimeUserDefinition user)
        {
            return user switch
            {
                TrojanUser trojanUser => CreateTrojanRuntimeUser(
                    trojanUser.UserId,
                    trojanUser.PasswordHash,
                    trojanUser.Level,
                    trojanUser.BytesPerSecond,
                    trojanUser.DeviceLimit,
                    string.IsNullOrWhiteSpace(trojanUser.RuntimeKey)
                        ? RuntimeUserKeys.Create(Protocol, InboundTag, trojanUser.UserId)
                        : trojanUser.RuntimeKey),
                ITrojanUserDefinition trojanDefinition => CreateTrojanRuntimeUser(
                    trojanDefinition.UserId,
                    TrojanPassword.ComputeHash(trojanDefinition.Password.Trim()),
                    trojanDefinition.Level,
                    trojanDefinition.BytesPerSecond,
                    trojanDefinition.DeviceLimit,
                    RuntimeUserKeys.Create(Protocol, InboundTag, trojanDefinition.UserId)),
                _ => throw new InvalidOperationException("Trojan inbound requires a trojan-compatible user definition.")
            };
        }

        private static TrojanUser CreateTrojanRuntimeUser(
            string userId,
            string passwordHash,
            int level,
            long bytesPerSecond,
            int deviceLimit,
            string runtimeKey)
        {
            var normalizedUserId = NormalizeUserId(userId);
            var normalizedPasswordHash = NormalizeTrojanHash(passwordHash);
            if (normalizedUserId.Length == 0 ||
                normalizedPasswordHash.Length == 0)
            {
                throw new InvalidOperationException("Trojan user requires a non-empty user id and password hash.");
            }

            return new TrojanUser
            {
                UserId = normalizedUserId,
                PasswordHash = normalizedPasswordHash,
                RuntimeKey = string.IsNullOrWhiteSpace(runtimeKey) ? normalizedUserId : runtimeKey.Trim(),
                Level = Math.Max(0, level),
                BytesPerSecond = Math.Max(0, bytesPerSecond),
                DeviceLimit = Math.Max(0, deviceLimit)
            };
        }

    }

    private sealed class ShadowsocksInboundUserRegistry : RuntimeInboundUserRegistry
    {
        private readonly Lock _sync = new();
        private readonly ShadowsocksInboundUserValidator _userValidator = new(Array.Empty<ShadowsocksUser>());

        public ShadowsocksInboundUserRegistry(string inboundTag)
            : base(InboundProtocols.Shadowsocks, inboundTag)
        {
        }

        public override int Count => _userValidator.Count;

        internal ShadowsocksInboundUserValidator UserValidator => _userValidator;

        public override IReadOnlyList<IRuntimeUserDefinition> GetUsers()
            => _userValidator.GetUsers().Cast<IRuntimeUserDefinition>().ToArray();

        public override bool TryGetUser(string userId, out IRuntimeUserDefinition? user)
        {
            if (_userValidator.TryGetUser(NormalizeUserId(userId), out var resolved))
            {
                user = resolved;
                return true;
            }

            user = null;
            return false;
        }

        public override void AddUser(IRuntimeUserDefinition user)
        {
            var compiled = CompileShadowsocksUser(user);

            lock (_sync)
            {
                if (_userValidator.TryGetUser(compiled.UserId, out _))
                {
                    throw new InvalidOperationException($"Shadowsocks user '{compiled.UserId}' already exists on inbound '{InboundTag}'.");
                }

                _userValidator.AddUser(compiled);
            }
        }

        public override bool RemoveUser(string userId)
        {
            var normalizedUserId = NormalizeUserId(userId);
            if (normalizedUserId.Length == 0)
            {
                return false;
            }

            lock (_sync)
            {
                return _userValidator.RemoveUser(normalizedUserId);
            }
        }

        public void Replace(IEnumerable<ShadowsocksUser> users)
        {
            ArgumentNullException.ThrowIfNull(users);

            lock (_sync)
            {
                _userValidator.Replace(CompileShadowsocksUsers(users));
            }
        }

        private ShadowsocksUser[] CompileShadowsocksUsers(IEnumerable<ShadowsocksUser> users)
            => users
                .Where(static user => user is not null)
                .Select(CompileShadowsocksUser)
                .ToArray();

        private ShadowsocksUser CompileShadowsocksUser(IRuntimeUserDefinition user)
        {
            return user switch
            {
                ShadowsocksUser shadowsocksUser => CreateShadowsocksRuntimeUser(
                    shadowsocksUser.UserId,
                    shadowsocksUser.Cipher,
                    shadowsocksUser.Password,
                    shadowsocksUser.Level,
                    shadowsocksUser.BytesPerSecond,
                    shadowsocksUser.DeviceLimit,
                    string.IsNullOrWhiteSpace(shadowsocksUser.RuntimeKey)
                        ? RuntimeUserKeys.Create(Protocol, InboundTag, shadowsocksUser.UserId)
                        : shadowsocksUser.RuntimeKey),
                IShadowsocksUserDefinition shadowsocksDefinition => CreateShadowsocksRuntimeUser(
                    shadowsocksDefinition.UserId,
                    shadowsocksDefinition.Cipher,
                    shadowsocksDefinition.Password,
                    shadowsocksDefinition.Level,
                    shadowsocksDefinition.BytesPerSecond,
                    shadowsocksDefinition.DeviceLimit,
                    RuntimeUserKeys.Create(Protocol, InboundTag, shadowsocksDefinition.UserId)),
                _ => throw new InvalidOperationException("Shadowsocks inbound requires a shadowsocks-compatible user definition.")
            };
        }

        private static ShadowsocksUser CreateShadowsocksRuntimeUser(
            string userId,
            string cipher,
            string password,
            int level,
            long bytesPerSecond,
            int deviceLimit,
            string runtimeKey)
        {
            var normalizedUserId = NormalizeUserId(userId);
            var normalizedCipher = ShadowsocksCipherTypes.Normalize(cipher);
            var normalizedPassword = password?.Trim() ?? string.Empty;
            if (normalizedUserId.Length == 0 ||
                normalizedCipher.Length == 0)
            {
                throw new InvalidOperationException("Shadowsocks user requires a non-empty user id and cipher.");
            }

            _ = ShadowsocksAccount.Create(normalizedCipher, normalizedPassword);

            return new ShadowsocksUser
            {
                UserId = normalizedUserId,
                Cipher = normalizedCipher,
                Password = normalizedPassword,
                RuntimeKey = string.IsNullOrWhiteSpace(runtimeKey) ? normalizedUserId : runtimeKey.Trim(),
                Level = Math.Max(0, level),
                BytesPerSecond = Math.Max(0, bytesPerSecond),
                DeviceLimit = Math.Max(0, deviceLimit)
            };
        }
    }

    private sealed class Shadowsocks2022InboundUserRegistry : RuntimeInboundUserRegistry
    {
        private readonly string _key;
        private readonly string _method;
        private readonly string _mode;
        private readonly Lock _sync = new();
        private readonly Shadowsocks2022InboundUserValidator _userValidator;

        public Shadowsocks2022InboundUserRegistry(
            string inboundTag,
            string method,
            string key,
            string mode)
            : base(InboundProtocols.Shadowsocks, inboundTag)
        {
            _method = Shadowsocks2022UserCompiler.NormalizeMethod(method);
            _key = Shadowsocks2022UserCompiler.NormalizeKey(key);
            _mode = Shadowsocks2022UserCompiler.NormalizeMode(mode);
            _userValidator = new Shadowsocks2022InboundUserValidator(_method, _key, _mode, Array.Empty<Shadowsocks2022User>());
        }

        public override int Count => _userValidator.Count;

        internal Shadowsocks2022InboundUserValidator UserValidator => _userValidator;

        public override IReadOnlyList<IRuntimeUserDefinition> GetUsers()
            => _userValidator.GetUsers().Cast<IRuntimeUserDefinition>().ToArray();

        public override bool TryGetUser(string userId, out IRuntimeUserDefinition? user)
        {
            if (_userValidator.TryGetUser(NormalizeUserId(userId), out var resolved))
            {
                user = resolved;
                return true;
            }

            user = null;
            return false;
        }

        public override void AddUser(IRuntimeUserDefinition user)
        {
            var compiled = CompileShadowsocks2022User(user);

            lock (_sync)
            {
                if (_userValidator.TryGetUser(compiled.UserId, out _))
                {
                    throw new InvalidOperationException($"Shadowsocks 2022 user '{compiled.UserId}' already exists on inbound '{InboundTag}'.");
                }

                _userValidator.AddUser(compiled);
            }
        }

        public override bool RemoveUser(string userId)
        {
            var normalizedUserId = NormalizeUserId(userId);
            if (normalizedUserId.Length == 0)
            {
                return false;
            }

            lock (_sync)
            {
                return _userValidator.RemoveUser(normalizedUserId);
            }
        }

        public void Replace(IEnumerable<Shadowsocks2022User> users)
        {
            ArgumentNullException.ThrowIfNull(users);

            lock (_sync)
            {
                _userValidator.Replace(_method, _key, _mode, CompileShadowsocks2022Users(users));
            }
        }

        private Shadowsocks2022User[] CompileShadowsocks2022Users(IEnumerable<Shadowsocks2022User> users)
            => users
                .Where(static user => user is not null)
                .Select(CompileShadowsocks2022User)
                .ToArray();

        private Shadowsocks2022User CompileShadowsocks2022User(IRuntimeUserDefinition user)
        {
            return Shadowsocks2022UserCompiler.CompileRuntimeUserOrThrow(
                _mode,
                _key,
                CreateShadowsocks2022UserCandidate(user),
                CreateRuntimeKey);
        }

        private Shadowsocks2022User CreateShadowsocks2022UserCandidate(IRuntimeUserDefinition user)
            => user switch
            {
                Shadowsocks2022User shadowsocks2022User => shadowsocks2022User,
                IShadowsocks2022UserDefinition shadowsocks2022Definition => new Shadowsocks2022User
                {
                    UserId = shadowsocks2022Definition.UserId,
                    Cipher = shadowsocks2022Definition.Cipher,
                    Password = shadowsocks2022Definition.Password,
                    Address = shadowsocks2022Definition.Address,
                    Port = shadowsocks2022Definition.Port,
                    RuntimeKey = string.Empty,
                    Level = Math.Max(0, shadowsocks2022Definition.Level),
                    BytesPerSecond = shadowsocks2022Definition.BytesPerSecond,
                    DeviceLimit = shadowsocks2022Definition.DeviceLimit
                },
                IShadowsocksUserDefinition shadowsocksDefinition when !Shadowsocks2022UserCompiler.IsRelayMode(_mode) => new Shadowsocks2022User
                {
                    UserId = shadowsocksDefinition.UserId,
                    Cipher = shadowsocksDefinition.Cipher,
                    Password = shadowsocksDefinition.Password,
                    Address = string.Empty,
                    Port = 0,
                    RuntimeKey = string.Empty,
                    Level = Math.Max(0, shadowsocksDefinition.Level),
                    BytesPerSecond = shadowsocksDefinition.BytesPerSecond,
                    DeviceLimit = shadowsocksDefinition.DeviceLimit
                },
                _ => throw new InvalidOperationException("Shadowsocks 2022 inbound requires a shadowsocks-2022-compatible user definition.")
            };

        private string CreateRuntimeKey(string userId)
            => RuntimeUserKeys.Create(Protocol, InboundTag, userId);
    }

    private sealed class VlessInboundUserRegistry : RuntimeInboundUserRegistry
    {
        private readonly Lock _sync = new();
        private readonly VlessUserValidator _userValidator = new(Array.Empty<VlessUser>());

        public VlessInboundUserRegistry(string inboundTag)
            : base(InboundProtocols.Vless, inboundTag)
        {
        }

        public override int Count => _userValidator.Count;

        internal VlessUserValidator UserValidator => _userValidator;

        public override IReadOnlyList<IRuntimeUserDefinition> GetUsers()
            => _userValidator.GetUsers().Cast<IRuntimeUserDefinition>().ToArray();

        public override bool TryGetUser(string userId, out IRuntimeUserDefinition? user)
        {
            if (_userValidator.TryGetUser(NormalizeUserId(userId), out var resolved))
            {
                user = resolved;
                return true;
            }

            user = null;
            return false;
        }

        public override void AddUser(IRuntimeUserDefinition user)
        {
            var compiled = CompileVlessUser(user);

            lock (_sync)
            {
                if (_userValidator.TryGetUser(compiled.UserId, out _))
                {
                    throw new InvalidOperationException($"VLESS user '{compiled.UserId}' already exists on inbound '{InboundTag}'.");
                }

                if (_userValidator.TryGetUserByUuid(compiled.Uuid, out _))
                {
                    throw new InvalidOperationException($"VLESS uuid '{compiled.Uuid}' already exists on inbound '{InboundTag}'.");
                }

                _userValidator.AddUser(compiled);
            }
        }

        public override bool RemoveUser(string userId)
        {
            var normalizedUserId = NormalizeUserId(userId);
            if (normalizedUserId.Length == 0)
            {
                return false;
            }

            lock (_sync)
            {
                return _userValidator.RemoveUser(normalizedUserId);
            }
        }

        public void Replace(IEnumerable<VlessUser> users)
        {
            ArgumentNullException.ThrowIfNull(users);

            lock (_sync)
            {
                _userValidator.Replace(CompileVlessUsers(users));
            }
        }

        private VlessUser[] CompileVlessUsers(IEnumerable<VlessUser> users)
            => users
                .Where(static user => user is not null)
                .Select(CompileVlessUser)
                .ToArray();

        private VlessUser CompileVlessUser(IRuntimeUserDefinition user)
        {
            return user switch
            {
                VlessUser vlessUser => CreateVlessRuntimeUser(
                    vlessUser.UserId,
                    vlessUser.Uuid,
                    vlessUser.Flow,
                    vlessUser.ReverseTag,
                    vlessUser.TestSeed,
                    vlessUser.Level,
                    vlessUser.BytesPerSecond,
                    vlessUser.DeviceLimit,
                    string.IsNullOrWhiteSpace(vlessUser.RuntimeKey)
                        ? RuntimeUserKeys.Create(Protocol, InboundTag, vlessUser.UserId)
                        : vlessUser.RuntimeKey),
                IVlessUserDefinition vlessDefinition => CreateVlessRuntimeUser(
                    vlessDefinition.UserId,
                    vlessDefinition.Uuid,
                    vlessDefinition.Flow,
                    vlessDefinition.ReverseTag,
                    vlessDefinition.TestSeed,
                    vlessDefinition.Level,
                    vlessDefinition.BytesPerSecond,
                    vlessDefinition.DeviceLimit,
                    RuntimeUserKeys.Create(Protocol, InboundTag, vlessDefinition.UserId)),
                _ => throw new InvalidOperationException("VLESS inbound requires a vless-compatible user definition.")
            };
        }

        private static VlessUser CreateVlessRuntimeUser(
            string userId,
            string uuid,
            string flow,
            string reverseTag,
            IReadOnlyList<uint>? testSeed,
            int level,
            long bytesPerSecond,
            int deviceLimit,
            string runtimeKey)
        {
            var normalizedUserId = NormalizeUserId(userId);
            var normalizedUuid = NormalizeUuid(uuid);
            if (normalizedUserId.Length == 0 ||
                normalizedUuid.Length == 0)
            {
                throw new InvalidOperationException("VLESS user requires a non-empty user id and valid uuid.");
            }

            return new VlessUser
            {
                UserId = normalizedUserId,
                Uuid = normalizedUuid,
                Flow = NormalizeVlessInboundFlow(flow),
                ReverseTag = NormalizeOptionalTag(reverseTag),
                TestSeed = NormalizeVlessTestSeed(testSeed),
                RuntimeKey = string.IsNullOrWhiteSpace(runtimeKey) ? normalizedUserId : runtimeKey.Trim(),
                Level = Math.Max(0, level),
                BytesPerSecond = Math.Max(0, bytesPerSecond),
                DeviceLimit = Math.Max(0, deviceLimit)
            };
        }

        private static string NormalizeOptionalTag(string? value)
            => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    }

    private sealed class VmessInboundUserRegistry : RuntimeInboundUserRegistry
    {
        private readonly Lock _sync = new();
        private readonly VmessTimedUserValidator _userValidator = new(Array.Empty<VmessUser>());

        public VmessInboundUserRegistry(string inboundTag)
            : base(InboundProtocols.Vmess, inboundTag)
        {
        }

        internal VmessTimedUserValidator UserValidator => _userValidator;

        public override int Count => _userValidator.Count;

        public override IReadOnlyList<IRuntimeUserDefinition> GetUsers()
            => _userValidator.GetUsers().Cast<IRuntimeUserDefinition>().ToArray();

        public override bool TryGetUser(string userId, out IRuntimeUserDefinition? user)
        {
            if (_userValidator.TryGetUser(NormalizeUserId(userId), out var resolved))
            {
                user = resolved;
                return true;
            }

            user = null;
            return false;
        }

        public override void AddUser(IRuntimeUserDefinition user)
        {
            var compiled = CompileVmessUser(user);

            lock (_sync)
            {
                if (_userValidator.TryGetUser(compiled.UserId, out _))
                {
                    throw new InvalidOperationException($"VMess user '{compiled.UserId}' already exists on inbound '{InboundTag}'.");
                }

                if (_userValidator.TryGetUserByUuid(compiled.Uuid, out _))
                {
                    throw new InvalidOperationException($"VMess uuid '{compiled.Uuid}' already exists on inbound '{InboundTag}'.");
                }

                _userValidator.AddUser(compiled);
            }
        }

        public override bool RemoveUser(string userId)
        {
            var normalizedUserId = NormalizeUserId(userId);
            if (normalizedUserId.Length == 0)
            {
                return false;
            }

            lock (_sync)
            {
                return _userValidator.RemoveUser(normalizedUserId);
            }
        }

        public void Replace(IEnumerable<VmessUser> users)
        {
            ArgumentNullException.ThrowIfNull(users);

            lock (_sync)
            {
                _userValidator.Replace(CompileVmessUsers(users));
            }
        }

        private VmessUser[] CompileVmessUsers(IEnumerable<VmessUser> users)
            => users
                .Where(static user => user is not null)
                .Select(CompileVmessUser)
                .ToArray();

        private VmessUser CompileVmessUser(IRuntimeUserDefinition user)
        {
            return user switch
            {
                VmessUser vmessUser => CreateVmessRuntimeUser(
                    vmessUser.UserId,
                    vmessUser.Uuid,
                    vmessUser.Level,
                    vmessUser.BytesPerSecond,
                    vmessUser.DeviceLimit,
                    string.IsNullOrWhiteSpace(vmessUser.RuntimeKey)
                        ? RuntimeUserKeys.Create(Protocol, InboundTag, vmessUser.UserId)
                        : vmessUser.RuntimeKey),
                IVmessUserDefinition vmessDefinition => CreateVmessRuntimeUser(
                    vmessDefinition.UserId,
                    vmessDefinition.Uuid,
                    vmessDefinition.Level,
                    vmessDefinition.BytesPerSecond,
                    vmessDefinition.DeviceLimit,
                    RuntimeUserKeys.Create(Protocol, InboundTag, vmessDefinition.UserId)),
                _ => throw new InvalidOperationException("VMess inbound requires a vmess-compatible user definition.")
            };
        }

        private static VmessUser CreateVmessRuntimeUser(
            string userId,
            string uuid,
            int level,
            long bytesPerSecond,
            int deviceLimit,
            string runtimeKey)
        {
            var normalizedUserId = NormalizeUserId(userId);
            var normalizedUuid = NormalizeUuid(uuid);
            if (normalizedUserId.Length == 0 ||
                normalizedUuid.Length == 0)
            {
                throw new InvalidOperationException("VMess user requires a non-empty user id and valid uuid.");
            }

            return new VmessUser
            {
                UserId = normalizedUserId,
                Uuid = normalizedUuid,
                CmdKey = VmessAccountCodec.CreateCommandKey(normalizedUuid),
                RuntimeKey = string.IsNullOrWhiteSpace(runtimeKey) ? normalizedUserId : runtimeKey.Trim(),
                Level = Math.Max(0, level),
                BytesPerSecond = Math.Max(0, bytesPerSecond),
                DeviceLimit = Math.Max(0, deviceLimit)
            };
        }

    }

    private static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();

    private static string NormalizeTrojanHash(string? passwordHash)
        => string.IsNullOrWhiteSpace(passwordHash)
            ? string.Empty
            : passwordHash.Trim().ToLowerInvariant();

    private static string NormalizeUuid(string? uuid)
        => ProtocolUuid.TryNormalize(uuid, out var normalizedUuid) ? normalizedUuid : string.Empty;

    private static string NormalizeVlessInboundFlow(string? flow)
        => VlessFlowTypes.IsVision(flow)
            ? VlessFlowTypes.Vision
            : string.Empty;

    private static IReadOnlyList<uint> NormalizeVlessTestSeed(IReadOnlyList<uint>? values)
        => values is { Count: >= 4 }
            ? values.Take(4).ToArray()
            : Array.Empty<uint>();
}

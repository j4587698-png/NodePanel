using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public interface IShadowsocksUserDefinition : IRuntimeUserDefinition
{
    string Cipher { get; }

    string Password { get; }
}

public interface IShadowsocksInboundDefinition
{
    string Tag { get; }

    bool Enabled { get; }

    string Protocol { get; }

    string ListenAddress { get; }

    int Port { get; }

    int HandshakeTimeoutSeconds { get; }

    string Security { get; }

    string Password { get; }

    int UserLevel { get; }

    IReadOnlyList<string> Networks { get; }
}

public interface IShadowsocksInboundScopeDefinition
{
    IReadOnlyList<IShadowsocksUserDefinition> GetShadowsocksUsers();

    IRuntimeSniffingDefinition GetSniffing();
}

public sealed record ShadowsocksUser : IRuntimeUserDefinition, IRuntimeScopedUserDefinition, IShadowsocksUserDefinition
{
    public required string UserId { get; init; }

    public string Cipher { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string RuntimeKey { get; init; } = string.Empty;

    public int Level { get; init; }

    public required long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

public sealed record ShadowsocksInboundRuntime
{
    internal ShadowsocksInboundRuntimeState RuntimeState { get; init; } = new(Array.Empty<ShadowsocksUser>());

    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public IReadOnlyList<string> Networks { get; init; } = [RoutingNetworks.Tcp];

    public RuntimeSniffingOptions Sniffing { get; init; } = new();

    public IReadOnlyList<ShadowsocksUser> Users { get; init; } = Array.Empty<ShadowsocksUser>();

    public bool HasTcp => Networks.Contains(RoutingNetworks.Tcp, StringComparer.OrdinalIgnoreCase);

    public bool HasUdp => Networks.Contains(RoutingNetworks.Udp, StringComparer.OrdinalIgnoreCase);
}

public sealed record ShadowsocksInboundRuntimePlan : IInboundProtocolRuntimePlan
{
    public static ShadowsocksInboundRuntimePlan Empty { get; } = new();

    public string Protocol => InboundProtocols.Shadowsocks;

    public IReadOnlyList<ShadowsocksInboundRuntime> Inbounds { get; init; } = Array.Empty<ShadowsocksInboundRuntime>();

    public IReadOnlyList<Shadowsocks2022InboundRuntime> Inbounds2022 { get; init; } = Array.Empty<Shadowsocks2022InboundRuntime>();

    public bool RequiresCertificate => false;

    public bool RequiresReality => false;

    public bool HasTcp => Inbounds.Any(static inbound => inbound.HasTcp) ||
                          Inbounds2022.Any(static inbound => inbound.HasTcp);

    public bool HasUdp => Inbounds.Any(static inbound => inbound.HasUdp) ||
                          Inbounds2022.Any(static inbound => inbound.HasUdp);
}

public static class ShadowsocksInboundRuntimePlanner
{
    private const string ImplicitUserId = "default";

    public static bool TryBuild(
        IReadOnlyList<IShadowsocksInboundDefinition> inbounds,
        out ShadowsocksInboundRuntimePlan plan,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(inbounds);

        var compiledInbounds = new List<ShadowsocksInboundRuntime>(inbounds.Count);
        var compiled2022Inbounds = new List<Shadowsocks2022InboundRuntime>(inbounds.Count);
        var bindingInputs = new List<BindingValidationInput>(inbounds.Count);
        if (!TryNormalizeAll(inbounds, compiledInbounds, compiled2022Inbounds, bindingInputs, out error) ||
            !ValidateBindingConflicts(bindingInputs, out error))
        {
            plan = ShadowsocksInboundRuntimePlan.Empty;
            return false;
        }

        plan = new ShadowsocksInboundRuntimePlan
        {
            Inbounds = compiledInbounds.ToArray(),
            Inbounds2022 = compiled2022Inbounds.ToArray()
        };
        error = null;
        return true;
    }

    private static bool TryNormalizeAll(
        IReadOnlyList<IShadowsocksInboundDefinition> inbounds,
        ICollection<ShadowsocksInboundRuntime> compiledInbounds,
        ICollection<Shadowsocks2022InboundRuntime> compiled2022Inbounds,
        ICollection<BindingValidationInput> bindingInputs,
        out string? error)
    {
        for (var index = 0; index < inbounds.Count; index++)
        {
            var inbound = inbounds[index];
            if (!inbound.Enabled ||
                !string.Equals(InboundProtocols.Normalize(inbound.Protocol), InboundProtocols.Shadowsocks, StringComparison.Ordinal))
            {
                continue;
            }

            var listenAddress = NormalizeListenAddress(inbound.ListenAddress);
            var port = NormalizeListenerPort(inbound.Port, 8388);
            if (!IsValidListenerBinding(listenAddress, port))
            {
                error = $"Invalid Shadowsocks listen address: {listenAddress}:{port}.";
                return false;
            }

            var cipher = ShadowsocksCipherTypes.Normalize(inbound.Security);
            if (!TryNormalizeNetworks(
                    inbound.Networks,
                    GetDefaultNetworks(cipher),
                    out var networks,
                    out error))
            {
                return false;
            }

            var tag = NormalizeTag(inbound.Tag, index);
            var binding = new ListenerBinding(listenAddress, port);
            var handshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 60);
            var sniffing = inbound is IShadowsocksInboundScopeDefinition scopedSniffing
                ? NormalizeSniffing(scopedSniffing.GetSniffing())
                : new RuntimeSniffingOptions();

            bindingInputs.Add(new BindingValidationInput(binding, networks));

            if (ShadowsocksCipherTypes.Is2022Method(cipher))
            {
                if (!Shadowsocks2022InboundPlanner.TryBuild(
                        tag,
                        binding,
                        handshakeTimeoutSeconds,
                        networks,
                        sniffing,
                        cipher,
                        inbound.Password,
                        Math.Max(0, inbound.UserLevel),
                        Resolve2022Users(inbound),
                        out var compiled2022Inbound,
                        out error))
                {
                    return false;
                }

                compiled2022Inbounds.Add(compiled2022Inbound);
                continue;
            }

            if (!TryCompileUsers(
                    inbound is IShadowsocksInboundScopeDefinition scopedInbound
                        ? scopedInbound.GetShadowsocksUsers()
                        : Array.Empty<IShadowsocksUserDefinition>(),
                    tag,
                    cipher,
                    inbound.Password,
                    Math.Max(0, inbound.UserLevel),
                    out var users,
                    out error))
            {
                return false;
            }

            compiledInbounds.Add(new ShadowsocksInboundRuntime
            {
                RuntimeState = new ShadowsocksInboundRuntimeState(users),
                Tag = tag,
                Binding = binding,
                HandshakeTimeoutSeconds = handshakeTimeoutSeconds,
                Networks = networks,
                Sniffing = sniffing,
                Users = users
            });
        }

        error = null;
        return true;
    }

    private static IReadOnlyList<IShadowsocks2022UserDefinition> Resolve2022Users(IShadowsocksInboundDefinition inbound)
    {
        if (inbound is IShadowsocks2022InboundScopeDefinition scoped2022Inbound)
        {
            var dedicatedUsers = scoped2022Inbound.GetShadowsocks2022Users();
            if (dedicatedUsers.Count > 0)
            {
                return dedicatedUsers;
            }
        }

        if (inbound is not IShadowsocksInboundScopeDefinition scopedInbound)
        {
            return Array.Empty<IShadowsocks2022UserDefinition>();
        }

        return scopedInbound.GetShadowsocksUsers()
            .Select(static user => new AdaptedShadowsocks2022User(user))
            .Cast<IShadowsocks2022UserDefinition>()
            .ToArray();
    }

    private static bool ValidateBindingConflicts(
        IReadOnlyList<BindingValidationInput> inbounds,
        out string? error)
    {
        for (var i = 0; i < inbounds.Count; i++)
        {
            for (var j = i + 1; j < inbounds.Count; j++)
            {
                var left = inbounds[i];
                var right = inbounds[j];

                if (!string.Equals(left.Binding.ListenAddress, right.Binding.ListenAddress, StringComparison.OrdinalIgnoreCase) ||
                    left.Binding.Port != right.Binding.Port)
                {
                    continue;
                }

                if (!left.Networks.Intersect(right.Networks, StringComparer.OrdinalIgnoreCase).Any())
                {
                    continue;
                }

                error = $"Shadowsocks inbounds cannot bind the same network on the same listener more than once: {left.Binding.ListenAddress}:{left.Binding.Port}.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool TryCompileUsers(
        IReadOnlyList<IShadowsocksUserDefinition> users,
        string inboundTag,
        string defaultCipher,
        string inboundPassword,
        int implicitUserLevel,
        out IReadOnlyList<ShadowsocksUser> compiledUsers,
        out string? error)
    {
        if (users.Count == 0)
        {
            return TryCompileImplicitUser(
                inboundTag,
                defaultCipher,
                inboundPassword,
                implicitUserLevel,
                out compiledUsers,
                out error);
        }

        var compiled = new List<ShadowsocksUser>(users.Count);
        foreach (var user in users)
        {
            if (user is null)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(user.UserId))
            {
                error = $"Shadowsocks inbound '{inboundTag}' contains a user without a user id.";
                compiledUsers = Array.Empty<ShadowsocksUser>();
                return false;
            }

            if (string.IsNullOrWhiteSpace(user.Password))
            {
                error = $"Shadowsocks user '{user.UserId.Trim()}' on inbound '{inboundTag}' requires a password.";
                compiledUsers = Array.Empty<ShadowsocksUser>();
                return false;
            }

            var cipher = ShadowsocksCipherTypes.Normalize(user.Cipher);
            if (!TryValidateCipher(cipher, allowNone: false, out var cipherError))
            {
                error = string.IsNullOrWhiteSpace(cipherError)
                    ? $"Shadowsocks user '{user.UserId}' on inbound '{inboundTag}' uses an unsupported cipher: {cipher}."
                    : $"Shadowsocks user '{user.UserId}' on inbound '{inboundTag}' is invalid: {cipherError}";
                compiledUsers = Array.Empty<ShadowsocksUser>();
                return false;
            }

            try
            {
                _ = ShadowsocksAccount.Create(cipher, user.Password.Trim());
            }
            catch (Exception ex)
            {
                error = $"Shadowsocks user '{user.UserId}' on inbound '{inboundTag}' is invalid: {ex.Message}";
                compiledUsers = Array.Empty<ShadowsocksUser>();
                return false;
            }

            compiled.Add(new ShadowsocksUser
            {
                UserId = user.UserId.Trim(),
                Cipher = cipher,
                Password = user.Password.Trim(),
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, inboundTag, user.UserId),
                Level = Math.Max(0, user.Level),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            });
        }

        compiledUsers = compiled;
        error = null;
        return true;
    }

    private static bool TryCompileImplicitUser(
        string inboundTag,
        string defaultCipher,
        string inboundPassword,
        int userLevel,
        out IReadOnlyList<ShadowsocksUser> compiledUsers,
        out string? error)
    {
        var cipher = ResolveCipher(userCipher: null, defaultCipher);
        if (string.IsNullOrWhiteSpace(cipher))
        {
            compiledUsers = Array.Empty<ShadowsocksUser>();
            error = $"Shadowsocks inbound '{inboundTag}' requires at least one user or an inbound password/cipher pair.";
            return false;
        }

        if (!TryValidateCipher(cipher, allowNone: true, out var cipherError))
        {
            error = string.IsNullOrWhiteSpace(cipherError)
                ? $"Shadowsocks inbound '{inboundTag}' uses an unsupported cipher: {cipher}."
                : $"Shadowsocks inbound '{inboundTag}' is invalid: {cipherError}";
            compiledUsers = Array.Empty<ShadowsocksUser>();
            return false;
        }

        var password = inboundPassword?.Trim() ?? string.Empty;
        if (password.Length == 0)
        {
            compiledUsers = Array.Empty<ShadowsocksUser>();
            error = $"Shadowsocks inbound '{inboundTag}' requires a password when no users are configured.";
            return false;
        }

        try
        {
            _ = ShadowsocksAccount.Create(cipher, password);
        }
        catch (Exception ex)
        {
            compiledUsers = Array.Empty<ShadowsocksUser>();
            error = $"Shadowsocks inbound '{inboundTag}' is invalid: {ex.Message}";
            return false;
        }

        compiledUsers =
        [
            new ShadowsocksUser
            {
                UserId = ImplicitUserId,
                Cipher = cipher,
                Password = password,
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, inboundTag, ImplicitUserId),
                Level = Math.Max(0, userLevel),
                BytesPerSecond = 0,
                DeviceLimit = 0
            }
        ];
        error = null;
        return true;
    }

    private static RuntimeSniffingOptions NormalizeSniffing(IRuntimeSniffingDefinition sniffing)
        => new()
        {
            Enabled = sniffing.Enabled,
            DestinationOverride = sniffing.DestinationOverride
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => RoutingProtocols.Normalize(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            DomainsExcluded = sniffing.DomainsExcluded
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim().ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            MetadataOnly = sniffing.MetadataOnly,
            RouteOnly = sniffing.RouteOnly
        };

    private static bool TryNormalizeNetworks(
        IReadOnlyList<string> values,
        IReadOnlyList<string> defaultNetworks,
        out IReadOnlyList<string> networks,
        out string? error)
    {
        var normalized = values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => RoutingNetworks.Normalize(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (normalized.Length == 0)
        {
            networks = defaultNetworks;
            error = null;
            return true;
        }

        foreach (var network in normalized)
        {
            if (network is RoutingNetworks.Tcp or RoutingNetworks.Udp)
            {
                continue;
            }

            networks = Array.Empty<string>();
            error = $"Unsupported Shadowsocks inbound network: {network}.";
            return false;
        }

        networks = normalized;
        error = null;
        return true;
    }

    private static IReadOnlyList<string> GetDefaultNetworks(string cipher)
        => ShadowsocksCipherTypes.Is2022Method(cipher)
            ? [RoutingNetworks.Tcp, RoutingNetworks.Udp]
            : [RoutingNetworks.Tcp];

    private static bool TryValidateCipher(string cipher, bool allowNone, out string? error)
    {
        var normalized = ResolveCipher(cipher, defaultCipher: string.Empty);
        if (normalized.Length == 0)
        {
            error = "Shadowsocks cipher is not specified.";
            return false;
        }

        if ((allowNone && ShadowsocksCipherTypes.IsRegularMethod(normalized)) ||
            (!allowNone && normalized is
                ShadowsocksCipherTypes.Aes128Gcm or
                ShadowsocksCipherTypes.Aes256Gcm or
                ShadowsocksCipherTypes.ChaCha20Poly1305 or
                ShadowsocksCipherTypes.XChaCha20Poly1305))
        {
            error = null;
            return true;
        }

        if (!allowNone &&
            string.Equals(normalized, ShadowsocksCipherTypes.None, StringComparison.Ordinal))
        {
            error = "Shadowsocks cipher 'none' is only supported by the implicit single-user path.";
            return false;
        }

        if (ShadowsocksCipherTypes.Is2022Method(normalized))
        {
            error = $"Shadowsocks cipher '{normalized}' is a Shadowsocks 2022 method and cannot be used by the regular Shadowsocks user path.";
            return false;
        }

        error = $"Unsupported Shadowsocks cipher: {cipher}.";
        return false;
    }

    private static string ResolveCipher(string? userCipher, string? defaultCipher)
    {
        var normalizedUserCipher = ShadowsocksCipherTypes.Normalize(userCipher);
        if (!string.IsNullOrWhiteSpace(normalizedUserCipher))
        {
            return normalizedUserCipher;
        }

        return ShadowsocksCipherTypes.Normalize(defaultCipher);
    }

    private static string NormalizeTag(string value, int index)
        => string.IsNullOrWhiteSpace(value)
            ? $"shadowsocks-{index + 1}"
            : value.Trim();

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static int NormalizeListenerPort(int value, int fallback)
        => value is > 0 and <= 65535 ? value : fallback;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static bool IsValidListenerBinding(string address, int port)
        => port is > 0 and <= 65535 && IPAddress.TryParse(address, out _);

    private sealed record BindingValidationInput(
        ListenerBinding Binding,
        IReadOnlyList<string> Networks);

    private sealed record AdaptedShadowsocks2022User(IShadowsocksUserDefinition Inner) : IShadowsocks2022UserDefinition
    {
        public string UserId => Inner.UserId;

        public string Cipher => Inner.Cipher;

        public string Password => Inner.Password;

        public string Address => string.Empty;

        public int Port => 0;

        public int Level => Inner.Level;

        public long BytesPerSecond => Inner.BytesPerSecond;

        public int DeviceLimit => Inner.DeviceLimit;
    }
}

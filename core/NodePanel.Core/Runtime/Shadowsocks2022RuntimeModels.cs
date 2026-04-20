using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public interface IShadowsocks2022UserDefinition : IRuntimeUserDefinition
{
    string Cipher { get; }

    string Password { get; }

    string Address { get; }

    int Port { get; }
}

public interface IShadowsocks2022InboundScopeDefinition
{
    IReadOnlyList<IShadowsocks2022UserDefinition> GetShadowsocks2022Users();
}

public static class Shadowsocks2022InboundModes
{
    public const string SingleUser = "single-user";
    public const string MultiUser = "multi-user";
    public const string Relay = "relay";
}

public sealed record Shadowsocks2022User : IRuntimeUserDefinition, IRuntimeScopedUserDefinition, IShadowsocks2022UserDefinition
{
    public required string UserId { get; init; }

    public string Cipher { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string Address { get; init; } = string.Empty;

    public int Port { get; init; }

    public string RuntimeKey { get; init; } = string.Empty;

    public int Level { get; init; }

    public required long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }

    public bool HasRelayDestination => !string.IsNullOrWhiteSpace(Address) && Port > 0;
}

public sealed record Shadowsocks2022InboundRuntime
{
    internal Shadowsocks2022InboundRuntimeState RuntimeState { get; init; } = Shadowsocks2022InboundRuntimeState.Empty;

    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public IReadOnlyList<string> Networks { get; init; } = [RoutingNetworks.Tcp, RoutingNetworks.Udp];

    public RuntimeSniffingOptions Sniffing { get; init; } = new();

    public string Method { get; init; } = string.Empty;

    public string Key { get; init; } = string.Empty;

    public string Mode { get; init; } = Shadowsocks2022InboundModes.SingleUser;

    public IReadOnlyList<Shadowsocks2022User> Users { get; init; } = Array.Empty<Shadowsocks2022User>();

    public bool HasTcp => Networks.Contains(RoutingNetworks.Tcp, StringComparer.OrdinalIgnoreCase);

    public bool HasUdp => Networks.Contains(RoutingNetworks.Udp, StringComparer.OrdinalIgnoreCase);
}

public static class Shadowsocks2022InboundPlanner
{
    public static bool TryBuild(
        string inboundTag,
        ListenerBinding binding,
        int handshakeTimeoutSeconds,
        IReadOnlyList<string> networks,
        RuntimeSniffingOptions sniffing,
        string method,
        string key,
        int userLevel,
        IReadOnlyList<IShadowsocks2022UserDefinition> users,
        out Shadowsocks2022InboundRuntime runtime,
        out string? error)
    {
        try
        {
            Shadowsocks2022UserCompiler.ValidateMethodOrThrow(inboundTag, method);

            var normalizedMethod = Shadowsocks2022UserCompiler.NormalizeMethod(method);
            var normalizedKey = Shadowsocks2022UserCompiler.NormalizeKey(key);
            Shadowsocks2022UserCompiler.ValidatePlannerServerKeyOrThrow(inboundTag, normalizedKey);
            if (users.Count == 0)
            {
                var defaultUser = Shadowsocks2022UserCompiler.CreateImplicitSingleUser(
                    inboundTag,
                    normalizedKey,
                    userLevel);
                runtime = new Shadowsocks2022InboundRuntime
                {
                    RuntimeState = new Shadowsocks2022InboundRuntimeState(
                        normalizedMethod,
                        normalizedKey,
                        Shadowsocks2022InboundModes.SingleUser,
                        [defaultUser]),
                    Tag = inboundTag,
                    Binding = binding,
                    HandshakeTimeoutSeconds = handshakeTimeoutSeconds,
                    Networks = networks,
                    Sniffing = sniffing,
                    Method = normalizedMethod,
                    Key = normalizedKey,
                    Mode = Shadowsocks2022InboundModes.SingleUser,
                    Users = [defaultUser]
                };
                error = null;
                return true;
            }

            Shadowsocks2022UserCompiler.ValidateMultiUserMethodOrThrow(inboundTag, normalizedMethod);

            var mode = Shadowsocks2022UserCompiler.HasRelayDestination(users[0])
                ? Shadowsocks2022InboundModes.Relay
                : Shadowsocks2022InboundModes.MultiUser;
            var compiledUsers = new List<Shadowsocks2022User>(users.Count);
            for (var index = 0; index < users.Count; index++)
            {
                var user = users[index];
                if (user is null)
                {
                    continue;
                }

                compiledUsers.Add(
                    Shadowsocks2022UserCompiler.CompilePlannerUserOrThrow(
                        inboundTag,
                        mode,
                        normalizedKey,
                        user,
                        Math.Max(0, user.Level),
                        index));
            }

            runtime = new Shadowsocks2022InboundRuntime
            {
                RuntimeState = new Shadowsocks2022InboundRuntimeState(
                    normalizedMethod,
                    normalizedKey,
                    mode,
                    compiledUsers),
                Tag = inboundTag,
                Binding = binding,
                HandshakeTimeoutSeconds = handshakeTimeoutSeconds,
                Networks = networks,
                Sniffing = sniffing,
                Method = normalizedMethod,
                Key = normalizedKey,
                Mode = mode,
                Users = compiledUsers
            };
            error = null;
            return true;
        }
        catch (InvalidOperationException ex)
        {
            runtime = default!;
            error = ex.Message;
            return false;
        }
    }
}

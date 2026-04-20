namespace NodePanel.Core.Runtime;

internal static class Shadowsocks2022UserCompiler
{
    private enum ErrorStyle
    {
        Planner,
        Runtime
    }

    public const string DefaultUserId = "default";

    public static string NormalizeMethod(string? method)
        => ShadowsocksCipherTypes.Normalize(method);

    public static string NormalizeKey(string? key)
        => key?.Trim() ?? string.Empty;

    public static string NormalizeMode(string? mode)
    {
        var normalized = mode?.Trim() ?? string.Empty;
        if (string.Equals(normalized, Shadowsocks2022InboundModes.SingleUser, StringComparison.OrdinalIgnoreCase))
        {
            return Shadowsocks2022InboundModes.SingleUser;
        }

        if (string.Equals(normalized, Shadowsocks2022InboundModes.MultiUser, StringComparison.OrdinalIgnoreCase))
        {
            return Shadowsocks2022InboundModes.MultiUser;
        }

        if (string.Equals(normalized, Shadowsocks2022InboundModes.Relay, StringComparison.OrdinalIgnoreCase))
        {
            return Shadowsocks2022InboundModes.Relay;
        }

        return normalized;
    }

    public static bool IsSingleUserMode(string? mode)
        => string.Equals(NormalizeMode(mode), Shadowsocks2022InboundModes.SingleUser, StringComparison.Ordinal);

    public static bool IsMultiUserMode(string? mode)
        => string.Equals(NormalizeMode(mode), Shadowsocks2022InboundModes.MultiUser, StringComparison.Ordinal);

    public static bool IsRelayMode(string? mode)
        => string.Equals(NormalizeMode(mode), Shadowsocks2022InboundModes.Relay, StringComparison.Ordinal);

    public static bool UsesManagedUsers(string? mode)
        => IsMultiUserMode(mode) || IsRelayMode(mode);

    public static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();

    public static string NormalizePlannerUserId(string? userId, string prefix, int index)
    {
        var normalizedUserId = NormalizeUserId(userId);
        return normalizedUserId.Length == 0
            ? $"{prefix}-{index + 1}"
            : normalizedUserId;
    }

    public static bool HasRelayDestination(IShadowsocks2022UserDefinition user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return HasRelayDestination(user.Address, user.Port);
    }

    public static bool HasRelayDestination(Shadowsocks2022User user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return HasRelayDestination(user.Address, user.Port);
    }

    public static bool HasRelayDestination(string? address, int port)
        => !string.IsNullOrWhiteSpace(address) || port > 0;

    public static void ValidateMethodOrThrow(string inboundTag, string? method)
    {
        if (!ShadowsocksCipherTypes.Is2022Method(NormalizeMethod(method)))
        {
            throw new InvalidOperationException(
                $"Shadowsocks inbound '{inboundTag}' uses an unsupported Shadowsocks 2022 method: {method}.");
        }
    }

    public static void ValidatePlannerServerKeyOrThrow(string inboundTag, string? key)
    {
        if (NormalizeKey(key).Length == 0)
        {
            throw new InvalidOperationException(
                $"Shadowsocks 2022 inbound '{inboundTag}' requires a server key.");
        }
    }

    public static void ValidateMultiUserMethodOrThrow(string inboundTag, string? method)
    {
        if (!ShadowsocksCipherTypes.Supports2022MultiUser(NormalizeMethod(method)))
        {
            throw new InvalidOperationException(
                $"Shadowsocks 2022 inbound '{inboundTag}' supports multi-user and relay modes only for 2022-blake3-aes-*-gcm methods.");
        }
    }

    public static void ValidateManagedUserServerKeyOrThrow(string? key)
    {
        if (NormalizeKey(key).Length == 0)
        {
            throw new InvalidOperationException(
                "Shadowsocks 2022 multi-user and relay modes require a server key.");
        }
    }

    public static Shadowsocks2022User CreateImplicitSingleUser(
        string inboundTag,
        string? serverKey,
        int level)
    {
        var normalizedKey = NormalizeKey(serverKey);
        return new Shadowsocks2022User
        {
            UserId = DefaultUserId,
            Cipher = string.Empty,
            Password = normalizedKey,
            Address = string.Empty,
            Port = 0,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, inboundTag, DefaultUserId),
            Level = Math.Max(0, level),
            BytesPerSecond = 0,
            DeviceLimit = 0
        };
    }

    public static Shadowsocks2022User CompilePlannerUserOrThrow(
        string inboundTag,
        string mode,
        string serverKey,
        IShadowsocks2022UserDefinition user,
        int level,
        int index)
    {
        ArgumentNullException.ThrowIfNull(user);

        var normalizedMode = NormalizeMode(mode);
        var normalizedUserId = NormalizePlannerUserId(
            user.UserId,
            IsRelayMode(normalizedMode) ? "unnamed-destination" : "unnamed-user",
            index);
        return CompileUserOrThrow(
            normalizedMode,
            NormalizeKey(serverKey),
            normalizedUserId,
            user.Cipher,
            user.Password,
            user.Address,
            user.Port,
            level,
            user.BytesPerSecond,
            user.DeviceLimit,
            RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, inboundTag, normalizedUserId),
            ErrorStyle.Planner,
            inboundTag);
    }

    public static Shadowsocks2022User CompileRuntimeUserOrThrow(
        string mode,
        string serverKey,
        Shadowsocks2022User user,
        Func<string, string> defaultRuntimeKeyFactory)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(defaultRuntimeKeyFactory);

        var normalizedUserId = NormalizeUserId(user.UserId);
        if (normalizedUserId.Length == 0)
        {
            throw new InvalidOperationException("Shadowsocks 2022 user requires a non-empty user id.");
        }

        var runtimeKey = string.IsNullOrWhiteSpace(user.RuntimeKey)
            ? defaultRuntimeKeyFactory(normalizedUserId)
            : user.RuntimeKey;
        return CompileUserOrThrow(
            NormalizeMode(mode),
            NormalizeKey(serverKey),
            normalizedUserId,
            user.Cipher,
            user.Password,
            user.Address,
            user.Port,
            user.Level,
            user.BytesPerSecond,
            user.DeviceLimit,
            runtimeKey,
            ErrorStyle.Runtime,
            inboundTag: null);
    }

    private static Shadowsocks2022User CompileUserOrThrow(
        string mode,
        string key,
        string userId,
        string? cipher,
        string? password,
        string? address,
        int port,
        int level,
        long bytesPerSecond,
        int deviceLimit,
        string runtimeKey,
        ErrorStyle errorStyle,
        string? inboundTag)
    {
        if (!string.IsNullOrWhiteSpace(cipher))
        {
            throw new InvalidOperationException(
                errorStyle == ErrorStyle.Planner
                    ? $"Shadowsocks 2022 inbound '{inboundTag}' requires empty per-user cipher in {mode} mode."
                    : $"Shadowsocks 2022 inbound requires empty per-user cipher in {mode} mode.");
        }

        var normalizedPassword = NormalizePasswordOrThrow(mode, key, password, errorStyle, inboundTag);
        var (normalizedAddress, normalizedPort) = NormalizeDestinationOrThrow(mode, address, port, errorStyle, inboundTag);
        return new Shadowsocks2022User
        {
            UserId = userId,
            Cipher = string.Empty,
            Password = normalizedPassword,
            Address = normalizedAddress,
            Port = normalizedPort,
            RuntimeKey = string.IsNullOrWhiteSpace(runtimeKey) ? userId : runtimeKey.Trim(),
            Level = Math.Max(0, level),
            BytesPerSecond = Math.Max(0, bytesPerSecond),
            DeviceLimit = Math.Max(0, deviceLimit)
        };
    }

    private static string NormalizePasswordOrThrow(
        string mode,
        string key,
        string? password,
        ErrorStyle errorStyle,
        string? inboundTag)
    {
        if (IsSingleUserMode(mode))
        {
            if (key.Length == 0)
            {
                throw new InvalidOperationException(
                    errorStyle == ErrorStyle.Planner
                        ? $"Shadowsocks 2022 inbound '{inboundTag}' requires a server key."
                        : "Shadowsocks 2022 single-user inbound requires a server key.");
            }

            return key;
        }

        var normalizedPassword = password?.Trim() ?? string.Empty;
        if (normalizedPassword.Length == 0)
        {
            throw new InvalidOperationException(
                errorStyle == ErrorStyle.Planner
                    ? $"Shadowsocks 2022 inbound '{inboundTag}' requires every user to define a key."
                    : "Shadowsocks 2022 user requires a non-empty key.");
        }

        return normalizedPassword;
    }

    private static (string Address, int Port) NormalizeDestinationOrThrow(
        string mode,
        string? address,
        int port,
        ErrorStyle errorStyle,
        string? inboundTag)
    {
        if (IsRelayMode(mode))
        {
            var normalizedAddress = address?.Trim() ?? string.Empty;
            var normalizedPort = port is > 0 and <= 65535 ? port : 0;
            if (normalizedAddress.Length == 0 || normalizedPort == 0)
            {
                throw new InvalidOperationException(
                    errorStyle == ErrorStyle.Planner
                        ? $"Shadowsocks 2022 inbound '{inboundTag}' relay mode requires every user to define a valid address and port."
                        : "Shadowsocks 2022 relay inbound requires a valid relay destination.");
            }

            return (normalizedAddress, normalizedPort);
        }

        if (IsSingleUserMode(mode) &&
            HasRelayDestination(address, port))
        {
            throw new InvalidOperationException(
                errorStyle == ErrorStyle.Planner
                    ? $"Shadowsocks 2022 inbound '{inboundTag}' single-user mode does not allow per-user relay destinations."
                    : "Shadowsocks 2022 single-user inbound does not allow relay destinations.");
        }

        return (string.Empty, 0);
    }
}

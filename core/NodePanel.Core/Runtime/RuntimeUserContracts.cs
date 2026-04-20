namespace NodePanel.Core.Runtime;

public interface IRuntimeUserDefinition
{
    string UserId { get; }

    int Level { get; }

    long BytesPerSecond { get; }

    int DeviceLimit { get; }
}

internal interface IRuntimeScopedUserDefinition : IRuntimeUserDefinition
{
    string RuntimeKey { get; }
}

public static class RuntimeUserKeys
{
    public static string Create(string? protocol, string? inboundTag, string? userId)
    {
        var normalizedProtocol = NormalizeProtocol(protocol);
        var normalizedInboundTag = NormalizeInboundTag(inboundTag);
        var normalizedUserId = NormalizeUserId(userId);
        if (normalizedProtocol.Length == 0 ||
            normalizedInboundTag.Length == 0 ||
            normalizedUserId.Length == 0)
        {
            return normalizedUserId;
        }

        return string.Concat(
            normalizedProtocol,
            "\u0000",
            normalizedInboundTag,
            "\u0000",
            normalizedUserId);
    }

    public static string Get(IRuntimeUserDefinition user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return user is IRuntimeScopedUserDefinition scopedUser &&
               !string.IsNullOrWhiteSpace(scopedUser.RuntimeKey)
            ? scopedUser.RuntimeKey.Trim()
            : NormalizeUserId(user.UserId);
    }

    public static bool TryParse(
        string? runtimeKey,
        out string protocol,
        out string inboundTag,
        out string userId)
    {
        protocol = string.Empty;
        inboundTag = string.Empty;
        userId = NormalizeUserId(runtimeKey);

        if (userId.Length == 0)
        {
            return false;
        }

        var normalizedRuntimeKey = runtimeKey!.Trim();
        var firstSeparatorIndex = normalizedRuntimeKey.IndexOf('\0');
        if (firstSeparatorIndex < 0)
        {
            return false;
        }

        var secondSeparatorIndex = normalizedRuntimeKey.IndexOf('\0', firstSeparatorIndex + 1);
        if (secondSeparatorIndex < 0 ||
            normalizedRuntimeKey.IndexOf('\0', secondSeparatorIndex + 1) >= 0)
        {
            return false;
        }

        protocol = NormalizeProtocol(normalizedRuntimeKey[..firstSeparatorIndex]);
        inboundTag = NormalizeInboundTag(normalizedRuntimeKey[(firstSeparatorIndex + 1)..secondSeparatorIndex]);
        userId = NormalizeUserId(normalizedRuntimeKey[(secondSeparatorIndex + 1)..]);
        return protocol.Length > 0 &&
               inboundTag.Length > 0 &&
               userId.Length > 0;
    }

    private static string NormalizeProtocol(string? protocol)
        => string.IsNullOrWhiteSpace(protocol)
            ? string.Empty
            : protocol.Trim().ToLowerInvariant();

    private static string NormalizeInboundTag(string? inboundTag)
        => string.IsNullOrWhiteSpace(inboundTag)
            ? string.Empty
            : inboundTag.Trim();

    private static string NormalizeUserId(string? userId)
        => string.IsNullOrWhiteSpace(userId)
            ? string.Empty
            : userId.Trim();
}

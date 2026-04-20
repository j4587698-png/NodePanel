namespace NodePanel.Core.Runtime;

public sealed record TrojanUser : IRuntimeUserDefinition, IRuntimeScopedUserDefinition
{
    public required string UserId { get; init; }

    public required string PasswordHash { get; init; }

    public string RuntimeKey { get; init; } = string.Empty;

    public int Level { get; init; }

    public required long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

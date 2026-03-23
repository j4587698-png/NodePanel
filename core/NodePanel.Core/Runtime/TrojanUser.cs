namespace NodePanel.Core.Runtime;

public sealed record TrojanUser : IRuntimeUserDefinition
{
    public required string UserId { get; init; }

    public required string PasswordHash { get; init; }

    public required long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

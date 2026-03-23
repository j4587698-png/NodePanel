namespace NodePanel.Core.Protocol;

public enum TrojanCommand : byte
{
    Connect = 1,
    Associate = 3
}

public sealed record TrojanRequest
{
    public required string UserHash { get; init; }

    public required TrojanCommand Command { get; init; }

    public required string TargetHost { get; init; }

    public required int TargetPort { get; init; }
}

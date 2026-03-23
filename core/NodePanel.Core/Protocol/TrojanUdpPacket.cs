namespace NodePanel.Core.Protocol;

public sealed record TrojanUdpPacket
{
    public required string DestinationHost { get; init; }

    public required int DestinationPort { get; init; }

    public required byte[] Payload { get; init; }
}

namespace NodePanel.Core.Runtime;

public sealed record UserTrafficSnapshot
{
    public string RuntimeKey { get; init; } = string.Empty;

    public string Protocol { get; init; } = string.Empty;

    public string InboundTag { get; init; } = string.Empty;

    public required string UserId { get; init; }

    public required long UploadBytes { get; init; }

    public required long DownloadBytes { get; init; }
}

public sealed record UserSessionSnapshot
{
    public string RuntimeKey { get; init; } = string.Empty;

    public string Protocol { get; init; } = string.Empty;

    public string InboundTag { get; init; } = string.Empty;

    public required string UserId { get; init; }

    public required int ActiveSessions { get; init; }

    public IReadOnlyList<string> RemoteIps { get; init; } = Array.Empty<string>();

    public int ActiveRemoteIpCount => RemoteIps.Count;
}

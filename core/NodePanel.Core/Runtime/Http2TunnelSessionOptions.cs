namespace NodePanel.Core.Runtime;

internal sealed record Http2TunnelSessionOptions
{
    public static Http2TunnelSessionOptions Default { get; } = new();

    public int InitialReceiveWindowSize { get; init; }

    public TimeSpan KeepAliveInterval { get; init; } = TimeSpan.Zero;

    public TimeSpan KeepAliveTimeout { get; init; } = TimeSpan.Zero;

    public bool PermitKeepAliveWithoutStreams { get; init; }
}

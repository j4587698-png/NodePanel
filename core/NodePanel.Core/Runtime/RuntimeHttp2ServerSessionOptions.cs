namespace NodePanel.Core.Runtime;

internal sealed record RuntimeHttp2ServerSessionOptions
{
    public static RuntimeHttp2ServerSessionOptions Default { get; } = new();

    public TimeSpan KeepAliveInterval { get; init; }

    public TimeSpan KeepAliveTimeout { get; init; }

    public bool PermitKeepAliveWithoutStreams { get; init; }

    public int InitialReceiveWindowSize { get; init; }

    public static RuntimeHttp2ServerSessionOptions Normalize(RuntimeHttp2ServerSessionOptions? options)
    {
        if (options is null)
        {
            return Default;
        }

        var keepAliveInterval = options.KeepAliveInterval > TimeSpan.Zero
            ? options.KeepAliveInterval
            : TimeSpan.Zero;
        var keepAliveTimeout = options.KeepAliveTimeout > TimeSpan.Zero
            ? options.KeepAliveTimeout
            : TimeSpan.Zero;
        var initialReceiveWindowSize = Math.Max(0, options.InitialReceiveWindowSize);

        if (keepAliveInterval == TimeSpan.Zero &&
            keepAliveTimeout == TimeSpan.Zero &&
            initialReceiveWindowSize == 0 &&
            !options.PermitKeepAliveWithoutStreams)
        {
            return Default;
        }

        return new RuntimeHttp2ServerSessionOptions
        {
            KeepAliveInterval = keepAliveInterval,
            KeepAliveTimeout = keepAliveTimeout,
            PermitKeepAliveWithoutStreams = options.PermitKeepAliveWithoutStreams,
            InitialReceiveWindowSize = initialReceiveWindowSize
        };
    }
}

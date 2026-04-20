namespace NodePanel.Core.Runtime;

public interface IInboundGrpcDefinition
{
    string GrpcServiceName { get; }

    string GrpcAuthority { get; }

    bool GrpcMultiMode { get; }

    string GrpcUserAgent { get; }

    int GrpcIdleTimeoutSeconds { get; }

    int GrpcHealthCheckTimeoutSeconds { get; }

    bool GrpcPermitWithoutStream { get; }

    int GrpcInitialWindowSize { get; }
}

public sealed record RuntimeGrpcTransportOptions
{
    public static RuntimeGrpcTransportOptions Empty { get; } = new();

    public string ServiceName { get; init; } = string.Empty;

    public string Authority { get; init; } = string.Empty;

    public bool MultiMode { get; init; }

    public string UserAgent { get; init; } = string.Empty;

    public int IdleTimeoutSeconds { get; init; }

    public int HealthCheckTimeoutSeconds { get; init; }

    public bool PermitWithoutStream { get; init; }

    public int InitialWindowSize { get; init; }

    public string TunMethodPath => RuntimeGrpcUtilities.ResolveMethodPath(ServiceName, multiMode: false);

    public string TunMultiMethodPath => RuntimeGrpcUtilities.ResolveMethodPath(ServiceName, multiMode: true);

    public string MethodPath => RuntimeGrpcUtilities.ResolveMethodPath(ServiceName, MultiMode);

    public bool TryResolveRequestMode(string? methodPath, out bool multiMode)
        => TryResolveRequestPath(methodPath, out _, out multiMode);

    internal bool TryResolveRequestPath(
        string? methodPath,
        out string normalizedMethodPath,
        out bool multiMode)
    {
        if (TryMatchMethodPath(methodPath, TunMethodPath, out normalizedMethodPath))
        {
            multiMode = false;
            return true;
        }

        if (TryMatchMethodPath(methodPath, TunMultiMethodPath, out normalizedMethodPath))
        {
            multiMode = true;
            return true;
        }

        normalizedMethodPath = string.Empty;
        multiMode = false;
        return false;
    }

    private static bool TryMatchMethodPath(
        string? methodPath,
        string expectedMethodPath,
        out string normalizedMethodPath)
    {
        if (string.Equals(methodPath, expectedMethodPath, StringComparison.Ordinal))
        {
            normalizedMethodPath = expectedMethodPath;
            return true;
        }

        if (!TryNormalizeMethodPath(methodPath, out normalizedMethodPath))
        {
            return false;
        }

        return string.Equals(normalizedMethodPath, expectedMethodPath, StringComparison.Ordinal);
    }

    private static bool TryNormalizeMethodPath(string? methodPath, out string normalizedMethodPath)
    {
        if (string.IsNullOrEmpty(methodPath) ||
            !methodPath.StartsWith("/", StringComparison.Ordinal))
        {
            normalizedMethodPath = string.Empty;
            return false;
        }

        var lastSlashIndex = methodPath.LastIndexOf('/');
        if (lastSlashIndex <= 0 || lastSlashIndex == methodPath.Length - 1)
        {
            normalizedMethodPath = string.Empty;
            return false;
        }

        var rawServiceName = methodPath[1..lastSlashIndex];
        var rawStreamName = methodPath[(lastSlashIndex + 1)..];
        if (!TryNormalizeMethodPathComponent(rawServiceName, splitOnSlash: true, out var normalizedServiceName) ||
            !TryNormalizeMethodPathComponent(rawStreamName, splitOnSlash: false, out var normalizedStreamName))
        {
            normalizedMethodPath = string.Empty;
            return false;
        }

        normalizedMethodPath = "/" + normalizedServiceName + "/" + normalizedStreamName;
        return true;
    }

    private static bool TryNormalizeMethodPathComponent(
        string value,
        bool splitOnSlash,
        out string normalizedValue)
    {
        try
        {
            var unescapedValue = Uri.UnescapeDataString(value);
            if (!splitOnSlash)
            {
                normalizedValue = Uri.EscapeDataString(unescapedValue);
                return true;
            }

            var segments = unescapedValue.Split('/', StringSplitOptions.None);
            for (var i = 0; i < segments.Length; i++)
            {
                segments[i] = Uri.EscapeDataString(segments[i]);
            }

            normalizedValue = string.Join("/", segments);
            return true;
        }
        catch (ArgumentException)
        {
            normalizedValue = string.Empty;
            return false;
        }
        catch (UriFormatException)
        {
            normalizedValue = string.Empty;
            return false;
        }
    }

    public static RuntimeGrpcTransportOptions Normalize(
        IInboundGrpcDefinition? definition,
        bool enabled)
    {
        if (!enabled || definition is null)
        {
            return Empty;
        }

        return new RuntimeGrpcTransportOptions
        {
            ServiceName = RuntimeGrpcUtilities.NormalizeServiceName(definition.GrpcServiceName),
            Authority = RuntimeGrpcUtilities.NormalizeAuthority(definition.GrpcAuthority),
            MultiMode = definition.GrpcMultiMode,
            UserAgent = RuntimeGrpcUtilities.NormalizeUserAgent(definition.GrpcUserAgent),
            IdleTimeoutSeconds = Math.Max(0, definition.GrpcIdleTimeoutSeconds),
            HealthCheckTimeoutSeconds = Math.Max(0, definition.GrpcHealthCheckTimeoutSeconds),
            PermitWithoutStream = definition.GrpcPermitWithoutStream,
            InitialWindowSize = Math.Max(0, definition.GrpcInitialWindowSize)
        };
    }
}

namespace NodePanel.Core.Runtime;

public static class RuntimeGrpcUtilities
{
    public static string NormalizeServiceName(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim();

    public static string NormalizeAuthority(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim();

    public static string NormalizeUserAgent(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim();

    public static string ResolveServiceName(string? rawServiceName)
    {
        var serviceName = NormalizeServiceName(rawServiceName);
        if (!serviceName.StartsWith("/", StringComparison.Ordinal))
        {
            return EscapePathSegment(serviceName);
        }

        var lastSlashIndex = serviceName.LastIndexOf('/');
        if (lastSlashIndex < 1)
        {
            lastSlashIndex = 1;
        }

        var rawPath = serviceName[1..lastSlashIndex];
        if (rawPath.Length == 0)
        {
            return string.Empty;
        }

        var parts = rawPath
            .Split('/', StringSplitOptions.None)
            .Select(static value => EscapePathSegment(value));
        return string.Join("/", parts);
    }

    public static string ResolveTunStreamName(string? rawServiceName)
    {
        var serviceName = NormalizeServiceName(rawServiceName);
        if (!serviceName.StartsWith("/", StringComparison.Ordinal))
        {
            return "Tun";
        }

        var endingPath = serviceName[(serviceName.LastIndexOf('/') + 1)..];
        var streamName = endingPath.Split('|', StringSplitOptions.None)[0];
        return EscapePathSegment(streamName);
    }

    public static string ResolveTunMultiStreamName(string? rawServiceName)
    {
        var serviceName = NormalizeServiceName(rawServiceName);
        if (!serviceName.StartsWith("/", StringComparison.Ordinal))
        {
            return "TunMulti";
        }

        var endingPath = serviceName[(serviceName.LastIndexOf('/') + 1)..];
        var streamNames = endingPath.Split('|', StringSplitOptions.None);
        return EscapePathSegment(streamNames.Length == 1 ? streamNames[0] : streamNames[1]);
    }

    public static string ResolveMethodPath(string? rawServiceName, bool multiMode)
        => "/" + ResolveServiceName(rawServiceName) + "/" +
           (multiMode ? ResolveTunMultiStreamName(rawServiceName) : ResolveTunStreamName(rawServiceName));

    private static string EscapePathSegment(string value)
        => Uri.EscapeDataString(value ?? string.Empty);
}

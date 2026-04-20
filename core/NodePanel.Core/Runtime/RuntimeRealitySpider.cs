using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NodePanel.Core.Runtime;

internal static partial class RuntimeRealitySpider
{
    private static readonly Lock PathCacheLock = new();
    private static readonly Dictionary<string, HashSet<string>> CachedPaths = new(StringComparer.Ordinal);

    public static async ValueTask ProcessInvalidConnectionAsync(
        Stream transportStream,
        string serverName,
        RuntimeRealityOptions options,
        string localAddress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverName);
        ArgumentException.ThrowIfNullOrWhiteSpace(localAddress);

        var normalizedOptions = RuntimeRealityOptions.Normalize(options, applyRealityDefaults: true);
        _ = cancellationToken;
        var spiderCancellationToken = CancellationToken.None;
        _ = RunHttp2SpiderInBackgroundAsync(
            transportStream,
            serverName.Trim(),
            normalizedOptions,
            localAddress.Trim(),
            spiderCancellationToken);

        await Task.Yield();

        var delayMilliseconds = PickSpiderRange(normalizedOptions.SpiderY, 8, 9);
        if (delayMilliseconds > 0)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(delayMilliseconds), spiderCancellationToken).ConfigureAwait(false);
        }

        throw new RuntimeRealityProcessedInvalidConnectionException();
    }

    private static async Task RunHttp2SpiderInBackgroundAsync(
        Stream transportStream,
        string serverName,
        RuntimeRealityOptions options,
        string localAddress,
        CancellationToken cancellationToken)
    {
        try
        {
            await RunHttp2SpiderAsync(
                    transportStream,
                    serverName,
                    options,
                    localAddress,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static async Task RunHttp2SpiderAsync(
        Stream transportStream,
        string serverName,
        RuntimeRealityOptions options,
        string localAddress,
        CancellationToken cancellationToken)
    {
        RuntimeRealityDebugLogger.TryWriteLine(
            options.Show,
            $"REALITY localAddr: {localAddress}\tDialTLSContext");
        await using var session = await Http2TunnelSession
            .CreateAsync(transportStream, cancellationToken)
            .ConfigureAwait(false);

        var firstPath = GetRandomPath(serverName, options.SpiderX);
        var firstUrl = BuildAbsoluteUrl(serverName, firstPath);
        await SendHttp2GetAsync(
                session,
                serverName,
                firstPath,
                referer: null,
                options,
                localAddress,
                logUserAgent: true,
                cancellationToken)
            .ConfigureAwait(false);

        var concurrency = ToNonNegativeInt(PickSpiderRange(options.SpiderY, 2, 3));
        if (concurrency == 0)
        {
            return;
        }

        var workerTasks = new Task[concurrency];
        for (var worker = 0; worker < workerTasks.Length; worker++)
        {
            workerTasks[worker] = RunHttp2SpiderWorkerAsync(
                session,
                serverName,
                firstUrl,
                options,
                localAddress,
                cancellationToken);
        }

        await Task.WhenAll(workerTasks).ConfigureAwait(false);
    }

    private static async Task RunHttp2SpiderWorkerAsync(
        Http2TunnelSession session,
        string serverName,
        string firstUrl,
        RuntimeRealityOptions options,
        string localAddress,
        CancellationToken cancellationToken)
    {
        var times = ToNonNegativeInt(PickSpiderRange(options.SpiderY, 4, 5));
        var referer = firstUrl;
        for (var iteration = 0; iteration < times; iteration++)
        {
            var path = GetRandomPath(serverName, options.SpiderX);
            await SendHttp2GetAsync(
                    session,
                    serverName,
                    path,
                    referer,
                    options,
                    localAddress,
                    logUserAgent: false,
                    cancellationToken)
                .ConfigureAwait(false);
            referer = BuildAbsoluteUrl(serverName, path);

            var intervalMilliseconds = PickSpiderRange(options.SpiderY, 6, 7);
            if (intervalMilliseconds > 0)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(intervalMilliseconds), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static async Task SendHttp2GetAsync(
        Http2TunnelSession session,
        string serverName,
        string path,
        string? referer,
        RuntimeRealityOptions options,
        string localAddress,
        bool logUserAgent,
        CancellationToken cancellationToken)
    {
        var requestPath = NormalizeRequestPath(path);
        var requestHeaders = CreateRequestHeaders(referer, options.SpiderY);
        if (logUserAgent &&
            requestHeaders.TryGetValue("user-agent", out var userAgent))
        {
            RuntimeRealityDebugLogger.TryWriteLine(
                options.Show,
                $"REALITY localAddr: {localAddress}\treq.UserAgent(): {userAgent}");
        }

        await using var responseStream = await session
            .OpenGetStreamAsync(
                authority: serverName,
                scheme: "https",
                path: requestPath,
                requestHeaders,
                cancellationToken)
            .ConfigureAwait(false);

        var body = await ReadAllBytesAsync(responseStream, cancellationToken).ConfigureAwait(false);
        var pathCount = UpdateCachedPaths(serverName, options.SpiderX, body);
        RuntimeRealityDebugLogger.TryWriteLine(
            options.Show,
            $"REALITY localAddr: {localAddress}\treq.Referer(): {BuildAbsoluteUrl(serverName, requestPath)}");
        RuntimeRealityDebugLogger.TryWriteLine(
            options.Show,
            $"REALITY localAddr: {localAddress}\tlen(body): {body.Length}");
        RuntimeRealityDebugLogger.TryWriteLine(
            options.Show,
            $"REALITY localAddr: {localAddress}\tlen(paths): {pathCount}");
    }

    private static IReadOnlyDictionary<string, string> CreateRequestHeaders(
        string? referer,
        IReadOnlyList<long> spiderY)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["user-agent"] = RuntimeInternetHttpUtilities.DefaultChromeUserAgent
        };

        if (!string.IsNullOrWhiteSpace(referer))
        {
            headers["referer"] = referer.Trim();
        }

        var paddingLength = checked((int)Math.Max(0, PickSpiderRange(spiderY, 0, 1)));
        headers["cookie"] = "padding=" + new string('0', paddingLength);

        return headers;
    }

    private static byte[] ReadBodyToBytes(MemoryStream buffer)
        => buffer.TryGetBuffer(out var segment)
            ? segment.AsSpan(0, checked((int)buffer.Length)).ToArray()
            : buffer.ToArray();

    private static async Task<byte[]> ReadAllBytesAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[4 * 1024];

        while (true)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return ReadBodyToBytes(buffer);
            }

            buffer.Write(chunk, 0, read);
        }
    }

    private static int UpdateCachedPaths(
        string serverName,
        string fallbackPath,
        ReadOnlySpan<byte> body)
    {
        lock (PathCacheLock)
        {
            var paths = GetOrCreatePathSetLocked(serverName, fallbackPath);
            if (body.Length == 0)
            {
                return paths.Count;
            }

            var prefix = "https://" + serverName.Trim();
            var html = Encoding.UTF8.GetString(body);
            foreach (Match match in HrefExpression().Matches(html))
            {
                if (!match.Success)
                {
                    continue;
                }

                var value = match.Groups[1].Value.Trim();
                if (value.StartsWith(prefix, StringComparison.Ordinal))
                {
                    value = value[prefix.Length..];
                }

                if (value.Length == 0 ||
                    value.Contains('.', StringComparison.Ordinal))
                {
                    continue;
                }

                if (value[0] != '/')
                {
                    continue;
                }

                paths.Add(value);
            }

            return paths.Count;
        }
    }

    private static string GetRandomPath(string serverName, string fallbackPath)
    {
        lock (PathCacheLock)
        {
            var paths = GetOrCreatePathSetLocked(serverName, fallbackPath);
            if (paths.Count == 0)
            {
                return "/";
            }

            var targetIndex = paths.Count == 1
                ? 0
                : RandomNumberGenerator.GetInt32(paths.Count);
            var index = 0;
            foreach (var path in paths)
            {
                if (index == targetIndex)
                {
                    return path;
                }

                index++;
            }

            return "/";
        }
    }

    private static HashSet<string> GetOrCreatePathSetLocked(string serverName, string fallbackPath)
    {
        if (!CachedPaths.TryGetValue(serverName, out var paths))
        {
            paths = new HashSet<string>(StringComparer.Ordinal)
            {
                NormalizeCachePath(fallbackPath)
            };
            CachedPaths[serverName] = paths;
            return paths;
        }

        if (paths.Count == 0)
        {
            paths.Add(NormalizeCachePath(fallbackPath));
        }

        return paths;
    }

    private static string NormalizeCachePath(string path)
    {
        var normalized = string.IsNullOrWhiteSpace(path)
            ? "/"
            : path.Trim();
        return normalized[0] == '/'
            ? normalized
            : "/" + normalized;
    }

    private static string NormalizeRequestPath(string path)
    {
        var normalized = NormalizeCachePath(path);
        var fragmentIndex = normalized.IndexOf('#', StringComparison.Ordinal);
        return fragmentIndex >= 0
            ? normalized[..fragmentIndex]
            : normalized;
    }

    private static string BuildAbsoluteUrl(string serverName, string path)
        => "https://" + serverName.Trim() + NormalizeRequestPath(path);

    private static long PickSpiderRange(
        IReadOnlyList<long> values,
        int firstIndex,
        int secondIndex)
    {
        var first = GetSpiderValue(values, firstIndex);
        var second = GetSpiderValue(values, secondIndex);
        var minimum = Math.Min(first, second);
        var maximum = Math.Max(first, second);
        if (minimum == maximum)
        {
            return minimum;
        }

        if (minimum < int.MinValue || maximum > int.MaxValue)
        {
            return minimum;
        }

        var range = checked((int)(maximum - minimum));
        if (range <= 0)
        {
            return minimum;
        }

        return minimum + RandomNumberGenerator.GetInt32(range);
    }

    private static int ToNonNegativeInt(long value)
    {
        if (value <= 0)
        {
            return 0;
        }

        return value >= int.MaxValue
            ? int.MaxValue
            : (int)value;
    }

    private static long GetSpiderValue(IReadOnlyList<long> values, int index)
        => values is { Count: > 0 } && index >= 0 && index < values.Count
            ? values[index]
            : 0;

    [GeneratedRegex("href=\"([/h].*?)\"", RegexOptions.CultureInvariant)]
    private static partial Regex HrefExpression();
}

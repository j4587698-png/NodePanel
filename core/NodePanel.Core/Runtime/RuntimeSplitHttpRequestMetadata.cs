namespace NodePanel.Core.Runtime;

// Mirrors xray-core transport/internet/splithttp/config.go metadata behavior
// so client and future server-side SplitHTTP flows can share one implementation.
internal static class RuntimeSplitHttpRequestMetadata
{
    private const string PathPlacement = "path";
    private const string QueryPlacement = "query";
    private const string HeaderPlacement = "header";
    private const string CookiePlacement = "cookie";

    public static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        var querySeparator = normalized.IndexOf('?');
        var path = querySeparator >= 0 ? normalized[..querySeparator] : normalized;
        var query = querySeparator >= 0 ? normalized[querySeparator..] : string.Empty;

        if (!path.StartsWith("/", StringComparison.Ordinal))
        {
            path = "/" + path;
        }

        if (!path.EndsWith("/", StringComparison.Ordinal))
        {
            path += "/";
        }

        return path + query;
    }

    public static bool MatchesPathPrefix(string requestPath, string configuredPath)
    {
        var normalizedConfiguredPath = NormalizePath(configuredPath);
        var querySeparator = normalizedConfiguredPath.IndexOf('?');
        var basePath = querySeparator >= 0
            ? normalizedConfiguredPath[..querySeparator]
            : normalizedConfiguredPath;
        var normalizedRequestPath = requestPath.StartsWith("/", StringComparison.Ordinal)
            ? requestPath
            : "/" + requestPath;
        return normalizedRequestPath.StartsWith(basePath, StringComparison.Ordinal);
    }

    public static string NormalizeSessionPlacement(string value)
        => NormalizePlacement(value, "session");

    public static string NormalizeSeqPlacement(string value)
        => NormalizePlacement(value, "seq");

    public static string ResolveSessionKey(string placement, string configuredKey)
    {
        if (!string.IsNullOrWhiteSpace(configuredKey))
        {
            return configuredKey.Trim();
        }

        return NormalizeSessionPlacement(placement) switch
        {
            HeaderPlacement => "X-Session",
            QueryPlacement or CookiePlacement => "x_session",
            _ => string.Empty
        };
    }

    public static string ResolveSeqKey(string placement, string configuredKey)
    {
        if (!string.IsNullOrWhiteSpace(configuredKey))
        {
            return configuredKey.Trim();
        }

        return NormalizeSeqPlacement(placement) switch
        {
            HeaderPlacement => "X-Seq",
            QueryPlacement or CookiePlacement => "x_seq",
            _ => string.Empty
        };
    }

    public static void ApplyToRequest(
        ref string requestTarget,
        IDictionary<string, string> requestHeaders,
        string sessionPlacement,
        string sessionKey,
        string sessionId,
        string seqPlacement,
        string seqKey,
        string? seqValue)
    {
        ArgumentNullException.ThrowIfNull(requestHeaders);

        var normalizedSessionPlacement = NormalizeSessionPlacement(sessionPlacement);
        var normalizedSeqPlacement = NormalizeSeqPlacement(seqPlacement);
        var normalizedSessionKey = ResolveSessionKey(normalizedSessionPlacement, sessionKey);
        var normalizedSeqKey = ResolveSeqKey(normalizedSeqPlacement, seqKey);

        var querySeparator = requestTarget.IndexOf('?');
        var path = querySeparator >= 0 ? requestTarget[..querySeparator] : requestTarget;
        var query = querySeparator >= 0 ? requestTarget[(querySeparator + 1)..] : string.Empty;

        if (string.Equals(normalizedSessionPlacement, PathPlacement, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(sessionId))
        {
            path = AppendPathSegment(path, sessionId);
        }

        if (string.Equals(normalizedSessionPlacement, QueryPlacement, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(sessionId) &&
            !string.IsNullOrWhiteSpace(normalizedSessionKey))
        {
            query = SetQueryParameter(query, normalizedSessionKey, sessionId);
        }

        if (!string.IsNullOrWhiteSpace(seqValue) &&
            string.Equals(normalizedSeqPlacement, PathPlacement, StringComparison.Ordinal))
        {
            path = AppendPathSegment(path, seqValue);
        }

        if (!string.IsNullOrWhiteSpace(seqValue) &&
            string.Equals(normalizedSeqPlacement, QueryPlacement, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(normalizedSeqKey))
        {
            query = SetQueryParameter(query, normalizedSeqKey, seqValue);
        }

        if (string.Equals(normalizedSessionPlacement, HeaderPlacement, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(normalizedSessionKey) &&
            !string.IsNullOrWhiteSpace(sessionId))
        {
            requestHeaders[normalizedSessionKey] = sessionId;
        }
        else if (string.Equals(normalizedSessionPlacement, CookiePlacement, StringComparison.Ordinal) &&
                 !string.IsNullOrWhiteSpace(normalizedSessionKey) &&
                 !string.IsNullOrWhiteSpace(sessionId))
        {
            requestHeaders["Cookie"] = AppendCookie(
                requestHeaders.TryGetValue("Cookie", out var existingCookie) ? existingCookie : string.Empty,
                normalizedSessionKey,
                sessionId);
        }

        if (!string.IsNullOrWhiteSpace(seqValue) &&
            string.Equals(normalizedSeqPlacement, HeaderPlacement, StringComparison.Ordinal) &&
            !string.IsNullOrWhiteSpace(normalizedSeqKey))
        {
            requestHeaders[normalizedSeqKey] = seqValue;
        }
        else if (!string.IsNullOrWhiteSpace(seqValue) &&
                 string.Equals(normalizedSeqPlacement, CookiePlacement, StringComparison.Ordinal) &&
                 !string.IsNullOrWhiteSpace(normalizedSeqKey))
        {
            requestHeaders["Cookie"] = AppendCookie(
                requestHeaders.TryGetValue("Cookie", out var existingCookie) ? existingCookie : string.Empty,
                normalizedSeqKey,
                seqValue);
        }

        requestTarget = query.Length == 0 ? path : path + "?" + query;
    }

    public static (string SessionId, string SeqValue) ExtractFromRequest(
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        string configuredPath,
        string sessionPlacement,
        string sessionKey,
        string seqPlacement,
        string seqKey)
    {
        ArgumentNullException.ThrowIfNull(requestHeaders);

        var normalizedPath = NormalizePath(configuredPath);
        var normalizedPathSeparator = normalizedPath.IndexOf('?');
        var basePath = normalizedPathSeparator >= 0 ? normalizedPath[..normalizedPathSeparator] : normalizedPath;

        var requestTargetSeparator = requestTarget.IndexOf('?');
        var requestPath = requestTargetSeparator >= 0 ? requestTarget[..requestTargetSeparator] : requestTarget;
        var query = requestTargetSeparator >= 0 ? requestTarget[(requestTargetSeparator + 1)..] : string.Empty;

        var normalizedSessionPlacement = NormalizeSessionPlacement(sessionPlacement);
        var normalizedSeqPlacement = NormalizeSeqPlacement(seqPlacement);
        var normalizedSessionKey = ResolveSessionKey(normalizedSessionPlacement, sessionKey);
        var normalizedSeqKey = ResolveSeqKey(normalizedSeqPlacement, seqKey);

        string[] subpath = Array.Empty<string>();
        var pathPart = 0;
        if (string.Equals(normalizedSessionPlacement, PathPlacement, StringComparison.Ordinal) ||
            string.Equals(normalizedSeqPlacement, PathPlacement, StringComparison.Ordinal))
        {
            subpath = TryExtractSubpath(requestPath, basePath);
        }

        var sessionId = ExtractValue(
            normalizedSessionPlacement,
            normalizedSessionKey,
            ref pathPart,
            subpath,
            query,
            requestHeaders);
        var seqValue = ExtractValue(
            normalizedSeqPlacement,
            normalizedSeqKey,
            ref pathPart,
            subpath,
            query,
            requestHeaders);

        return (sessionId, seqValue);
    }

    private static string NormalizePlacement(string value, string name)
        => string.IsNullOrWhiteSpace(value)
            ? PathPlacement
            : value.Trim().ToLowerInvariant() switch
            {
                PathPlacement => PathPlacement,
                QueryPlacement => QueryPlacement,
                HeaderPlacement => HeaderPlacement,
                CookiePlacement => CookiePlacement,
                _ => throw new NotSupportedException("Unsupported SplitHTTP " + name + " placement: " + value.Trim())
            };

    private static string ExtractValue(
        string placement,
        string key,
        ref int pathPart,
        IReadOnlyList<string> subpath,
        string query,
        IReadOnlyDictionary<string, string> requestHeaders)
    {
        return placement switch
        {
            PathPlacement => ExtractPathValue(ref pathPart, subpath),
            QueryPlacement => GetQueryParameter(query, key),
            HeaderPlacement => GetHeaderValue(requestHeaders, key),
            CookiePlacement => GetCookieValue(GetHeaderValue(requestHeaders, "Cookie"), key),
            _ => string.Empty
        };
    }

    private static string ExtractPathValue(ref int pathPart, IReadOnlyList<string> subpath)
    {
        if (pathPart >= subpath.Count)
        {
            return string.Empty;
        }

        var value = subpath[pathPart];
        pathPart++;
        return value.Length == 0 ? string.Empty : Uri.UnescapeDataString(value);
    }

    private static string[] TryExtractSubpath(string requestPath, string normalizedBasePath)
    {
        var normalizedRequestPath = requestPath.StartsWith("/", StringComparison.Ordinal)
            ? requestPath
            : "/" + requestPath;

        if (!normalizedRequestPath.StartsWith(normalizedBasePath, StringComparison.Ordinal))
        {
            return Array.Empty<string>();
        }

        var suffix = normalizedRequestPath[normalizedBasePath.Length..];
        return suffix.Length == 0
            ? Array.Empty<string>()
            : suffix.Split('/', StringSplitOptions.None);
    }

    private static string GetHeaderValue(IReadOnlyDictionary<string, string> headers, string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        if (headers.TryGetValue(key, out var value))
        {
            return value;
        }

        foreach (var pair in headers)
        {
            if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }

        return string.Empty;
    }

    private static string GetQueryParameter(string query, string key)
    {
        if (string.IsNullOrWhiteSpace(query) || string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        var normalizedQuery = query.StartsWith("?", StringComparison.Ordinal)
            ? query[1..]
            : query;
        foreach (var segment in normalizedQuery.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = segment.IndexOf('=');
            var currentKey = separator >= 0 ? segment[..separator] : segment;
            if (!string.Equals(Uri.UnescapeDataString(currentKey), key, StringComparison.Ordinal))
            {
                continue;
            }

            var currentValue = separator >= 0 ? segment[(separator + 1)..] : string.Empty;
            return Uri.UnescapeDataString(currentValue);
        }

        return string.Empty;
    }

    private static string GetCookieValue(string cookieHeader, string key)
    {
        if (string.IsNullOrWhiteSpace(cookieHeader) || string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        foreach (var segment in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = segment.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            var separator = trimmed.IndexOf('=');
            var currentKey = separator >= 0 ? trimmed[..separator].Trim() : trimmed;
            if (!string.Equals(currentKey, key, StringComparison.Ordinal))
            {
                continue;
            }

            return separator >= 0 ? trimmed[(separator + 1)..].Trim() : string.Empty;
        }

        return string.Empty;
    }

    private static string AppendPathSegment(string path, string value)
    {
        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }

        if (!path.EndsWith("/", StringComparison.Ordinal))
        {
            path += "/";
        }

        return path + Uri.EscapeDataString(value);
    }

    private static string SetQueryParameter(string query, string key, string value)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return query;
        }

        var encodedKey = Uri.EscapeDataString(key);
        var encodedValue = Uri.EscapeDataString(value);
        var segments = query.Length == 0
            ? new List<string>()
            : query
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Where(segment =>
                {
                    var separator = segment.IndexOf('=');
                    var currentKey = separator >= 0 ? segment[..separator] : segment;
                    return !string.Equals(currentKey, encodedKey, StringComparison.Ordinal);
                })
                .ToList();
        segments.Add(encodedKey + "=" + encodedValue);
        return string.Join("&", segments);
    }

    private static string AppendCookie(string existingCookie, string key, string value)
        => string.IsNullOrWhiteSpace(existingCookie)
            ? key + "=" + value
            : existingCookie.Trim() + "; " + key + "=" + value;
}

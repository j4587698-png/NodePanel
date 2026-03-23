namespace NodePanel.Core.Runtime;

internal static class TrojanFallbackSelector
{
    public static ITrojanFallbackDefinition? Select(
        IReadOnlyList<ITrojanFallbackDefinition> fallbacks,
        string serverName,
        string alpn,
        ReadOnlySpan<byte> initialPayload)
    {
        ArgumentNullException.ThrowIfNull(fallbacks);

        if (fallbacks.Count == 0)
        {
            return null;
        }

        var lookup = BuildLookup(fallbacks);

        var selectedName = SelectName(lookup, NormalizeLookupValue(serverName));
        if (!lookup.TryGetValue(selectedName, out var alpnLookup))
        {
            if (!lookup.TryGetValue(string.Empty, out alpnLookup))
            {
                return null;
            }
        }

        var selectedAlpn = SelectAlpn(alpnLookup, NormalizeLookupValue(alpn));
        if (!alpnLookup.TryGetValue(selectedAlpn, out var pathLookup))
        {
            if (!alpnLookup.TryGetValue(string.Empty, out pathLookup))
            {
                return null;
            }
        }

        var selectedPath = SelectPath(pathLookup, initialPayload);
        return pathLookup.TryGetValue(selectedPath, out var fallback) ? fallback : null;
    }

    private static Dictionary<string, Dictionary<string, Dictionary<string, ITrojanFallbackDefinition>>> BuildLookup(
        IReadOnlyList<ITrojanFallbackDefinition> fallbacks)
    {
        var lookup = new Dictionary<string, Dictionary<string, Dictionary<string, ITrojanFallbackDefinition>>>(StringComparer.Ordinal);

        foreach (var fallback in fallbacks)
        {
            var normalizedName = NormalizeLookupValue(fallback.Name);
            var normalizedAlpn = NormalizeLookupValue(fallback.Alpn);
            var normalizedPath = NormalizePathValue(fallback.Path);

            if (!lookup.TryGetValue(normalizedName, out var alpnLookup))
            {
                alpnLookup = new Dictionary<string, Dictionary<string, ITrojanFallbackDefinition>>(StringComparer.Ordinal);
                lookup[normalizedName] = alpnLookup;
            }

            if (!alpnLookup.TryGetValue(normalizedAlpn, out var pathLookup))
            {
                pathLookup = new Dictionary<string, ITrojanFallbackDefinition>(StringComparer.Ordinal);
                alpnLookup[normalizedAlpn] = pathLookup;
            }

            pathLookup[normalizedPath] = fallback;
        }

        if (lookup.TryGetValue(string.Empty, out var defaultNameLookup))
        {
            foreach (var (name, alpnLookup) in lookup)
            {
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                foreach (var defaultAlpn in defaultNameLookup.Keys)
                {
                    if (!alpnLookup.ContainsKey(defaultAlpn))
                    {
                        alpnLookup[defaultAlpn] = new Dictionary<string, ITrojanFallbackDefinition>(StringComparer.Ordinal);
                    }
                }
            }
        }

        foreach (var alpnLookup in lookup.Values)
        {
            if (!alpnLookup.TryGetValue(string.Empty, out var defaultPathLookup))
            {
                continue;
            }

            foreach (var (alpnKey, pathLookup) in alpnLookup)
            {
                if (string.IsNullOrEmpty(alpnKey))
                {
                    continue;
                }

                foreach (var (path, fallback) in defaultPathLookup)
                {
                    pathLookup.TryAdd(path, fallback);
                }
            }
        }

        if (defaultNameLookup is null)
        {
            return lookup;
        }

        foreach (var (name, alpnLookup) in lookup)
        {
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }

            foreach (var (defaultAlpn, defaultPathLookup) in defaultNameLookup)
            {
                if (!alpnLookup.TryGetValue(defaultAlpn, out var pathLookup))
                {
                    pathLookup = new Dictionary<string, ITrojanFallbackDefinition>(StringComparer.Ordinal);
                    alpnLookup[defaultAlpn] = pathLookup;
                }

                foreach (var (path, fallback) in defaultPathLookup)
                {
                    pathLookup.TryAdd(path, fallback);
                }
            }
        }

        return lookup;
    }

    private static string SelectName(
        IReadOnlyDictionary<string, Dictionary<string, Dictionary<string, ITrojanFallbackDefinition>>> lookup,
        string serverName)
    {
        var selectedName = serverName;

        if (lookup.Count > 1 || !lookup.ContainsKey(string.Empty))
        {
            if (!string.IsNullOrEmpty(selectedName) && !lookup.ContainsKey(selectedName))
            {
                var match = string.Empty;
                foreach (var candidate in lookup.Keys)
                {
                    if (string.IsNullOrEmpty(candidate))
                    {
                        continue;
                    }

                    if (selectedName.Contains(candidate, StringComparison.Ordinal) && candidate.Length > match.Length)
                    {
                        match = candidate;
                    }
                }

                selectedName = match;
            }
        }

        return lookup.ContainsKey(selectedName) ? selectedName : string.Empty;
    }

    private static string SelectAlpn(
        IReadOnlyDictionary<string, Dictionary<string, ITrojanFallbackDefinition>> alpnLookup,
        string alpn)
        => alpnLookup.ContainsKey(alpn) ? alpn : string.Empty;

    private static string SelectPath(
        IReadOnlyDictionary<string, ITrojanFallbackDefinition> pathLookup,
        ReadOnlySpan<byte> initialPayload)
    {
        if (pathLookup.Count > 1 || !pathLookup.ContainsKey(string.Empty))
        {
            var extractedPath = HttpRequestProbe.ExtractRequestPath(initialPayload);
            if (!string.IsNullOrEmpty(extractedPath) && pathLookup.ContainsKey(extractedPath))
            {
                return extractedPath;
            }
        }

        return string.Empty;
    }

    private static string NormalizeLookupValue(string value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToLowerInvariant();

    private static string NormalizePathValue(string value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().StartsWith("/", StringComparison.Ordinal)
                ? value.Trim()
                : "/" + value.Trim();
}

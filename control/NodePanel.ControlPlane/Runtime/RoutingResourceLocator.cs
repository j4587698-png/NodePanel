using NodePanel.ControlPlane.Configuration;

namespace NodePanel.ControlPlane.Runtime;

public static class RoutingResourceLocator
{
    public const string AssetLocationEnvironmentName = "xray.location.asset";
    public const string AssetLocationAlternateEnvironmentName = "XRAY_LOCATION_ASSET";

    private static readonly StringComparer PathComparer =
        OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    public static NodeServiceConfig ApplyDefaults(
        NodeServiceConfig config,
        string? baseDirectory = null,
        string? currentDirectory = null,
        Func<string, string?>? environmentReader = null)
    {
        ArgumentNullException.ThrowIfNull(config);

        environmentReader ??= Environment.GetEnvironmentVariable;

        var normalizedBaseDirectory = NormalizeDirectory(
            string.IsNullOrWhiteSpace(baseDirectory) ? AppContext.BaseDirectory : baseDirectory);
        var normalizedCurrentDirectory = NormalizeDirectory(
            string.IsNullOrWhiteSpace(currentDirectory) ? Environment.CurrentDirectory : currentDirectory);
        var normalizedResources = NormalizeResources(config.RoutingResources);
        var configuredDirectory = ResolveConfiguredDirectory(normalizedResources.ResourceDirectory, normalizedBaseDirectory);
        var environmentAssetDirectory = ResolveEnvironmentAssetDirectory(environmentReader, normalizedBaseDirectory);
        var candidateDirectories = BuildCandidateDirectories(
            configuredDirectory,
            environmentAssetDirectory,
            normalizedBaseDirectory,
            normalizedCurrentDirectory);

        var defaultDirectory = ResolveDefaultDirectory(candidateDirectories, configuredDirectory, normalizedBaseDirectory);
        var resolvedGeoSitePath = ResolveConfiguredFilePath(
            normalizedResources.GeoSitePath,
            configuredDirectory,
            defaultDirectory);
        if (resolvedGeoSitePath.Length == 0)
        {
            resolvedGeoSitePath = ProbeDefaultFile(candidateDirectories, "geosite.dat");
        }

        var resolvedGeoIpPath = ResolveConfiguredFilePath(
            normalizedResources.GeoIpPath,
            configuredDirectory,
            defaultDirectory);
        if (resolvedGeoIpPath.Length == 0)
        {
            resolvedGeoIpPath = ProbeDefaultFile(candidateDirectories, "geoip.dat");
        }

        var resolvedResourceDirectory = configuredDirectory.Length > 0
            ? configuredDirectory
            : ResolveInferredResourceDirectory(
                resolvedGeoSitePath,
                resolvedGeoIpPath,
                defaultDirectory);

        return config with
        {
            RoutingResources = normalizedResources with
            {
                ResourceDirectory = resolvedResourceDirectory,
                GeoSitePath = resolvedGeoSitePath,
                GeoIpPath = resolvedGeoIpPath
            }
        };
    }

    private static RoutingResourceOptions NormalizeResources(RoutingResourceOptions? resources)
    {
        var normalized = resources ?? new RoutingResourceOptions();
        return normalized with
        {
            ResourceDirectory = normalized.ResourceDirectory?.Trim() ?? string.Empty,
            GeoSitePath = normalized.GeoSitePath?.Trim() ?? string.Empty,
            GeoIpPath = normalized.GeoIpPath?.Trim() ?? string.Empty
        };
    }

    private static string ResolveEnvironmentAssetDirectory(
        Func<string, string?> environmentReader,
        string baseDirectory)
    {
        ArgumentNullException.ThrowIfNull(environmentReader);

        var value =
            environmentReader(AssetLocationEnvironmentName) ??
            environmentReader(AssetLocationAlternateEnvironmentName) ??
            string.Empty;
        return ResolveConfiguredDirectory(value, baseDirectory);
    }

    private static string ResolveConfiguredDirectory(string value, string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        return NormalizeDirectory(
            Path.IsPathFullyQualified(normalized)
                ? normalized
                : Path.Combine(baseDirectory, normalized));
    }

    private static string ResolveConfiguredFilePath(
        string value,
        string configuredDirectory,
        string defaultDirectory)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        if (Path.IsPathFullyQualified(normalized))
        {
            return Path.GetFullPath(normalized);
        }

        var anchorDirectory = configuredDirectory.Length > 0 ? configuredDirectory : defaultDirectory;
        return anchorDirectory.Length == 0
            ? Path.GetFullPath(normalized)
            : Path.GetFullPath(Path.Combine(anchorDirectory, normalized));
    }

    private static string ResolveDefaultDirectory(
        IReadOnlyList<string> candidateDirectories,
        string configuredDirectory,
        string baseDirectory)
    {
        if (configuredDirectory.Length > 0)
        {
            return configuredDirectory;
        }

        for (var index = 0; index < candidateDirectories.Count; index++)
        {
            if (Directory.Exists(candidateDirectories[index]))
            {
                return candidateDirectories[index];
            }
        }

        return baseDirectory;
    }

    private static string ResolveInferredResourceDirectory(
        string geoSitePath,
        string geoIpPath,
        string defaultDirectory)
    {
        var geoSiteDirectory = GetParentDirectory(geoSitePath);
        var geoIpDirectory = GetParentDirectory(geoIpPath);
        if (geoSiteDirectory.Length > 0 &&
            geoIpDirectory.Length > 0 &&
            PathComparer.Equals(geoSiteDirectory, geoIpDirectory))
        {
            return geoSiteDirectory;
        }

        if (geoSiteDirectory.Length > 0)
        {
            return geoSiteDirectory;
        }

        if (geoIpDirectory.Length > 0)
        {
            return geoIpDirectory;
        }

        return defaultDirectory;
    }

    private static IReadOnlyList<string> BuildCandidateDirectories(
        string configuredDirectory,
        string environmentAssetDirectory,
        string baseDirectory,
        string currentDirectory)
    {
        var candidates = new List<string>();
        if (configuredDirectory.Length > 0)
        {
            AddCandidateDirectories(candidates, configuredDirectory);
            return candidates;
        }

        if (environmentAssetDirectory.Length > 0)
        {
            AddCandidateDirectories(candidates, environmentAssetDirectory);
        }

        AddCandidateDirectories(candidates, baseDirectory);
        if (!PathComparer.Equals(currentDirectory, baseDirectory))
        {
            AddCandidateDirectories(candidates, currentDirectory);
        }

        if (!OperatingSystem.IsWindows())
        {
            AddCandidateDirectories(candidates, "/usr/local/share/xray");
            AddCandidateDirectories(candidates, "/usr/share/xray");
            AddCandidateDirectories(candidates, "/opt/share/xray");
        }

        return candidates;
    }

    private static void AddCandidateDirectories(List<string> candidates, string directory)
    {
        AddCandidate(candidates, directory);
        AddCandidate(candidates, Path.Combine(directory, "config"));
    }

    private static void AddCandidate(List<string> candidates, string directory)
    {
        var normalized = NormalizeDirectory(directory);
        if (normalized.Length == 0)
        {
            return;
        }

        if (!candidates.Contains(normalized, PathComparer))
        {
            candidates.Add(normalized);
        }
    }

    private static string ProbeDefaultFile(IReadOnlyList<string> directories, string fileName)
    {
        for (var index = 0; index < directories.Count; index++)
        {
            var path = Path.Combine(directories[index], fileName);
            if (File.Exists(path))
            {
                return path;
            }
        }

        return string.Empty;
    }

    private static string NormalizeDirectory(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return Path.GetFullPath(value.Trim());
    }

    private static string GetParentDirectory(string filePath)
        => string.IsNullOrWhiteSpace(filePath)
            ? string.Empty
            : Path.GetDirectoryName(filePath) ?? string.Empty;
}

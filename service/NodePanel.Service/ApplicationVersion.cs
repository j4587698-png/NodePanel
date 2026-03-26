using System.Reflection;

namespace NodePanel.Service;

internal static class ApplicationVersion
{
    public static string Current { get; } = ResolveCurrent();

    private static string ResolveCurrent()
    {
        var assembly = typeof(ApplicationVersion).Assembly;
        var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informationalVersion))
        {
            return NormalizeDisplayVersion(informationalVersion);
        }

        var assemblyVersion = assembly.GetName().Version?.ToString();
        return string.IsNullOrWhiteSpace(assemblyVersion) ? "unknown" : NormalizeDisplayVersion(assemblyVersion);
    }

    private static string NormalizeDisplayVersion(string value)
    {
        var candidate = value.Trim();
        var plusIndex = candidate.IndexOf('+');
        if (plusIndex >= 0)
        {
            candidate = candidate[..plusIndex];
        }

        var dashIndex = candidate.IndexOf('-');
        if (dashIndex >= 0)
        {
            candidate = candidate[..dashIndex];
        }

        var segments = candidate.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length == 4 && string.Equals(segments[3], "0", StringComparison.Ordinal))
        {
            candidate = string.Join(".", segments.Take(3));
        }

        return string.IsNullOrWhiteSpace(candidate) ? "unknown" : candidate;
    }
}

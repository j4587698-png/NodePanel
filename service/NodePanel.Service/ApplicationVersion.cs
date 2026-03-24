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
            return informationalVersion;
        }

        var assemblyVersion = assembly.GetName().Version?.ToString();
        return string.IsNullOrWhiteSpace(assemblyVersion) ? "unknown" : assemblyVersion;
    }
}

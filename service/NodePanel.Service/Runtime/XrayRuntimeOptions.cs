namespace NodePanel.Service.Runtime;

public sealed record XrayRuntimeOptions
{
    public bool UseCone { get; init; } = true;

    public static XrayRuntimeOptions FromEnvironment()
        => new()
        {
            UseCone = !IsExplicitlyTrue(
                Environment.GetEnvironmentVariable("xray.cone.disabled"),
                Environment.GetEnvironmentVariable("XRAY_CONE_DISABLED"))
        };

    private static bool IsExplicitlyTrue(params string?[] values)
    {
        foreach (var value in values)
        {
            if (string.Equals(value?.Trim(), "true", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

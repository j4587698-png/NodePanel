namespace NodePanel.Core.Runtime;

public static class VlessFlowTypes
{
    public const string Vision = "xtls-rprx-vision";
    public const string VisionUdp443 = Vision + "-udp443";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        if (string.Equals(normalized, Vision, StringComparison.OrdinalIgnoreCase))
        {
            return Vision;
        }

        if (string.Equals(normalized, VisionUdp443, StringComparison.OrdinalIgnoreCase))
        {
            return VisionUdp443;
        }

        return normalized;
    }

    public static bool IsSupported(string? value)
        => Normalize(value) is "" or Vision or VisionUdp443;

    public static bool IsVision(string? value)
        => Normalize(value) is Vision or VisionUdp443;

    public static bool AllowsUdp443(string? value)
        => string.Equals(Normalize(value), VisionUdp443, StringComparison.Ordinal);

    public static string ToHeaderFlow(string? value)
        => Normalize(value) switch
        {
            Vision or VisionUdp443 => Vision,
            _ => string.Empty
        };
}

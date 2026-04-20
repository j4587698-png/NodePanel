namespace NodePanel.Core.Runtime;

public static class HttpOutboundTransports
{
    public const string Tcp = "tcp";
    public const string Tls = "tls";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Tcp
            : value.Trim().ToLowerInvariant() switch
            {
                "https" => Tls,
                _ => value.Trim().ToLowerInvariant()
            };
}

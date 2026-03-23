namespace NodePanel.Panel.Models;

public static class PanelDnsProviderTypes
{
    public const string Cloudflare = "cloudflare";
    public const string AliDns = "alidns";
    public const string DnsPod = "dnspod";

    public static string Normalize(string? value)
    {
        var normalized = value?.Trim().ToLowerInvariant() ?? string.Empty;
        return normalized switch
        {
            Cloudflare => Cloudflare,
            AliDns => AliDns,
            DnsPod => DnsPod,
            _ => string.Empty
        };
    }

    public static bool RequiresApiToken(string provider)
        => string.Equals(Normalize(provider), Cloudflare, StringComparison.Ordinal);

    public static bool RequiresAccessKeyPair(string provider)
        => Normalize(provider) is AliDns or DnsPod;
}

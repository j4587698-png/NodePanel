using System.Text;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class SubscriptionRenderer
{
    private const string ClashFormat = "clash";
    private const string GeneralFormat = "general";
    private const string QuantumultXFormat = "quantumultx";
    private const string RawTrojanFormat = "trojan";
    private const string ShadowrocketFormat = "shadowrocket";
    private const string StashFormat = "stash";
    private const string SurgeFormat = "surge";

    private readonly PanelOptions _options;
    private readonly PanelQueryService _panelQueryService;
    private readonly SubscriptionCatalogService _subscriptionCatalogService;

    public SubscriptionRenderer(
        SubscriptionCatalogService subscriptionCatalogService,
        PanelQueryService panelQueryService,
        IOptions<PanelOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _subscriptionCatalogService = subscriptionCatalogService;
        _panelQueryService = panelQueryService;
        _options = options.Value;
    }

    public async Task<(bool Success, RenderedSubscription Document, string Error)> TryRenderAsync(string token, string? flag, string? userAgent, CancellationToken cancellationToken = default)
    {
        var buildResult = await _subscriptionCatalogService.TryBuildAsync(token, cancellationToken);
        if (!buildResult.Success)
        {
            return (false, new RenderedSubscription { Format = GeneralFormat, Content = string.Empty }, buildResult.Error);
        }

        var doc = await RenderAsync(buildResult.Catalog, flag, userAgent, cancellationToken);
        return (true, doc, string.Empty);
    }

    public async Task<RenderedSubscription> RenderAsync(SubscriptionCatalog catalog, string? flag, string? userAgent, CancellationToken cancellationToken)
    {
        var format = ResolveFormat(flag, userAgent);
        var headers = await BuildHeadersAsync(catalog, format is SurgeFormat or ClashFormat or StashFormat, cancellationToken);

        var rendered = format switch
        {
            ClashFormat => RenderClash(catalog, ClashFormat),
            StashFormat => RenderClash(catalog, StashFormat),
            SurgeFormat => RenderSurge(catalog),
            QuantumultXFormat => RenderQuantumultX(catalog),
            ShadowrocketFormat => RenderGeneral(catalog, ShadowrocketFormat, raw: false),
            RawTrojanFormat => RenderGeneral(catalog, RawTrojanFormat, raw: true),
            _ => RenderGeneral(catalog, GeneralFormat, raw: false)
        };

        return rendered with { Headers = headers };
    }

    public string RenderRawList(SubscriptionCatalog catalog)
        => string.Join("\n", catalog.Endpoints.Select(endpoint => _subscriptionCatalogService.BuildUri(catalog.User, endpoint)));

    private RenderedSubscription RenderGeneral(SubscriptionCatalog catalog, string format, bool raw)
    {
        var payload = RenderRawList(catalog);
        var content = raw ? payload : Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
        return new RenderedSubscription { Format = format, Content = content, ContentType = "text/plain", FileName = BuildFileName("txt") };
    }

    // Keep RenderQuantumultX, RenderSurge, RenderClash unchanged mostly, just remove headers since it's injected later.
    private RenderedSubscription RenderQuantumultX(SubscriptionCatalog catalog)
    {
        var lines = catalog.Endpoints.Select(e =>
        {
            var v = new List<string> { $"trojan={e.Host}:{e.Port}", $"password={catalog.User.TrojanPassword}", "over-tls=true" };
            if (!string.IsNullOrWhiteSpace(e.Sni)) v.Add($"tls-host={e.Sni}");
            v.Add(e.SkipCertificateVerification ? "tls-verification=false" : "tls-verification=true");
            if (string.Equals(e.Transport, "ws", StringComparison.OrdinalIgnoreCase))
            {
                v.Add("obfs=wss");
                if (!string.IsNullOrWhiteSpace(e.WsHost)) v.Add($"obfs-host={e.WsHost}");
                if (!string.IsNullOrWhiteSpace(e.Path)) v.Add($"obfs-uri={e.Path}");
            }
            v.Add("fast-open=true"); v.Add("udp-relay=true"); v.Add($"tag={e.Label}");
            return string.Join(", ", v);
        });
        return new RenderedSubscription { Format = QuantumultXFormat, Content = Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\r\n", lines))), ContentType = "text/plain", FileName = BuildFileName("txt") };
    }

    private RenderedSubscription RenderSurge(SubscriptionCatalog catalog)
    {
        var proxyLines = catalog.Endpoints.Select(e =>
        {
            var v = new List<string> { $"{e.Label}=trojan", e.Host, e.Port.ToString(), $"password={catalog.User.TrojanPassword}", "udp-relay=true", "tfo=true" };
            if (!string.IsNullOrWhiteSpace(e.Sni)) v.Add($"sni={e.Sni}");
            v.Add($"skip-cert-verify={(e.SkipCertificateVerification ? "true" : "false")}");
            if (string.Equals(e.Transport, "ws", StringComparison.OrdinalIgnoreCase))
            {
                v.Add("ws=true");
                if (!string.IsNullOrWhiteSpace(e.Path)) v.Add($"ws-path={e.Path}");
                if (!string.IsNullOrWhiteSpace(e.WsHost)) v.Add($"ws-headers=Host:{e.WsHost}");
            }
            return string.Join(",", v);
        });

        var proxyTargets = catalog.Endpoints.Select(static e => e.Label).ToList(); proxyTargets.Add("DIRECT");
        var builder = new StringBuilder();
        builder.AppendLine("[General]\nloglevel = notify\ndns-server = system\nskip-proxy = 127.0.0.1, localhost\n\n[Proxy]");
        foreach (var line in proxyLines) builder.AppendLine(line);
        builder.AppendLine($"\n[Proxy Group]\nProxy = select,{string.Join(",", proxyTargets)}\n\n[Rule]\n{(catalog.Endpoints.Count == 0 ? "FINAL,DIRECT" : "FINAL,Proxy")}");
        return new RenderedSubscription { Format = SurgeFormat, Content = builder.ToString(), ContentType = "text/plain", FileName = BuildFileName("conf") };
    }

    private RenderedSubscription RenderClash(SubscriptionCatalog catalog, string format)
    {
        var builder = new StringBuilder();
        builder.AppendLine("mixed-port: 7890\nallow-lan: false\nmode: rule");
        if (catalog.Endpoints.Count == 0) builder.AppendLine("proxies: []");
        else
        {
            builder.AppendLine("proxies:");
            foreach (var e in catalog.Endpoints)
            {
                builder.AppendLine($"  - name: {YamlString(e.Label)}\n    type: trojan\n    server: {YamlString(e.Host)}\n    port: {e.Port}\n    password: {YamlString(catalog.User.TrojanPassword)}");
                if (!string.IsNullOrWhiteSpace(e.Sni)) builder.AppendLine($"    sni: {YamlString(e.Sni)}");
                builder.AppendLine("    udp: true"); builder.AppendLine($"    skip-cert-verify: {ToYamlBoolean(e.SkipCertificateVerification)}");
                if (string.Equals(e.Transport, "ws", StringComparison.OrdinalIgnoreCase))
                {
                    builder.AppendLine("    network: ws\n    ws-opts:\n      path: " + YamlString(string.IsNullOrWhiteSpace(e.Path) ? "/" : e.Path) + "\n      headers:\n        Host: " + YamlString(string.IsNullOrWhiteSpace(e.WsHost) ? e.Host : e.WsHost));
                }
            }
        }
        builder.AppendLine("proxy-groups:"); builder.AppendLine($"  - name: {YamlString("Proxy")}\n    type: select\n    proxies:");
        foreach (var e in catalog.Endpoints) builder.AppendLine($"      - {YamlString(e.Label)}");
        builder.AppendLine($"      - {YamlString("DIRECT")}");
        builder.AppendLine("rules:\n  - DOMAIN,localhost,DIRECT\n  - IP-CIDR,127.0.0.0/8,DIRECT\n  - IP-CIDR,10.0.0.0/8,DIRECT\n  - IP-CIDR,100.64.0.0/10,DIRECT\n  - IP-CIDR,172.16.0.0/12,DIRECT\n  - IP-CIDR,192.168.0.0/16,DIRECT\n  - MATCH,Proxy");
        return new RenderedSubscription { Format = format, Content = builder.ToString(), ContentType = "text/yaml", FileName = BuildFileName("yaml") };
    }

    private async Task<IReadOnlyDictionary<string, string>> BuildHeadersAsync(SubscriptionCatalog catalog, bool includeProfileInterval, CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var traffic = await _panelQueryService.BuildUserTrafficSummaryAsync(catalog.User.UserId, cancellationToken) ?? new PanelUserTrafficSummary { UserId = catalog.User.UserId };
        var subscription = catalog.User.Subscription;

        if (subscription.TransferEnableBytes > 0 || subscription.ExpiresAt.HasValue)
        {
            headers["subscription-userinfo"] =
                $"upload={traffic.UploadBytes}; download={traffic.DownloadBytes}; total={Math.Max(0, subscription.TransferEnableBytes)}; expire={subscription.ExpiresAt?.ToUnixTimeSeconds() ?? 0}";
        }

        if (includeProfileInterval) headers["profile-update-interval"] = "24";
        return headers;
    }

    private static string ResolveFormat(string? flag, string? userAgent) => TryResolveFromValue(flag, out var format) ? format : TryResolveFromValue(userAgent, out format) ? format : GeneralFormat;
    private static bool TryResolveFromValue(string? value, out string format)
    {
        var normalized = NormalizeMarker(value);
        if (string.IsNullOrWhiteSpace(normalized)) { format = string.Empty; return false; }
        if (normalized.Contains("shadowrocket", StringComparison.Ordinal)) { format = ShadowrocketFormat; return true; }
        if (normalized.Contains("quantumult", StringComparison.Ordinal)) { format = QuantumultXFormat; return true; }
        if (normalized.Contains("stash", StringComparison.Ordinal)) { format = StashFormat; return true; }
        if (normalized.Contains("surge", StringComparison.Ordinal) || normalized.Contains("surfboard", StringComparison.Ordinal)) { format = SurgeFormat; return true; }
        if (normalized.Contains("clash", StringComparison.Ordinal) || normalized.Contains("mihomo", StringComparison.Ordinal)) { format = ClashFormat; return true; }
        if (normalized.Contains("raw", StringComparison.Ordinal) || normalized.Contains("trojan", StringComparison.Ordinal)) { format = RawTrojanFormat; return true; }
        if (normalized.Contains("general", StringComparison.Ordinal)) { format = GeneralFormat; return true; }
        format = string.Empty; return false;
    }
    private static string NormalizeMarker(string? value) { try { return string.IsNullOrWhiteSpace(value) ? string.Empty : Uri.UnescapeDataString(value).Trim().ToLowerInvariant(); } catch (UriFormatException) { return value!.Trim().ToLowerInvariant(); } }
    private string BuildFileName(string extension)
    {
        var appName = string.IsNullOrWhiteSpace(_options.AppName) ? "nodepanel" : _options.AppName;
        var sanitized = string.Concat(appName.Where(ch => !Path.GetInvalidFileNameChars().Contains(ch)).Select(ch => char.IsWhiteSpace(ch) ? '-' : ch));
        return $"{(string.IsNullOrWhiteSpace(sanitized) ? "nodepanel" : sanitized)}.{extension}";
    }
    private static string YamlString(string value) => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";
    private static string ToYamlBoolean(bool value) => value ? "true" : "false";
}

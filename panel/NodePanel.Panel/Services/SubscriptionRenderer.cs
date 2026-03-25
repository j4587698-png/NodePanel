using System.Text;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class SubscriptionRenderer
{
    private readonly PanelOptions _options;
    private readonly PanelQueryService _panelQueryService;
    private readonly SubscriptionCatalogService _subscriptionCatalogService;
    private readonly SubscriptionProfileResolver _subscriptionProfileResolver;

    public SubscriptionRenderer(
        SubscriptionCatalogService subscriptionCatalogService,
        SubscriptionProfileResolver subscriptionProfileResolver,
        PanelQueryService panelQueryService,
        IOptions<PanelOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _subscriptionCatalogService = subscriptionCatalogService;
        _subscriptionProfileResolver = subscriptionProfileResolver;
        _panelQueryService = panelQueryService;
        _options = options.Value;
    }

    public async Task<(bool Success, RenderedSubscription Document, string Error)> TryRenderAsync(
        string token,
        string? flag,
        string? profile,
        string? userAgent,
        CancellationToken cancellationToken = default)
    {
        var buildResult = await _subscriptionCatalogService.TryBuildAsync(token, cancellationToken);
        if (!buildResult.Success)
        {
            return (false, new RenderedSubscription { Format = SubscriptionFormats.General, Content = string.Empty }, buildResult.Error);
        }

        var doc = await RenderAsync(buildResult.Catalog, flag, profile, userAgent, cancellationToken);
        return (true, doc, string.Empty);
    }

    public async Task<RenderedSubscription> RenderAsync(
        SubscriptionCatalog catalog,
        string? flag,
        string? profile,
        string? userAgent,
        CancellationToken cancellationToken)
    {
        var settings = await _panelQueryService.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
        var request = _subscriptionProfileResolver.ResolveRequest(flag, profile, userAgent, settings);
        var headers = await BuildHeadersAsync(catalog, SubscriptionFormats.IsStructured(request.Format), cancellationToken);

        var rendered = request.Format switch
        {
            SubscriptionFormats.Clash or SubscriptionFormats.Stash or SubscriptionFormats.Surge or SubscriptionFormats.QuantumultX =>
                SubscriptionFormatRenderer.Render(
                    catalog,
                    _subscriptionProfileResolver.BuildPlan(catalog, request),
                    ResolveAppName()),
            SubscriptionFormats.Shadowrocket => RenderGeneral(catalog, SubscriptionFormats.Shadowrocket, raw: false),
            SubscriptionFormats.RawTrojan => RenderGeneral(catalog, SubscriptionFormats.RawTrojan, raw: true),
            _ => RenderGeneral(catalog, SubscriptionFormats.General, raw: false)
        };

        return rendered with { Headers = headers };
    }

    public string RenderRawList(SubscriptionCatalog catalog)
        => string.Join("\n", catalog.Endpoints.Select(endpoint => _subscriptionCatalogService.BuildUri(catalog.User, endpoint)));

    private RenderedSubscription RenderGeneral(SubscriptionCatalog catalog, string format, bool raw)
    {
        var payload = RenderRawList(catalog);
        var content = raw ? payload : Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
        return new RenderedSubscription
        {
            Format = format,
            Content = content,
            ContentType = "text/plain",
            FileName = BuildFileName("txt")
        };
    }

    private async Task<IReadOnlyDictionary<string, string>> BuildHeadersAsync(
        SubscriptionCatalog catalog,
        bool includeProfileInterval,
        CancellationToken cancellationToken)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var traffic = await _panelQueryService.BuildUserTrafficSummaryAsync(catalog.User.UserId, cancellationToken)
                          ?? new PanelUserTrafficSummary { UserId = catalog.User.UserId };
        var subscription = catalog.User.Subscription;

        if (subscription.TransferEnableBytes > 0 || subscription.ExpiresAt.HasValue)
        {
            headers["subscription-userinfo"] =
                $"upload={traffic.UploadBytes}; download={traffic.DownloadBytes}; total={Math.Max(0, subscription.TransferEnableBytes)}; expire={subscription.ExpiresAt?.ToUnixTimeSeconds() ?? 0}";
        }

        if (includeProfileInterval)
        {
            headers["profile-update-interval"] = "24";
        }

        return headers;
    }

    private string ResolveAppName()
        => string.IsNullOrWhiteSpace(_options.AppName) ? "nodepanel" : _options.AppName;

    private string BuildFileName(string extension)
    {
        var appName = ResolveAppName();
        var sanitized = string.Concat(
            appName
                .Where(ch => !Path.GetInvalidFileNameChars().Contains(ch))
                .Select(static ch => char.IsWhiteSpace(ch) ? '-' : ch));
        return $"{(string.IsNullOrWhiteSpace(sanitized) ? "nodepanel" : sanitized)}.{extension}";
    }
}

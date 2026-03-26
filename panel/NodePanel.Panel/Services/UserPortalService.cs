using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class UserPortalService
{
    private readonly PanelOptions _options;
    private readonly PanelPublicUrlBuilder _publicUrlBuilder;
    private readonly PanelQueryService _panelQueryService;
    private readonly SubscriptionCatalogService _subscriptionCatalogService;
    private readonly SubscriptionRenderer _subscriptionRenderer;

    public UserPortalService(
        SubscriptionCatalogService subscriptionCatalogService,
        SubscriptionRenderer subscriptionRenderer,
        PanelQueryService panelQueryService,
        PanelPublicUrlBuilder publicUrlBuilder,
        IOptions<PanelOptions> options)
    {
        _subscriptionCatalogService = subscriptionCatalogService;
        _subscriptionRenderer = subscriptionRenderer;
        _panelQueryService = panelQueryService;
        _publicUrlBuilder = publicUrlBuilder;
        _options = options.Value;
    }

    public Task<(bool Success, PortalPageViewModel Model, string Error)> TryBuildAsync(string token, HttpRequest request, CancellationToken cancellationToken = default)
    {
        return TryBuildInternalAsync(
            () => _subscriptionCatalogService.TryBuildAsync(token, cancellationToken),
            token,
            "portal",
            request,
            cancellationToken);
    }

    public Task<(bool Success, PortalPageViewModel Model, string Error)> TryBuildByUserIdAsync(string userId, HttpRequest request, CancellationToken cancellationToken = default)
    {
        return TryBuildInternalAsync(
            () => _subscriptionCatalogService.TryBuildByUserIdAsync(userId, cancellationToken),
            string.Empty,
            "user",
            request,
            cancellationToken);
    }

    public async Task<PortalStoreViewModel> BuildStoreAsync(string userId, CancellationToken cancellationToken)
    {
        var buildResult = await _subscriptionCatalogService.TryBuildByUserIdAsync(userId, cancellationToken);
        var title = buildResult.Success ? (string.IsNullOrWhiteSpace(buildResult.Catalog.User.DisplayName) ? userId : buildResult.Catalog.User.DisplayName) : userId;
        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
        
        return new PortalStoreViewModel
        {
            AppName = ResolveAppName(),
            DisplayName = title,
            Plans = state.Plans.Where(PlanPresentation.HasAvailableCycles).ToArray(),
            CurrencySymbol = state.Settings.GetValueOrDefault("currency_symbol", "¥") ?? "¥",
            StatusMessage = string.Empty
        };
    }

    public async Task<PortalOrdersViewModel> BuildOrdersAsync(string userId, CancellationToken cancellationToken)
    {
        var buildResult = await _subscriptionCatalogService.TryBuildByUserIdAsync(userId, cancellationToken);
        var title = buildResult.Success ? (string.IsNullOrWhiteSpace(buildResult.Catalog.User.DisplayName) ? userId : buildResult.Catalog.User.DisplayName) : userId;
        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
        
        return new PortalOrdersViewModel
        {
            AppName = ResolveAppName(),
            DisplayName = title,
            Orders = state.Orders.Where(o => string.Equals(o.UserId, userId, StringComparison.Ordinal)).ToList(),
            Plans = state.Plans,
            CurrencySymbol = state.Settings.GetValueOrDefault("currency_symbol", "¥") ?? "¥",
            StatusMessage = string.Empty
        };
    }

    private async Task<(bool Success, PortalPageViewModel Model, string Error)> TryBuildInternalAsync(
        Func<Task<(bool Success, SubscriptionCatalog Catalog, string Error)>> catalogFactory,
        string tokenFallback,
        string resetSubscriptionReturnTarget,
        HttpRequest request, 
        CancellationToken cancellationToken)
    {
        var buildResult = await catalogFactory();
        if (!buildResult.Success)
        {
            return (false, BuildFallbackModel(tokenFallback, buildResult.Error), buildResult.Error);
        }

        var catalog = buildResult.Catalog;
        var trafficTask = _panelQueryService.BuildUserTrafficSummaryAsync(catalog.User.UserId, cancellationToken);
        var referralTask = _panelQueryService.BuildUserReferralCenterAsync(catalog.User.UserId, cancellationToken);
        var settingsTask = _panelQueryService.GetSettingsAsync(cancellationToken);
        await Task.WhenAll(trafficTask, referralTask, settingsTask).ConfigureAwait(false);

        var traffic = trafficTask.Result ?? new PanelUserTrafficSummary { UserId = catalog.User.UserId };
        var referral = referralTask.Result;
        var settings = settingsTask.Result;
        var subscription = catalog.User.Subscription;
        var totalTraffic = Math.Max(0, subscription.TransferEnableBytes);
        var remainingTraffic = totalTraffic > 0 ? Math.Max(0, totalTraffic - traffic.TotalBytes) : 0;
        var title = string.IsNullOrWhiteSpace(catalog.User.DisplayName) ? catalog.User.UserId : catalog.User.DisplayName;

        var model = new PortalPageViewModel
        {
            AppName = ResolveAppName(),
            LookupToken = tokenFallback,
            IsResolved = true,
            DisplayName = title,
            CurrentSubscriptionToken = catalog.User.SubscriptionToken,
            AllowSubscriptionReset = !string.IsNullOrWhiteSpace(catalog.User.SubscriptionToken),
            ResetSubscriptionReturnTarget = resetSubscriptionReturnTarget,
            PortalUrl = _publicUrlBuilder.BuildPortalUrl(catalog.User.SubscriptionToken, request),
            SubscriptionUrl = _publicUrlBuilder.BuildSubscriptionUrl(catalog.User.SubscriptionToken, null, request),
            RawSubscriptionUrl = _publicUrlBuilder.BuildSubscriptionUrl(catalog.User.SubscriptionToken, "trojan", request),
            PlanName = string.IsNullOrWhiteSpace(subscription.PlanName) ? "未设置套餐" : subscription.PlanName,
            ExpiresAtText = subscription.ExpiresAt?.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") ?? "长期有效",
            UsedTrafficText = FormatTraffic(traffic.TotalBytes),
            RemainingTrafficText = totalTraffic > 0 ? FormatTraffic(remainingTraffic) : "未限制",
            TotalTrafficText = totalTraffic > 0 ? FormatTraffic(totalTraffic) : "未限制",
            Notice = subscription.PortalNotice,
            PurchaseUrl = subscription.PurchaseUrl,
            CurrencySymbol = settings.GetValueOrDefault("currency_symbol", "¥") ?? "¥",
            Referral = referral,
            ImportLinks = BuildImportLinks(catalog.User.SubscriptionToken, request, title),
            Nodes = catalog.Endpoints
                .Select(endpoint => new PortalNodeViewModel
                {
                    CopyId = $"{endpoint.NodeId}-{endpoint.Transport}-{endpoint.Port}",
                    Name = endpoint.DisplayName,
                    TransportLabel = BuildTransportLabel(endpoint),
                    Address = $"{endpoint.Host}:{endpoint.Port}",
                    Sni = endpoint.Sni,
                    Path = endpoint.Path,
                    ManualUri = _subscriptionCatalogService.BuildUri(catalog.User, endpoint)
                }).ToArray(),
            RawSubscriptionContent = _subscriptionRenderer.RenderRawList(catalog)
        };

        return (true, model, string.Empty);
    }

    public PortalPageViewModel BuildEmpty() => new() { AppName = ResolveAppName() };

    private PortalPageViewModel BuildFallbackModel(string token, string error) => new() { AppName = ResolveAppName(), LookupToken = token, ErrorMessage = error };

    private IReadOnlyList<PortalClientLinkViewModel> BuildImportLinks(string token, HttpRequest request, string title)
    {
        var remark = Uri.EscapeDataString(title);
        return new[]
        {
            new PortalClientLinkViewModel { Title = "Shadowrocket", Description = "iOS 一键导入", Url = $"shadowrocket://add/sub://{ToSafeBase64(_publicUrlBuilder.BuildSubscriptionUrl(token, "shadowrocket", request))}?remark={remark}" },
            new PortalClientLinkViewModel { Title = "Quantumult X", Description = "配置远程资源", Url = BuildQuantumultXScheme(_publicUrlBuilder.BuildSubscriptionUrl(token, "quantumultx", request), title) },
            new PortalClientLinkViewModel { Title = "Clash", Description = "Clash 系列订阅", Url = $"clash://install-config?url={Uri.EscapeDataString(_publicUrlBuilder.BuildSubscriptionUrl(token, "clash", request, SubscriptionProfileNames.Managed))}&name={remark}" },
            new PortalClientLinkViewModel { Title = "Stash", Description = "Stash YAML 订阅", Url = $"stash://install-config?url={Uri.EscapeDataString(_publicUrlBuilder.BuildSubscriptionUrl(token, "stash", request, SubscriptionProfileNames.Managed))}&name={remark}" },
            new PortalClientLinkViewModel { Title = "Surge", Description = "Surge 配置导入", Url = $"surge:///install-config?url={Uri.EscapeDataString(_publicUrlBuilder.BuildSubscriptionUrl(token, "surge", request, SubscriptionProfileNames.Managed))}&name={remark}" }
        };
    }

    private static string BuildQuantumultXScheme(string subscriptionUrl, string title) => $"quantumult-x:///update-configuration?remote-resource={Uri.EscapeDataString(JsonSerializer.Serialize(new { server_remote = new[] { $"{subscriptionUrl}, tag={title}" } }))}";
    private static string ToSafeBase64(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private string ResolveAppName() => string.IsNullOrWhiteSpace(_options.AppName) ? "NodePanel" : _options.AppName;
    private static string BuildTransportLabel(SubscriptionEndpoint endpoint)
    {
        var protocol = string.IsNullOrWhiteSpace(endpoint.Protocol)
            ? "Trojan"
            : endpoint.Protocol.Trim().ToUpperInvariant();
        var transport = string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase) ? "WSS" : "TLS";
        return $"{protocol} / {transport}";
    }

    private static string FormatTraffic(long bytes)
    {
        if (bytes >= 1099511627776d) return $"{bytes / 1099511627776d:0.##} TB";
        if (bytes >= 1073741824d) return $"{bytes / 1073741824d:0.##} GB";
        if (bytes >= 1048576d) return $"{bytes / 1048576d:0.##} MB";
        if (bytes >= 1024d) return $"{bytes / 1024d:0.##} KB";
        return $"{Math.Max(0, bytes)} B";
    }
}

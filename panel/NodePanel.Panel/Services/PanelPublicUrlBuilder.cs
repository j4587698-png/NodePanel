using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;

namespace NodePanel.Panel.Services;

public sealed class PanelPublicUrlBuilder
{
    private readonly PanelOptions _options;

    public PanelPublicUrlBuilder(IOptions<PanelOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    public string BuildPortalUrl(string token, HttpRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentNullException.ThrowIfNull(request);

        return BuildAbsoluteUrl(ResolvePortalBaseUri(request), $"/portal/{Uri.EscapeDataString(token)}");
    }

    public string BuildSubscriptionUrl(string token, string? flag, HttpRequest request)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentNullException.ThrowIfNull(request);

        var path = $"/client/subscribe?token={Uri.EscapeDataString(token)}";
        if (!string.IsNullOrWhiteSpace(flag))
        {
            path += $"&flag={Uri.EscapeDataString(flag.Trim())}";
        }

        return BuildAbsoluteUrl(ResolveSubscribeBaseUri(request), path);
    }

    private Uri ResolvePortalBaseUri(HttpRequest request)
        => TryBuildAbsoluteUri(_options.PublicBaseUrl) ?? BuildRequestBaseUri(request);

    private Uri ResolveSubscribeBaseUri(HttpRequest request)
    {
        var configured = _options.SubscribeUrls
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Select(static item => item.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (configured.Length > 0)
        {
            var selected = configured[Random.Shared.Next(configured.Length)];
            var selectedUri = TryBuildAbsoluteUri(selected);
            if (selectedUri is not null)
            {
                return selectedUri;
            }
        }

        return ResolvePortalBaseUri(request);
    }

    private static Uri? TryBuildAbsoluteUri(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return Uri.TryCreate(value.TrimEnd('/'), UriKind.Absolute, out var uri)
            ? BuildOriginUri(uri)
            : null;
    }

    private static Uri BuildRequestBaseUri(HttpRequest request)
    {
        var builder = new UriBuilder(request.Scheme, request.Host.Host);
        if (request.Host.Port.HasValue)
        {
            builder.Port = request.Host.Port.Value;
        }

        return builder.Uri;
    }

    private static Uri BuildOriginUri(Uri value)
    {
        var builder = new UriBuilder(value.Scheme, value.Host);
        if (!value.IsDefaultPort)
        {
            builder.Port = value.Port;
        }

        return builder.Uri;
    }

    private static string BuildAbsoluteUrl(Uri baseUri, string path)
        => new Uri(baseUri, path).ToString();
}

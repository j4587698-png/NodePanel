using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace NodePanel.Panel.Services;

public static class PanelListenerBindingRules
{
    public const string DefaultUrls = "http://0.0.0.0:80;https://0.0.0.0:443";

    public static PanelListenerBindingSnapshot Resolve(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var kestrelEndpointUrls = configuration.GetSection("Kestrel:Endpoints")
            .GetChildren()
            .Select(static endpoint => endpoint["Url"])
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray();

        var urls = FirstNonEmpty(
            configuration[WebHostDefaults.ServerUrlsKey],
            configuration["ASPNETCORE_URLS"],
            configuration["URLS"],
            configuration["DOTNET_URLS"]);

        if (!string.IsNullOrWhiteSpace(urls))
        {
            return new PanelListenerBindingSnapshot
            {
                HasConfiguredBindings = true,
                HttpsPort = TryResolveHttpsPortFromUrls(urls)
            };
        }

        if (kestrelEndpointUrls.Length > 0)
        {
            return new PanelListenerBindingSnapshot
            {
                HasConfiguredBindings = true,
                HttpsPort = TryResolveHttpsPortFromUrls(string.Join(';', kestrelEndpointUrls))
            };
        }

        var httpsPorts = FirstNonEmpty(
            configuration["https_ports"],
            configuration["HTTPS_PORTS"],
            configuration["ASPNETCORE_HTTPS_PORTS"],
            configuration["DOTNET_HTTPS_PORTS"]);
        var httpPorts = FirstNonEmpty(
            configuration["http_ports"],
            configuration["HTTP_PORTS"],
            configuration["ASPNETCORE_HTTP_PORTS"],
            configuration["DOTNET_HTTP_PORTS"]);

        if (!string.IsNullOrWhiteSpace(httpsPorts) || !string.IsNullOrWhiteSpace(httpPorts))
        {
            return new PanelListenerBindingSnapshot
            {
                HasConfiguredBindings = true,
                HttpsPort = TryResolveHttpsPortFromPorts(httpsPorts)
            };
        }

        return new PanelListenerBindingSnapshot
        {
            HasConfiguredBindings = false,
            HttpsPort = null
        };
    }

    public static PanelListenerBindingSnapshot ResolveDefaults()
        => new()
        {
            HasConfiguredBindings = true,
            HttpsPort = 443
        };

    private static string FirstNonEmpty(params string?[] values)
        => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;

    private static int? TryResolveHttpsPortFromUrls(string urls)
    {
        foreach (var rawUrl in urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TryParseUrl(rawUrl, out var scheme, out var port))
            {
                continue;
            }

            if (string.Equals(scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return port;
            }
        }

        return null;
    }

    private static int? TryResolveHttpsPortFromPorts(string? ports)
    {
        if (string.IsNullOrWhiteSpace(ports))
        {
            return null;
        }

        foreach (var rawPort in ports.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(rawPort, out var port) && port is > 0 and <= 65535)
            {
                return port;
            }
        }

        return null;
    }

    private static bool TryParseUrl(string rawUrl, out string scheme, out int port)
    {
        scheme = string.Empty;
        port = 0;

        if (string.IsNullOrWhiteSpace(rawUrl))
        {
            return false;
        }

        var normalizedUrl = rawUrl.Trim()
            .Replace("://*:", "://0.0.0.0:", StringComparison.Ordinal)
            .Replace("://+:", "://0.0.0.0:", StringComparison.Ordinal);

        if (!Uri.TryCreate(normalizedUrl, UriKind.Absolute, out var uri))
        {
            return false;
        }

        scheme = uri.Scheme;
        port = uri.IsDefaultPort
            ? string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ? 443 : 80
            : uri.Port;
        return true;
    }
}

public sealed record PanelListenerBindingSnapshot
{
    public bool HasConfiguredBindings { get; init; }

    public int? HttpsPort { get; init; }
}

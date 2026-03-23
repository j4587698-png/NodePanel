using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace NodePanel.Core.Runtime;

public interface IDnsResolver
{
    ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

public interface IDnsRuntimeSettingsProvider
{
    DnsRuntimeSettings GetCurrentDnsSettings();
}

public sealed record DnsRuntimeSettings
{
    public static DnsRuntimeSettings Default { get; } = new();

    public string Mode { get; init; } = DnsModes.System;

    public int TimeoutSeconds { get; init; } = 5;

    public int CacheTtlSeconds { get; init; } = 30;

    public IReadOnlyList<DnsHttpServerRuntime> Servers { get; init; } = Array.Empty<DnsHttpServerRuntime>();
}

public sealed record DnsHttpServerRuntime
{
    public required string Url { get; init; }

    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

public static class DnsModes
{
    public const string System = "system";
    public const string Http = "http";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return System;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            Http => Http,
            _ => System
        };
    }
}

public sealed class SystemDnsResolver : IDnsResolver
{
    public static SystemDnsResolver Instance { get; } = new();

    private SystemDnsResolver()
    {
    }

    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        if (IPAddress.TryParse(host, out var ipAddress))
        {
            return
            [
                ipAddress
            ];
        }

        return await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);
    }
}

public sealed class RuntimeDnsResolver : IDnsResolver
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    private readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HttpClient _httpClient;
    private readonly IDnsRuntimeSettingsProvider? _settingsProvider;

    public RuntimeDnsResolver(
        IDnsRuntimeSettingsProvider? settingsProvider = null,
        HttpClient? httpClient = null)
    {
        _settingsProvider = settingsProvider;
        _httpClient = httpClient ?? CreateDefaultHttpClient();
    }

    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var normalizedHost = host.Trim();
        if (IPAddress.TryParse(normalizedHost, out var ipAddress))
        {
            return
            [
                ipAddress
            ];
        }

        var settings = _settingsProvider?.GetCurrentDnsSettings() ?? DnsRuntimeSettings.Default;
        return DnsModes.Normalize(settings.Mode) switch
        {
            DnsModes.Http => await ResolveByHttpAsync(normalizedHost, settings, cancellationToken).ConfigureAwait(false),
            _ => await SystemDnsResolver.Instance.ResolveAsync(normalizedHost, cancellationToken).ConfigureAwait(false)
        };
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveByHttpAsync(
        string host,
        DnsRuntimeSettings settings,
        CancellationToken cancellationToken)
    {
        if (settings.Servers.Count == 0)
        {
            throw new InvalidOperationException("HTTP DNS mode requires at least one configured server.");
        }

        var cacheKey = BuildCacheKey(host, settings);
        if (TryGetCached(cacheKey, out var cached))
        {
            return cached;
        }

        Exception? lastError = null;
        foreach (var server in settings.Servers)
        {
            try
            {
                var addresses = await ResolveByHttpServerAsync(host, server, settings, cancellationToken).ConfigureAwait(false);
                if (addresses.Count == 0)
                {
                    continue;
                }

                Cache(cacheKey, addresses, settings);
                return addresses;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        if (lastError is not null)
        {
            throw lastError;
        }

        throw new SocketException((int)SocketError.HostNotFound);
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveByHttpServerAsync(
        string host,
        DnsHttpServerRuntime server,
        DnsRuntimeSettings settings,
        CancellationToken cancellationToken)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linkedCts.CancelAfter(ResolveTimeout(settings.TimeoutSeconds));

        var ipv4Task = QueryRecordAsync(host, "A", server, linkedCts.Token);
        var ipv6Task = QueryRecordAsync(host, "AAAA", server, linkedCts.Token);

        var addresses = new List<IPAddress>(4);
        Exception? lastError = null;

        try
        {
            addresses.AddRange(await ipv4Task.ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            lastError = ex;
        }

        try
        {
            addresses.AddRange(await ipv6Task.ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            lastError ??= ex;
        }

        if (addresses.Count > 0)
        {
            return addresses
                .Distinct()
                .ToArray();
        }

        if (lastError is not null)
        {
            throw lastError;
        }

        return Array.Empty<IPAddress>();
    }

    private async Task<IReadOnlyList<IPAddress>> QueryRecordAsync(
        string host,
        string recordType,
        DnsHttpServerRuntime server,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildQueryUri(server.Url, host, recordType));
        request.Headers.Accept.ParseAdd("application/json");
        request.Headers.Accept.ParseAdd("application/dns-json");

        foreach (var (name, value) in server.Headers)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        return ParseAddresses(document.RootElement, recordType);
    }

    private void Cache(string cacheKey, IReadOnlyList<IPAddress> addresses, DnsRuntimeSettings settings)
    {
        if (settings.CacheTtlSeconds <= 0 || addresses.Count == 0)
        {
            return;
        }

        _cache[cacheKey] = new DnsCacheEntry(
            addresses,
            DateTimeOffset.UtcNow.AddSeconds(settings.CacheTtlSeconds));
    }

    private bool TryGetCached(string cacheKey, out IReadOnlyList<IPAddress> addresses)
    {
        if (_cache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            addresses = cached.Addresses;
            return true;
        }

        _cache.TryRemove(cacheKey, out _);
        addresses = Array.Empty<IPAddress>();
        return false;
    }

    private static TimeSpan ResolveTimeout(int timeoutSeconds)
        => timeoutSeconds > 0 ? TimeSpan.FromSeconds(timeoutSeconds) : DefaultTimeout;

    private static string BuildCacheKey(string host, DnsRuntimeSettings settings)
        => string.Create(
            host.Length + settings.Mode.Length + 1 + settings.Servers.Sum(static server => server.Url.Length + 1),
            (Host: host, Settings: settings),
            static (span, state) =>
            {
                var offset = 0;
                state.Settings.Mode.AsSpan().CopyTo(span[offset..]);
                offset += state.Settings.Mode.Length;
                span[offset++] = '|';
                state.Host.AsSpan().CopyTo(span[offset..]);
                offset += state.Host.Length;

                foreach (var server in state.Settings.Servers)
                {
                    span[offset++] = '|';
                    server.Url.AsSpan().CopyTo(span[offset..]);
                    offset += server.Url.Length;
                }
            });

    private static string BuildQueryUri(string baseUrl, string host, string recordType)
    {
        var separator = baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var builder = new StringBuilder(baseUrl.Length + host.Length + recordType.Length + 16);
        builder.Append(baseUrl);
        builder.Append(separator);
        builder.Append("name=");
        builder.Append(Uri.EscapeDataString(host));
        builder.Append("&type=");
        builder.Append(Uri.EscapeDataString(recordType));
        return builder.ToString();
    }

    private static HttpClient CreateDefaultHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    private static IReadOnlyList<IPAddress> ParseAddresses(JsonElement root, string recordType)
    {
        var addresses = new List<IPAddress>(4);

        if (TryGetPropertyIgnoreCase(root, "addresses", out var addressesElement) &&
            addressesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in addressesElement.EnumerateArray())
            {
                if (TryReadAddress(item, out var address))
                {
                    addresses.Add(address);
                }
            }
        }

        if (TryGetPropertyIgnoreCase(root, "answer", out var answerElement) ||
            TryGetPropertyIgnoreCase(root, "answers", out answerElement))
        {
            if (answerElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in answerElement.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    if (TryGetPropertyIgnoreCase(item, "type", out var typeElement) &&
                        !MatchesRecordType(typeElement, recordType))
                    {
                        continue;
                    }

                    if (TryGetPropertyIgnoreCase(item, "data", out var dataElement) &&
                        TryReadAddress(dataElement, out var address))
                    {
                        addresses.Add(address);
                    }
                }
            }
        }

        return addresses
            .Distinct()
            .ToArray();
    }

    private static bool MatchesRecordType(JsonElement element, string recordType)
    {
        if (element.ValueKind == JsonValueKind.Number &&
            element.TryGetInt32(out var numericType))
        {
            return numericType switch
            {
                1 => string.Equals(recordType, "A", StringComparison.Ordinal),
                28 => string.Equals(recordType, "AAAA", StringComparison.Ordinal),
                _ => false
            };
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return string.Equals(element.GetString(), recordType, StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static bool TryReadAddress(JsonElement element, out IPAddress address)
    {
        if (element.ValueKind == JsonValueKind.String &&
            IPAddress.TryParse(element.GetString()!, out var parsedAddress) &&
            parsedAddress is not null)
        {
            address = parsedAddress;
            return true;
        }

        if (element.ValueKind == JsonValueKind.Object &&
            TryGetPropertyIgnoreCase(element, "address", out var addressElement) &&
            addressElement.ValueKind == JsonValueKind.String &&
            IPAddress.TryParse(addressElement.GetString()!, out parsedAddress) &&
            parsedAddress is not null)
        {
            address = parsedAddress;
            return true;
        }

        address = IPAddress.None;
        return false;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private sealed record DnsCacheEntry(IReadOnlyList<IPAddress> Addresses, DateTimeOffset ExpiresAt);
}

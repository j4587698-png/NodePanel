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

public interface IDnsLookupResolver : IDnsResolver
{
    ValueTask<DnsLookupResult> LookupAsync(
        string host,
        DnsLookupOptions options,
        CancellationToken cancellationToken);
}

public sealed record DnsLookupOptions
{
    public static DnsLookupOptions Default { get; } = new();

    public bool IPv4Enable { get; init; } = true;

    public bool IPv6Enable { get; init; } = true;

    public bool FakeEnable { get; init; }
}

public sealed record DnsLookupResult
{
    public IReadOnlyList<IPAddress> Addresses { get; init; } = Array.Empty<IPAddress>();

    public uint TtlSeconds { get; init; } = DnsResolutionDefaults.DefaultTtl;

    public byte ResponseCode { get; init; } = DnsResponseCodes.Success;

    public bool IsEmptyResponse { get; init; }

    public bool IsFakeResponse { get; init; }
}

public static class DnsResolutionDefaults
{
    public const uint DefaultTtl = 300;
}

public sealed class DnsResponseCodeException : Exception
{
    public DnsResponseCodeException(
        byte responseCode,
        string? message = null,
        Exception? innerException = null)
        : base(message ?? $"DNS lookup failed with response code {responseCode}.", innerException)
    {
        ResponseCode = responseCode;
    }

    public byte ResponseCode { get; }
}

public static class DnsResolverExtensions
{
    public static async ValueTask<DnsLookupResult> LookupAsync(
        this IDnsResolver resolver,
        string host,
        DnsLookupOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);

        var effectiveOptions = options ?? DnsLookupOptions.Default;
        if (resolver is IDnsLookupResolver lookupResolver)
        {
            return await lookupResolver.LookupAsync(host, effectiveOptions, cancellationToken).ConfigureAwait(false);
        }

        var addresses = await resolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        var filtered = FilterAddresses(addresses, effectiveOptions);
        return new DnsLookupResult
        {
            Addresses = filtered,
            IsEmptyResponse = filtered.Count == 0
        };
    }

    public static Exception CreateResolutionException(byte responseCode)
        => responseCode switch
        {
            DnsResponseCodes.NameError => new SocketException((int)SocketError.HostNotFound),
            DnsResponseCodes.Success => new InvalidOperationException("DNS response code 0 does not represent a resolution failure."),
            _ => new DnsResponseCodeException(responseCode)
        };

    public static byte GetResponseCode(Exception exception)
        => exception switch
        {
            DnsResponseCodeException dnsException => dnsException.ResponseCode,
            SocketException { SocketErrorCode: SocketError.HostNotFound or SocketError.NoData } => DnsResponseCodes.NameError,
            _ => DnsResponseCodes.Success
        };

    internal static IReadOnlyList<IPAddress> FilterAddresses(
        IReadOnlyList<IPAddress> addresses,
        DnsLookupOptions options)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        ArgumentNullException.ThrowIfNull(options);

        return addresses
            .Where(address =>
                (options.IPv4Enable && address.AddressFamily == AddressFamily.InterNetwork) ||
                (options.IPv6Enable && address.AddressFamily == AddressFamily.InterNetworkV6))
            .Select(static address => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address)
            .Distinct()
            .ToArray();
    }
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

    public IReadOnlyList<FakeDnsPoolRuntime> FakeDnsPools { get; init; } = Array.Empty<FakeDnsPoolRuntime>();
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

public sealed class SystemDnsResolver : IDnsLookupResolver
{
    public static SystemDnsResolver Instance { get; } = new();

    private SystemDnsResolver()
    {
    }

    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        => (await LookupAsync(host, DnsLookupOptions.Default, cancellationToken).ConfigureAwait(false)).Addresses;

    public async ValueTask<DnsLookupResult> LookupAsync(
        string host,
        DnsLookupOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentNullException.ThrowIfNull(options);

        var normalizedHost = host.Trim();
        if (IPAddress.TryParse(normalizedHost, out var ipAddress))
        {
            var literalAddresses = DnsResolverExtensions.FilterAddresses([ipAddress], options);
            return new DnsLookupResult
            {
                Addresses = literalAddresses,
                IsEmptyResponse = literalAddresses.Count == 0
            };
        }

        var addresses = await Dns.GetHostAddressesAsync(normalizedHost, cancellationToken).ConfigureAwait(false);
        var filtered = DnsResolverExtensions.FilterAddresses(addresses, options);
        return new DnsLookupResult
        {
            Addresses = filtered,
            IsEmptyResponse = filtered.Count == 0
        };
    }
}

public sealed class RuntimeDnsResolver : IDnsLookupResolver
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(5);

    private readonly ConcurrentDictionary<string, DnsCacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly HttpClient _httpClient;
    private readonly IFakeDnsEngine? _fakeDnsEngine;
    private readonly IDnsRuntimeSettingsProvider? _settingsProvider;

    public RuntimeDnsResolver(
        IDnsRuntimeSettingsProvider? settingsProvider = null,
        HttpClient? httpClient = null,
        IFakeDnsEngine? fakeDnsEngine = null)
    {
        _settingsProvider = settingsProvider;
        _httpClient = httpClient ?? CreateDefaultHttpClient();
        _fakeDnsEngine = fakeDnsEngine;
    }

    public async ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        var result = await LookupAsync(host, DnsLookupOptions.Default, cancellationToken).ConfigureAwait(false);
        if (result.ResponseCode != DnsResponseCodes.Success)
        {
            throw DnsResolverExtensions.CreateResolutionException(result.ResponseCode);
        }

        return result.Addresses;
    }

    public async ValueTask<DnsLookupResult> LookupAsync(
        string host,
        DnsLookupOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentNullException.ThrowIfNull(options);

        var normalizedHost = host.Trim();
        if (IPAddress.TryParse(normalizedHost, out var ipAddress))
        {
            var literalAddresses = DnsResolverExtensions.FilterAddresses([ipAddress], options);
            return new DnsLookupResult
            {
                Addresses = literalAddresses,
                IsEmptyResponse = literalAddresses.Count == 0
            };
        }

        var settings = _settingsProvider?.GetCurrentDnsSettings() ?? DnsRuntimeSettings.Default;
        var fakeResult = ResolveByFakeDns(normalizedHost, options);
        if (fakeResult is not null)
        {
            return fakeResult;
        }

        return DnsModes.Normalize(settings.Mode) switch
        {
            DnsModes.Http => await ResolveByHttpAsync(normalizedHost, settings, options, cancellationToken).ConfigureAwait(false),
            _ => await SystemDnsResolver.Instance.LookupAsync(normalizedHost, options, cancellationToken).ConfigureAwait(false)
        };
    }

    private DnsLookupResult? ResolveByFakeDns(string host, DnsLookupOptions options)
    {
        if (!options.FakeEnable || _fakeDnsEngine is null)
        {
            return null;
        }

        var addresses = _fakeDnsEngine.GetFakeIPForDomain(host, options.IPv4Enable, options.IPv6Enable);
        if (addresses.Count == 0)
        {
            return new DnsLookupResult
            {
                TtlSeconds = FakeDnsDefaults.DefaultTtlSeconds,
                IsEmptyResponse = true,
                IsFakeResponse = true
            };
        }

        return new DnsLookupResult
        {
            Addresses = addresses,
            TtlSeconds = FakeDnsDefaults.DefaultTtlSeconds,
            IsFakeResponse = true
        };
    }

    private async Task<DnsLookupResult> ResolveByHttpAsync(
        string host,
        DnsRuntimeSettings settings,
        DnsLookupOptions options,
        CancellationToken cancellationToken)
    {
        if (settings.Servers.Count == 0)
        {
            throw new InvalidOperationException("HTTP DNS mode requires at least one configured server.");
        }

        var cacheKey = BuildCacheKey(host, settings, options);
        if (TryGetCached(cacheKey, out var cached))
        {
            return cached;
        }

        Exception? lastError = null;
        DnsLookupResult? lastDnsResult = null;
        foreach (var server in settings.Servers)
        {
            try
            {
                var result = await ResolveByHttpServerAsync(host, server, settings, options, cancellationToken).ConfigureAwait(false);
                if (result.ResponseCode == DnsResponseCodes.Success)
                {
                    if (result.Addresses.Count > 0 || result.IsEmptyResponse)
                    {
                        Cache(cacheKey, result, settings);
                        return result;
                    }
                }

                lastDnsResult = result;
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

        if (lastDnsResult is not null)
        {
            return lastDnsResult;
        }

        if (lastError is not null)
        {
            throw lastError;
        }

        return new DnsLookupResult
        {
            IsEmptyResponse = true
        };
    }

    private async Task<DnsLookupResult> ResolveByHttpServerAsync(
        string host,
        DnsHttpServerRuntime server,
        DnsRuntimeSettings settings,
        DnsLookupOptions options,
        CancellationToken cancellationToken)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linkedCts.CancelAfter(ResolveTimeout(settings.TimeoutSeconds));

        var tasks = new List<Task<DnsRecordLookupResult>>(2);
        if (options.IPv4Enable)
        {
            tasks.Add(QueryRecordAsync(host, "A", server, linkedCts.Token));
        }

        if (options.IPv6Enable)
        {
            tasks.Add(QueryRecordAsync(host, "AAAA", server, linkedCts.Token));
        }

        if (tasks.Count == 0)
        {
            return new DnsLookupResult
            {
                IsEmptyResponse = true
            };
        }

        var records = new List<DnsRecordLookupResult>(tasks.Count);
        Exception? lastError = null;

        foreach (var task in tasks)
        {
            try
            {
                records.Add(await task.ConfigureAwait(false));
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested && cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError ??= ex;
            }
        }

        if (records.Count > 0)
        {
            var successfulAddresses = records
                .Where(static record => record.ResponseCode == DnsResponseCodes.Success)
                .SelectMany(static record => record.Addresses)
                .Distinct()
                .ToArray();
            if (successfulAddresses.Length > 0)
            {
                return new DnsLookupResult
                {
                    Addresses = successfulAddresses,
                    TtlSeconds = records
                        .Where(static record => record.ResponseCode == DnsResponseCodes.Success && record.Addresses.Count > 0)
                        .Select(static record => record.TtlSeconds)
                        .DefaultIfEmpty(DnsResolutionDefaults.DefaultTtl)
                        .Min(),
                    IsEmptyResponse = false
                };
            }

            if (records.Any(static record => record.ResponseCode == DnsResponseCodes.Success && record.IsEmptyResponse))
            {
                return new DnsLookupResult
                {
                    TtlSeconds = records
                        .Where(static record => record.ResponseCode == DnsResponseCodes.Success)
                        .Select(static record => record.TtlSeconds)
                        .DefaultIfEmpty(DnsResolutionDefaults.DefaultTtl)
                        .Min(),
                    IsEmptyResponse = true
                };
            }

            var responseCode = records
                .Select(static record => record.ResponseCode)
                .FirstOrDefault(static code => code != DnsResponseCodes.Success);
            if (responseCode != DnsResponseCodes.Success)
            {
                return new DnsLookupResult
                {
                    ResponseCode = responseCode
                };
            }
        }

        if (lastError is not null)
        {
            throw lastError;
        }

        return new DnsLookupResult
        {
            IsEmptyResponse = true
        };
    }

    private async Task<DnsRecordLookupResult> QueryRecordAsync(
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
        return ParseRecordLookupResult(document.RootElement, recordType);
    }

    private void Cache(string cacheKey, DnsLookupResult result, DnsRuntimeSettings settings)
    {
        if (settings.CacheTtlSeconds <= 0 ||
            (result.Addresses.Count == 0 && !result.IsEmptyResponse) ||
            result.ResponseCode != DnsResponseCodes.Success)
        {
            return;
        }

        _cache[cacheKey] = new DnsCacheEntry(
            result,
            DateTimeOffset.UtcNow.AddSeconds(settings.CacheTtlSeconds));
    }

    private bool TryGetCached(string cacheKey, out DnsLookupResult result)
    {
        if (_cache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            result = cached.Result;
            return true;
        }

        _cache.TryRemove(cacheKey, out _);
        result = new DnsLookupResult();
        return false;
    }

    private static TimeSpan ResolveTimeout(int timeoutSeconds)
        => timeoutSeconds > 0 ? TimeSpan.FromSeconds(timeoutSeconds) : DefaultTimeout;

    private static string BuildCacheKey(string host, DnsRuntimeSettings settings, DnsLookupOptions options)
        => string.Create(
            host.Length + settings.Mode.Length + 5 + settings.Servers.Sum(static server => server.Url.Length + 1),
            (Host: host, Settings: settings, Options: options),
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

                span[offset++] = '|';
                span[offset++] = state.Options.IPv4Enable ? '4' : '-';
                span[offset++] = state.Options.IPv6Enable ? '6' : '-';
                span[offset] = state.Options.FakeEnable ? 'f' : '-';
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

    private static DnsRecordLookupResult ParseRecordLookupResult(JsonElement root, string recordType)
    {
        var addresses = new List<IPAddress>(4);
        uint? minTtl = null;
        var responseCode = ReadResponseCode(root);

        if (TryGetPropertyIgnoreCase(root, "addresses", out var addressesElement) &&
            addressesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in addressesElement.EnumerateArray())
            {
                if (TryReadAddress(item, out var address))
                {
                    addresses.Add(address);
                    if (TryReadTtl(item, out var ttl))
                    {
                        minTtl = !minTtl.HasValue || ttl < minTtl.Value ? ttl : minTtl.Value;
                    }
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
                        if (TryReadTtl(item, out var ttl))
                        {
                            minTtl = !minTtl.HasValue || ttl < minTtl.Value ? ttl : minTtl.Value;
                        }
                    }
                }
            }
        }

        var filtered = FilterRecordAddresses(
            addresses
            .Distinct()
            .ToArray(),
            recordType);
        return new DnsRecordLookupResult(
            filtered,
            minTtl ?? DnsResolutionDefaults.DefaultTtl,
            responseCode,
            responseCode == DnsResponseCodes.Success && filtered.Count == 0);
    }

    private static byte ReadResponseCode(JsonElement root)
    {
        if (!TryGetPropertyIgnoreCase(root, "status", out var statusElement) &&
            !TryGetPropertyIgnoreCase(root, "rcode", out statusElement) &&
            !TryGetPropertyIgnoreCase(root, "responseCode", out statusElement))
        {
            return DnsResponseCodes.Success;
        }

        if (statusElement.ValueKind == JsonValueKind.Number &&
            statusElement.TryGetInt32(out var numericCode) &&
            numericCode >= 0 &&
            numericCode <= byte.MaxValue)
        {
            return (byte)numericCode;
        }

        if (statusElement.ValueKind == JsonValueKind.String &&
            byte.TryParse(statusElement.GetString(), out var parsedCode))
        {
            return parsedCode;
        }

        return DnsResponseCodes.Success;
    }

    private static IReadOnlyList<IPAddress> FilterRecordAddresses(
        IReadOnlyList<IPAddress> addresses,
        string recordType)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        return recordType.ToUpperInvariant() switch
        {
            "A" => addresses
                .Where(static address => address.AddressFamily == AddressFamily.InterNetwork)
                .ToArray(),
            "AAAA" => addresses
                .Where(static address => address.AddressFamily == AddressFamily.InterNetworkV6)
                .ToArray(),
            _ => addresses.ToArray()
        };
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

    private static bool TryReadTtl(JsonElement element, out uint ttl)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            (TryGetPropertyIgnoreCase(element, "ttl", out var ttlElement) ||
             TryGetPropertyIgnoreCase(element, "TTL", out ttlElement)))
        {
            if (ttlElement.ValueKind == JsonValueKind.Number &&
                ttlElement.TryGetUInt32(out ttl))
            {
                return true;
            }

            if (ttlElement.ValueKind == JsonValueKind.String &&
                uint.TryParse(ttlElement.GetString(), out ttl))
            {
                return true;
            }
        }

        ttl = 0;
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

    private sealed record DnsRecordLookupResult(
        IReadOnlyList<IPAddress> Addresses,
        uint TtlSeconds,
        byte ResponseCode,
        bool IsEmptyResponse);

    private sealed record DnsCacheEntry(DnsLookupResult Result, DateTimeOffset ExpiresAt);
}

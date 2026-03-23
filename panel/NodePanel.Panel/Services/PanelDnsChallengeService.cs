using System.Net.Http.Headers;
using System.Text.Json;
using AlibabaCloud.SDK.Alidns20150109;
using AlibabaCloud.SDK.Alidns20150109.Models;
using AlibabaCloud.TeaUtil.Models;
using NodePanel.Panel.Models;
using TencentCloud.Common;
using TencentCloud.Common.Profile;
using TencentCloud.Dnspod.V20210323;
using TencentCloud.Dnspod.V20210323.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelDnsChallengeService
{
    private const int DnsTtlSeconds = 600;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly IHttpClientFactory _httpClientFactory;

    public PanelDnsChallengeService(
        IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public bool HasApiProvider(PanelCertificateRecord record)
        => !string.IsNullOrWhiteSpace(PanelDnsProviderTypes.Normalize(record.DnsProvider));

    public TimeSpan GetPropagationDelay(PanelCertificateRecord record)
        => PanelDnsProviderTypes.Normalize(record.DnsProvider) == PanelDnsProviderTypes.DnsPod
            ? TimeSpan.FromSeconds(30)
            : TimeSpan.FromSeconds(10);

    public async Task PresentTxtRecordAsync(
        PanelCertificateRecord record,
        string recordName,
        string recordValue,
        CancellationToken cancellationToken)
    {
        var spec = BuildSpec(record, recordName, recordValue);
        switch (PanelDnsProviderTypes.Normalize(record.DnsProvider))
        {
            case PanelDnsProviderTypes.Cloudflare:
                await PresentCloudflareAsync(record, spec, cancellationToken).ConfigureAwait(false);
                return;

            case PanelDnsProviderTypes.AliDns:
                await PresentAliDnsAsync(record, spec, cancellationToken).ConfigureAwait(false);
                return;

            case PanelDnsProviderTypes.DnsPod:
                await PresentDnsPodAsync(record, spec, cancellationToken).ConfigureAwait(false);
                return;

            default:
                throw new InvalidOperationException("DNS API provider is not configured.");
        }
    }

    public async Task CleanupTxtRecordAsync(
        PanelCertificateRecord record,
        string recordName,
        string recordValue,
        CancellationToken cancellationToken)
    {
        var spec = BuildSpec(record, recordName, recordValue);
        switch (PanelDnsProviderTypes.Normalize(record.DnsProvider))
        {
            case PanelDnsProviderTypes.Cloudflare:
                await CleanupCloudflareAsync(record, spec, cancellationToken).ConfigureAwait(false);
                return;

            case PanelDnsProviderTypes.AliDns:
                await CleanupAliDnsAsync(record, spec, cancellationToken).ConfigureAwait(false);
                return;

            case PanelDnsProviderTypes.DnsPod:
                await CleanupDnsPodAsync(record, spec, cancellationToken).ConfigureAwait(false);
                return;

            default:
                throw new InvalidOperationException("DNS API provider is not configured.");
        }
    }

    private async Task PresentCloudflareAsync(
        PanelCertificateRecord record,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var zoneId = await GetCloudflareZoneIdAsync(record, spec.Zone, cancellationToken).ConfigureAwait(false);
        var records = await GetCloudflareRecordsAsync(record, zoneId, spec.RecordName, cancellationToken).ConfigureAwait(false);
        if (records.Any(item => string.Equals(item.Content, spec.Value, StringComparison.Ordinal)))
        {
            return;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://api.cloudflare.com/client/v4/zones/{zoneId}/dns_records")
        {
            Content = JsonContent.Create(
                new
                {
                    type = "TXT",
                    name = spec.RecordName,
                    content = spec.Value,
                    ttl = 120
                },
                options: JsonOptions)
        };

        ApplyCloudflareAuth(request, record);
        await SendCloudflareAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task CleanupCloudflareAsync(
        PanelCertificateRecord record,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var zoneId = await GetCloudflareZoneIdAsync(record, spec.Zone, cancellationToken).ConfigureAwait(false);
        var records = await GetCloudflareRecordsAsync(record, zoneId, spec.RecordName, cancellationToken).ConfigureAwait(false);
        foreach (var item in records.Where(item => string.Equals(item.Content, spec.Value, StringComparison.Ordinal)))
        {
            using var request = new HttpRequestMessage(HttpMethod.Delete, $"https://api.cloudflare.com/client/v4/zones/{zoneId}/dns_records/{item.Id}");
            ApplyCloudflareAuth(request, record);
            await SendCloudflareAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<string> GetCloudflareZoneIdAsync(
        PanelCertificateRecord record,
        string zone,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.cloudflare.com/client/v4/zones?name={Uri.EscapeDataString(zone)}&status=active&per_page=1");
        ApplyCloudflareAuth(request, record);
        using var response = await SendCloudflareAsync(request, cancellationToken).ConfigureAwait(false);

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        var zoneId = document.RootElement.GetProperty("result")
            .EnumerateArray()
            .Select(static item => item.TryGetProperty("id", out var id) ? id.GetString() : null)
            .FirstOrDefault(static item => !string.IsNullOrWhiteSpace(item));

        return zoneId?.Trim() ?? throw new InvalidOperationException($"Cloudflare zone '{zone}' does not exist or is not accessible.");
    }

    private async Task<IReadOnlyList<CloudflareDnsRecord>> GetCloudflareRecordsAsync(
        PanelCertificateRecord record,
        string zoneId,
        string recordName,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://api.cloudflare.com/client/v4/zones/{zoneId}/dns_records?type=TXT&name={Uri.EscapeDataString(recordName)}");
        ApplyCloudflareAuth(request, record);
        using var response = await SendCloudflareAsync(request, cancellationToken).ConfigureAwait(false);

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        return document.RootElement.GetProperty("result")
            .EnumerateArray()
            .Select(static item => new CloudflareDnsRecord(
                item.GetProperty("id").GetString() ?? string.Empty,
                item.GetProperty("content").GetString() ?? string.Empty))
            .ToArray();
    }

    private async Task<HttpResponseMessage> SendCloudflareAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(nameof(PanelDnsChallengeService));
        var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        response.Dispose();
        throw new InvalidOperationException($"Cloudflare DNS API failed: {(int)response.StatusCode} {body}".Trim());
    }

    private static void ApplyCloudflareAuth(HttpRequestMessage request, PanelCertificateRecord record)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", record.DnsApiToken.Trim());
    }

    private async Task PresentAliDnsAsync(
        PanelCertificateRecord record,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var client = CreateAliDnsClient(record);
        var existingRecords = await ListAliDnsRecordsAsync(client, spec, cancellationToken).ConfigureAwait(false);
        if (existingRecords.Any(item => string.Equals(item.Value, spec.Value, StringComparison.Ordinal)))
        {
            return;
        }

        var request = new AddDomainRecordRequest
        {
            DomainName = spec.Zone,
            RR = spec.RelativeName,
            Type = "TXT",
            Value = spec.Value,
            TTL = DnsTtlSeconds,
            Line = "default"
        };

        await client.AddDomainRecordWithOptionsAsync(request, new RuntimeOptions()).ConfigureAwait(false);
    }

    private async Task CleanupAliDnsAsync(
        PanelCertificateRecord record,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var client = CreateAliDnsClient(record);
        var existingRecords = await ListAliDnsRecordsAsync(client, spec, cancellationToken).ConfigureAwait(false);
        foreach (var existing in existingRecords.Where(item => string.Equals(item.Value, spec.Value, StringComparison.Ordinal)))
        {
            var request = new DeleteDomainRecordRequest
            {
                RecordId = existing.RecordId
            };

            await client.DeleteDomainRecordWithOptionsAsync(request, new RuntimeOptions()).ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyList<AliDnsRecord>> ListAliDnsRecordsAsync(
        Client client,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var request = new DescribeSubDomainRecordsRequest
        {
            SubDomain = spec.RecordName,
            Type = "TXT",
            PageSize = 100
        };

        var response = await client.DescribeSubDomainRecordsWithOptionsAsync(request, new RuntimeOptions()).ConfigureAwait(false);
        return response.Body.DomainRecords.Record
            .Select(static item => new AliDnsRecord(item.RecordId ?? string.Empty, item.Value ?? string.Empty))
            .ToArray();
    }

    private static Client CreateAliDnsClient(PanelCertificateRecord record)
        => new(new AlibabaCloud.OpenApiClient.Models.Config
        {
            AccessKeyId = record.DnsAccessKeyId.Trim(),
            AccessKeySecret = record.DnsAccessKeySecret.Trim(),
            Endpoint = "alidns.cn-hangzhou.aliyuncs.com"
        });

    private async Task PresentDnsPodAsync(
        PanelCertificateRecord record,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var client = CreateDnsPodClient(record);
        var existingRecords = await ListDnsPodRecordsAsync(client, spec, cancellationToken).ConfigureAwait(false);
        if (existingRecords.Any(item => string.Equals(item.Value, spec.Value, StringComparison.Ordinal)))
        {
            return;
        }

        var request = new CreateRecordRequest
        {
            Domain = spec.Zone,
            SubDomain = spec.RelativeName,
            RecordType = "TXT",
            RecordLineId = "0",
            Value = spec.Value,
            TTL = DnsTtlSeconds
        };

        await client.CreateRecord(request).ConfigureAwait(false);
    }

    private async Task CleanupDnsPodAsync(
        PanelCertificateRecord record,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var client = CreateDnsPodClient(record);
        var existingRecords = await ListDnsPodRecordsAsync(client, spec, cancellationToken).ConfigureAwait(false);
        foreach (var existing in existingRecords.Where(item => string.Equals(item.Value, spec.Value, StringComparison.Ordinal)))
        {
            var request = new DeleteRecordRequest
            {
                Domain = spec.Zone,
                RecordId = existing.RecordId
            };

            await client.DeleteRecord(request).ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyList<DnsPodRecord>> ListDnsPodRecordsAsync(
        DnspodClient client,
        DnsTxtRecordSpec spec,
        CancellationToken cancellationToken)
    {
        var request = new DescribeRecordListRequest
        {
            Domain = spec.Zone,
            Subdomain = spec.RelativeName,
            RecordType = "TXT",
            Limit = 100
        };

        var response = await client.DescribeRecordList(request).ConfigureAwait(false);
        var recordList = response.RecordList;
        if (recordList is null)
        {
            return Array.Empty<DnsPodRecord>();
        }

        return recordList
            .Where(static item => item.RecordId.HasValue)
            .Select(static item => new DnsPodRecord(item.RecordId!.Value, item.Value ?? string.Empty))
            .ToArray();
    }

    private static DnspodClient CreateDnsPodClient(PanelCertificateRecord record)
    {
        var credential = new Credential
        {
            SecretId = record.DnsAccessKeyId.Trim(),
            SecretKey = record.DnsAccessKeySecret.Trim()
        };

        var profile = new ClientProfile();
        profile.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com";
        return new DnspodClient(credential, string.Empty, profile);
    }

    private static DnsTxtRecordSpec BuildSpec(
        PanelCertificateRecord record,
        string recordName,
        string recordValue)
    {
        var zone = NormalizeDomain(record.DnsZone);
        if (string.IsNullOrWhiteSpace(zone))
        {
            throw new InvalidOperationException("DNS API provider requires a root zone.");
        }

        var normalizedRecordName = NormalizeDomain(recordName);
        if (!string.Equals(normalizedRecordName, zone, StringComparison.OrdinalIgnoreCase) &&
            !normalizedRecordName.EndsWith($".{zone}", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"DNS record '{recordName}' does not belong to zone '{record.DnsZone}'.");
        }

        var relativeName = string.Equals(normalizedRecordName, zone, StringComparison.OrdinalIgnoreCase)
            ? "@"
            : normalizedRecordName[..^(zone.Length + 1)];

        return new DnsTxtRecordSpec(
            zone,
            normalizedRecordName,
            relativeName,
            recordValue.Trim());
    }

    private static string NormalizeDomain(string? value)
        => value?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;

    private sealed record DnsTxtRecordSpec(string Zone, string RecordName, string RelativeName, string Value);

    private sealed record CloudflareDnsRecord(string Id, string Content);

    private sealed record AliDnsRecord(string RecordId, string Value);

    private sealed record DnsPodRecord(ulong RecordId, string Value);
}

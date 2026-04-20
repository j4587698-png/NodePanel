using System.Net;
using System.Text;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.ControlPlane.Runtime;

internal static class RoutingResourceExpander
{
    private const string GeoSitePrefix = "geosite:";
    private const string GeoIpPrefix = "geoip:";
    private const string GeoIpReversePrefix = "geoip:!";
    private const string ExtPrefix = "ext:";
    private const string ExtDomainPrefix = "ext-domain:";
    private const string ExtIpPrefix = "ext-ip:";
    private const string DefaultGeoSiteFileName = "geosite.dat";
    private const string DefaultGeoIpFileName = "geoip.dat";

    public static bool TryExpand(
        NodeServiceConfig config,
        out NodeServiceConfig expanded,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(config);

        var rules = new List<RoutingRuleConfig>(config.RoutingRules.Count);
        for (var index = 0; index < config.RoutingRules.Count; index++)
        {
            if (!TryExpandRule(config.RoutingRules[index], config.RoutingResources, out var rule, out error))
            {
                expanded = config;
                return false;
            }

            rules.Add(rule);
        }

        expanded = config with
        {
            RoutingRules = rules.ToArray()
        };
        error = null;
        return true;
    }

    private static bool TryExpandRule(
        RoutingRuleConfig rule,
        RoutingResourceOptions resources,
        out RoutingRuleConfig expanded,
        out string? error)
    {
        if (!TryExpandDomains(rule.Domains, resources, out var domains, out error) ||
            !TryExpandCidrs(rule.SourceCidrs, resources, "source", out var sourceCidrs, out error) ||
            !TryExpandCidrs(rule.DestinationCidrs, resources, "destination", out var destinationCidrs, out error) ||
            !TryExpandCidrs(rule.LocalCidrs, resources, "local", out var localCidrs, out error))
        {
            expanded = rule;
            return false;
        }

        expanded = rule with
        {
            Domains = domains,
            SourceCidrs = sourceCidrs,
            DestinationCidrs = destinationCidrs,
            LocalCidrs = localCidrs
        };
        error = null;
        return true;
    }

    private static bool TryExpandDomains(
        IReadOnlyList<string> values,
        RoutingResourceOptions resources,
        out IReadOnlyList<string> expanded,
        out string? error)
    {
        var result = new List<string>(values.Count);
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index]?.Trim() ?? string.Empty;
            if (value.Length == 0)
            {
                continue;
            }

            if (TryStripPrefix(value, GeoSitePrefix, out var siteWithAttr))
            {
                if (!TryLoadGeoSite(resourcePath: ResolveGeoSitePath(resources), siteWithAttr, out var domains, out error))
                {
                    error = $"Failed to load geosite: {siteWithAttr}. {error}";
                    expanded = Array.Empty<string>();
                    return false;
                }

                result.AddRange(domains);
                continue;
            }

            if (TryStripPrefix(value, ExtPrefix, out var extDomainSpec) ||
                TryStripPrefix(value, ExtDomainPrefix, out extDomainSpec))
            {
                if (!TryParseExternalResourceSpec(extDomainSpec, out var fileName, out var siteCode, out error))
                {
                    error = $"Routing external domain resource is invalid: {value}. {error}";
                    expanded = Array.Empty<string>();
                    return false;
                }

                if (!TryLoadGeoSite(ResolveResourcePath(resources, fileName), siteCode, out var domains, out error))
                {
                    error = $"Failed to load external sites: {siteCode} from {fileName}. {error}";
                    expanded = Array.Empty<string>();
                    return false;
                }

                result.AddRange(domains);
                continue;
            }

            result.Add(value);
        }

        expanded = result.ToArray();
        error = null;
        return true;
    }

    private static bool TryExpandCidrs(
        IReadOnlyList<string> values,
        RoutingResourceOptions resources,
        string scope,
        out IReadOnlyList<string> expanded,
        out string? error)
    {
        var result = new List<string>(values.Count);
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index]?.Trim() ?? string.Empty;
            if (value.Length == 0)
            {
                continue;
            }

            var reverseMatch = false;
            string countryCode;
            if (TryStripPrefix(value, GeoIpReversePrefix, out countryCode))
            {
                reverseMatch = true;
            }
            else if (TryStripPrefix(value, GeoIpPrefix, out countryCode))
            {
                reverseMatch = false;
            }
            else
            {
                countryCode = string.Empty;
            }

            if (countryCode.Length > 0 || value.StartsWith(GeoIpPrefix, StringComparison.OrdinalIgnoreCase))
            {
                if (!TryLoadGeoIp(
                        ResolveGeoIpPath(resources),
                        countryCode,
                        reverseMatch,
                        out var cidrs,
                        out error))
                {
                    error = $"Failed to load GeoIP for {scope}: {countryCode}. {error}";
                    expanded = Array.Empty<string>();
                    return false;
                }

                result.AddRange(cidrs);
                continue;
            }

            if (TryStripPrefix(value, ExtPrefix, out var extIpSpec) ||
                TryStripPrefix(value, ExtIpPrefix, out extIpSpec))
            {
                if (!TryParseExternalResourceSpec(extIpSpec, out var fileName, out var extCountry, out error))
                {
                    error = $"Routing external IP resource is invalid: {value}. {error}";
                    expanded = Array.Empty<string>();
                    return false;
                }

                reverseMatch = extCountry.StartsWith("!", StringComparison.Ordinal);
                if (reverseMatch)
                {
                    extCountry = extCountry[1..];
                }

                if (!TryLoadGeoIp(
                        ResolveResourcePath(resources, fileName),
                        extCountry,
                        reverseMatch,
                        out var cidrs,
                        out error))
                {
                    error = $"Failed to load external IPs for {scope}: {extCountry} from {fileName}. {error}";
                    expanded = Array.Empty<string>();
                    return false;
                }

                result.AddRange(cidrs);
                continue;
            }

            result.Add(value);
        }

        expanded = result.ToArray();
        error = null;
        return true;
    }

    private static string ResolveGeoSitePath(RoutingResourceOptions resources)
        => ResolveResourcePath(resources, string.IsNullOrWhiteSpace(resources.GeoSitePath)
            ? DefaultGeoSiteFileName
            : resources.GeoSitePath);

    private static string ResolveGeoIpPath(RoutingResourceOptions resources)
        => ResolveResourcePath(resources, string.IsNullOrWhiteSpace(resources.GeoIpPath)
            ? DefaultGeoIpFileName
            : resources.GeoIpPath);

    private static string ResolveResourcePath(RoutingResourceOptions resources, string value)
    {
        var path = value.Trim();
        if (Path.IsPathFullyQualified(path))
        {
            return Path.GetFullPath(path);
        }

        if (!string.IsNullOrWhiteSpace(resources.ResourceDirectory))
        {
            return Path.GetFullPath(Path.Combine(resources.ResourceDirectory.Trim(), path));
        }

        return Path.GetFullPath(path);
    }

    private static bool TryLoadGeoSite(
        string resourcePath,
        string siteWithAttr,
        out IReadOnlyList<string> domains,
        out string? error)
    {
        if (!TryParseSiteWithAttributes(siteWithAttr, out var countryCode, out var requiredAttributes, out error))
        {
            domains = Array.Empty<string>();
            return false;
        }

        if (!TryReadFile(resourcePath, out var bytes, out error))
        {
            domains = Array.Empty<string>();
            return false;
        }

        if (!TryFindGeoSite(bytes, countryCode, out var site, out error))
        {
            domains = Array.Empty<string>();
            return false;
        }

        var result = new List<string>(site.Domains.Count);
        for (var index = 0; index < site.Domains.Count; index++)
        {
            var domain = site.Domains[index];
            if (!MatchesAllAttributes(domain.Attributes, requiredAttributes))
            {
                continue;
            }

            if (TryConvertDomainRule(domain, out var value))
            {
                result.Add(value);
            }
        }

        domains = result.ToArray();
        error = null;
        return true;
    }

    private static bool TryLoadGeoIp(
        string resourcePath,
        string countryCode,
        bool reverseMatch,
        out IReadOnlyList<string> cidrs,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
        {
            cidrs = Array.Empty<string>();
            error = "Country code cannot be empty.";
            return false;
        }

        if (!TryReadFile(resourcePath, out var bytes, out error))
        {
            cidrs = Array.Empty<string>();
            return false;
        }

        if (!TryFindGeoIp(bytes, countryCode, out var geoIp, out error))
        {
            cidrs = Array.Empty<string>();
            return false;
        }

        var result = new List<string>(geoIp.Cidrs.Count);
        for (var index = 0; index < geoIp.Cidrs.Count; index++)
        {
            var cidr = geoIp.Cidrs[index];
            var text = cidr.Address + "/" + cidr.PrefixLength.ToString();
            result.Add(reverseMatch ? "!" + text : text);
        }

        cidrs = result.ToArray();
        error = null;
        return true;
    }

    private static bool TryReadFile(string path, out byte[] bytes, out string? error)
    {
        try
        {
            bytes = File.ReadAllBytes(path);
            error = null;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            bytes = Array.Empty<byte>();
            error = ex.Message;
            return false;
        }
    }

    private static bool TryParseSiteWithAttributes(
        string value,
        out string countryCode,
        out IReadOnlySet<string> requiredAttributes,
        out string? error)
    {
        var parts = value.Split('@', StringSplitOptions.None);
        if (parts.Length == 0 || string.IsNullOrWhiteSpace(parts[0]))
        {
            countryCode = string.Empty;
            requiredAttributes = new HashSet<string>(StringComparer.Ordinal);
            error = "Site code cannot be empty.";
            return false;
        }

        countryCode = parts[0].Trim().ToUpperInvariant();
        var attributes = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 1; index < parts.Length; index++)
        {
            var attribute = parts[index].Trim().ToLowerInvariant();
            if (attribute.Length == 0)
            {
                continue;
            }

            attributes.Add(attribute);
        }

        requiredAttributes = attributes;
        error = null;
        return true;
    }

    private static bool MatchesAllAttributes(
        IReadOnlySet<string> domainAttributes,
        IReadOnlySet<string> requiredAttributes)
    {
        if (requiredAttributes.Count == 0)
        {
            return true;
        }

        foreach (var attribute in requiredAttributes)
        {
            if (!domainAttributes.Contains(attribute))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryConvertDomainRule(ParsedGeoDomain domain, out string value)
    {
        var pattern = domain.Value.Trim();
        if (pattern.Length == 0)
        {
            value = string.Empty;
            return false;
        }

        value = domain.Type switch
        {
            0 => pattern,
            1 => "regexp:" + pattern,
            2 => "domain:" + pattern,
            3 => "full:" + pattern,
            _ => string.Empty
        };
        return value.Length > 0;
    }

    private static bool TryParseExternalResourceSpec(
        string value,
        out string fileName,
        out string code,
        out string? error)
    {
        var separatorIndex = value.LastIndexOf(':');
        if (separatorIndex <= 0 || separatorIndex >= value.Length - 1)
        {
            fileName = string.Empty;
            code = string.Empty;
            error = "Expected '<file>:<code>' format.";
            return false;
        }

        fileName = value[..separatorIndex].Trim();
        code = value[(separatorIndex + 1)..].Trim();
        if (fileName.Length == 0 || code.Length == 0)
        {
            error = "Filename and code cannot be empty.";
            return false;
        }

        error = null;
        return true;
    }

    private static bool TryFindGeoSite(
        ReadOnlySpan<byte> data,
        string countryCode,
        out ParsedGeoSite geoSite,
        out string? error)
    {
        var offset = 0;
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                geoSite = default!;
                error = "GeoSite data is truncated.";
                return false;
            }

            if (fieldNumber != 1 || wireType != 2)
            {
                if (!TrySkipFieldValue(data, ref offset, wireType))
                {
                    geoSite = default!;
                    error = "GeoSite data contains an unsupported field.";
                    return false;
                }

                continue;
            }

            if (!TryReadLengthDelimited(data, ref offset, out var payload))
            {
                geoSite = default!;
                error = "GeoSite entry is truncated.";
                return false;
            }

            if (!TryParseGeoSite(payload, out var candidate, out error))
            {
                geoSite = default!;
                return false;
            }

            if (string.Equals(candidate.CountryCode, countryCode, StringComparison.OrdinalIgnoreCase))
            {
                geoSite = candidate;
                error = null;
                return true;
            }
        }

        geoSite = default!;
        error = $"GeoSite code '{countryCode}' was not found.";
        return false;
    }

    private static bool TryFindGeoIp(
        ReadOnlySpan<byte> data,
        string countryCode,
        out ParsedGeoIp geoIp,
        out string? error)
    {
        var offset = 0;
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                geoIp = default!;
                error = "GeoIP data is truncated.";
                return false;
            }

            if (fieldNumber != 1 || wireType != 2)
            {
                if (!TrySkipFieldValue(data, ref offset, wireType))
                {
                    geoIp = default!;
                    error = "GeoIP data contains an unsupported field.";
                    return false;
                }

                continue;
            }

            if (!TryReadLengthDelimited(data, ref offset, out var payload))
            {
                geoIp = default!;
                error = "GeoIP entry is truncated.";
                return false;
            }

            if (!TryParseGeoIp(payload, out var candidate, out error))
            {
                geoIp = default!;
                return false;
            }

            if (string.Equals(candidate.CountryCode, countryCode, StringComparison.OrdinalIgnoreCase))
            {
                geoIp = candidate;
                error = null;
                return true;
            }
        }

        geoIp = default!;
        error = $"GeoIP code '{countryCode}' was not found.";
        return false;
    }

    private static bool TryParseGeoSite(
        ReadOnlySpan<byte> data,
        out ParsedGeoSite geoSite,
        out string? error)
    {
        var offset = 0;
        var countryCode = string.Empty;
        var domains = new List<ParsedGeoDomain>();
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                geoSite = default!;
                error = "GeoSite message is truncated.";
                return false;
            }

            switch (fieldNumber, wireType)
            {
                case (1, 2):
                    if (!TryReadString(data, ref offset, out countryCode))
                    {
                        geoSite = default!;
                        error = "GeoSite country code is invalid.";
                        return false;
                    }

                    break;
                case (2, 2):
                    if (!TryReadLengthDelimited(data, ref offset, out var payload))
                    {
                        geoSite = default!;
                        error = "GeoSite domain entry is invalid.";
                        return false;
                    }

                    if (!TryParseDomain(payload, out var domain, out error))
                    {
                        geoSite = default!;
                        error ??= "GeoSite domain entry is invalid.";
                        return false;
                    }

                    domains.Add(domain);
                    break;
                default:
                    if (!TrySkipFieldValue(data, ref offset, wireType))
                    {
                        geoSite = default!;
                        error = "GeoSite message contains an unsupported field.";
                        return false;
                    }

                    break;
            }
        }

        geoSite = new ParsedGeoSite(countryCode, domains);
        error = null;
        return true;
    }

    private static bool TryParseGeoIp(
        ReadOnlySpan<byte> data,
        out ParsedGeoIp geoIp,
        out string? error)
    {
        var offset = 0;
        var countryCode = string.Empty;
        var cidrs = new List<ParsedGeoCidr>();
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                geoIp = default!;
                error = "GeoIP message is truncated.";
                return false;
            }

            switch (fieldNumber, wireType)
            {
                case (1, 2):
                    if (!TryReadString(data, ref offset, out countryCode))
                    {
                        geoIp = default!;
                        error = "GeoIP country code is invalid.";
                        return false;
                    }

                    break;
                case (2, 2):
                    if (!TryReadLengthDelimited(data, ref offset, out var payload))
                    {
                        geoIp = default!;
                        error = "GeoIP CIDR entry is invalid.";
                        return false;
                    }

                    if (!TryParseCidr(payload, out var cidr, out error))
                    {
                        geoIp = default!;
                        error ??= "GeoIP CIDR entry is invalid.";
                        return false;
                    }

                    cidrs.Add(cidr);
                    break;
                default:
                    if (!TrySkipFieldValue(data, ref offset, wireType))
                    {
                        geoIp = default!;
                        error = "GeoIP message contains an unsupported field.";
                        return false;
                    }

                    break;
            }
        }

        geoIp = new ParsedGeoIp(countryCode, cidrs);
        error = null;
        return true;
    }

    private static bool TryParseDomain(
        ReadOnlySpan<byte> data,
        out ParsedGeoDomain domain,
        out string? error)
    {
        var offset = 0;
        var type = 0;
        var value = string.Empty;
        var attributes = new HashSet<string>(StringComparer.Ordinal);
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                domain = default!;
                error = "Domain message is truncated.";
                return false;
            }

            switch (fieldNumber, wireType)
            {
                case (1, 0):
                    if (!TryReadVarint(data, ref offset, out var rawType))
                    {
                        domain = default!;
                        error = "Domain type is invalid.";
                        return false;
                    }

                    type = (int)rawType;
                    break;
                case (2, 2):
                    if (!TryReadString(data, ref offset, out value))
                    {
                        domain = default!;
                        error = "Domain value is invalid.";
                        return false;
                    }

                    break;
                case (3, 2):
                    if (!TryReadLengthDelimited(data, ref offset, out var payload))
                    {
                        domain = default!;
                        error = "Domain attribute is invalid.";
                        return false;
                    }

                    if (!TryParseDomainAttribute(payload, out var attribute, out error))
                    {
                        domain = default!;
                        error ??= "Domain attribute is invalid.";
                        return false;
                    }

                    if (attribute.Length > 0)
                    {
                        attributes.Add(attribute);
                    }

                    break;
                default:
                    if (!TrySkipFieldValue(data, ref offset, wireType))
                    {
                        domain = default!;
                        error = "Domain message contains an unsupported field.";
                        return false;
                    }

                    break;
            }
        }

        domain = new ParsedGeoDomain(type, value, attributes);
        error = null;
        return true;
    }

    private static bool TryParseDomainAttribute(
        ReadOnlySpan<byte> data,
        out string attribute,
        out string? error)
    {
        var offset = 0;
        attribute = string.Empty;
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                error = "Domain attribute message is truncated.";
                return false;
            }

            if (fieldNumber == 1 && wireType == 2)
            {
                if (!TryReadString(data, ref offset, out attribute))
                {
                    error = "Domain attribute key is invalid.";
                    return false;
                }

                attribute = attribute.Trim().ToLowerInvariant();
                continue;
            }

            if (!TrySkipFieldValue(data, ref offset, wireType))
            {
                error = "Domain attribute message contains an unsupported field.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool TryParseCidr(
        ReadOnlySpan<byte> data,
        out ParsedGeoCidr cidr,
        out string? error)
    {
        var offset = 0;
        byte[]? addressBytes = null;
        var prefixLength = 0;
        while (offset < data.Length)
        {
            if (!TryReadFieldHeader(data, ref offset, out var fieldNumber, out var wireType))
            {
                cidr = default!;
                error = "CIDR message is truncated.";
                return false;
            }

            switch (fieldNumber, wireType)
            {
                case (1, 2):
                    if (!TryReadLengthDelimited(data, ref offset, out var payload))
                    {
                        cidr = default!;
                        error = "CIDR address is invalid.";
                        return false;
                    }

                    addressBytes = payload.ToArray();
                    break;
                case (2, 0):
                    if (!TryReadVarint(data, ref offset, out var rawPrefix))
                    {
                        cidr = default!;
                        error = "CIDR prefix is invalid.";
                        return false;
                    }

                    prefixLength = (int)rawPrefix;
                    break;
                default:
                    if (!TrySkipFieldValue(data, ref offset, wireType))
                    {
                        cidr = default!;
                        error = "CIDR message contains an unsupported field.";
                        return false;
                    }

                    break;
            }
        }

        if (addressBytes is null)
        {
            cidr = default!;
            error = "CIDR address bytes are missing.";
            return false;
        }

        try
        {
            cidr = new ParsedGeoCidr(new IPAddress(addressBytes).ToString(), prefixLength);
            error = null;
            return true;
        }
        catch (ArgumentException)
        {
            cidr = default!;
            error = "CIDR address bytes are invalid.";
            return false;
        }
    }

    private static bool TryReadFieldHeader(
        ReadOnlySpan<byte> data,
        ref int offset,
        out int fieldNumber,
        out int wireType)
    {
        if (!TryReadVarint(data, ref offset, out var header))
        {
            fieldNumber = 0;
            wireType = 0;
            return false;
        }

        fieldNumber = (int)(header >> 3);
        wireType = (int)(header & 0x07);
        return true;
    }

    private static bool TryReadLengthDelimited(
        ReadOnlySpan<byte> data,
        ref int offset,
        out ReadOnlySpan<byte> payload)
    {
        if (!TryReadVarint(data, ref offset, out var lengthValue))
        {
            payload = default;
            return false;
        }

        if (lengthValue > int.MaxValue)
        {
            payload = default;
            return false;
        }

        var length = (int)lengthValue;
        if (length < 0 || offset > data.Length - length)
        {
            payload = default;
            return false;
        }

        payload = data.Slice(offset, length);
        offset += length;
        return true;
    }

    private static bool TryReadString(
        ReadOnlySpan<byte> data,
        ref int offset,
        out string value)
    {
        if (!TryReadLengthDelimited(data, ref offset, out var payload))
        {
            value = string.Empty;
            return false;
        }

        value = Encoding.UTF8.GetString(payload);
        return true;
    }

    private static bool TrySkipFieldValue(ReadOnlySpan<byte> data, ref int offset, int wireType)
    {
        switch (wireType)
        {
            case 0:
                return TryReadVarint(data, ref offset, out _);
            case 1:
                if (offset > data.Length - 8)
                {
                    return false;
                }

                offset += 8;
                return true;
            case 2:
                return TryReadLengthDelimited(data, ref offset, out _);
            case 5:
                if (offset > data.Length - 4)
                {
                    return false;
                }

                offset += 4;
                return true;
            default:
                return false;
        }
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int offset, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (offset < data.Length && shift < 64)
        {
            var current = data[offset++];
            value |= ((ulong)(current & 0x7F)) << shift;
            if ((current & 0x80) == 0)
            {
                return true;
            }

            shift += 7;
        }

        value = 0;
        return false;
    }

    private static bool TryStripPrefix(string value, string prefix, out string remainder)
    {
        if (value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            remainder = value[prefix.Length..].Trim();
            return true;
        }

        remainder = string.Empty;
        return false;
    }

    private sealed record ParsedGeoSite(string CountryCode, IReadOnlyList<ParsedGeoDomain> Domains);

    private sealed record ParsedGeoIp(string CountryCode, IReadOnlyList<ParsedGeoCidr> Cidrs);

    private sealed record ParsedGeoDomain(int Type, string Value, IReadOnlySet<string> Attributes);

    private sealed record ParsedGeoCidr(string Address, int PrefixLength);
}

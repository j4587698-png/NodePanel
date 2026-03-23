using System.Formats.Asn1;
using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

public static class TrojanTlsServerNamePolicy
{
    public static bool ShouldReject(
        TrojanTlsServerNamePolicyOptions options,
        X509Certificate2 certificate,
        string? requestedServerName)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(certificate);

        if (!options.RejectUnknownServerName)
        {
            return false;
        }

        var normalizedRequestedServerName = NormalizeServerName(requestedServerName);
        if (string.IsNullOrWhiteSpace(normalizedRequestedServerName))
        {
            return true;
        }

        var allowedServerNames = ResolveAllowedServerNames(options, certificate);
        if (allowedServerNames.Count == 0)
        {
            return true;
        }

        foreach (var allowedServerName in allowedServerNames)
        {
            if (IsMatch(normalizedRequestedServerName, allowedServerName))
            {
                return false;
            }
        }

        return true;
    }

    private static IReadOnlyList<string> ResolveAllowedServerNames(
        TrojanTlsServerNamePolicyOptions options,
        X509Certificate2 certificate)
    {
        var allowed = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var configuredServerName in options.ConfiguredServerNames)
        {
            AddServerName(configuredServerName, allowed, seen);
        }

        foreach (var dnsName in ReadSubjectAlternativeDnsNames(certificate))
        {
            AddServerName(dnsName, allowed, seen);
        }

        AddServerName(certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false), allowed, seen);
        AddServerName(certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false), allowed, seen);

        return allowed;
    }

    private static IEnumerable<string> ReadSubjectAlternativeDnsNames(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (!string.Equals(extension.Oid?.Value, "2.5.29.17", StringComparison.Ordinal))
            {
                continue;
            }

            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();
            while (sequence.HasData)
            {
                var tag = sequence.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
                {
                    yield return sequence.ReadCharacterString(
                        UniversalTagNumber.IA5String,
                        new Asn1Tag(TagClass.ContextSpecific, 2));
                    continue;
                }

                sequence.ReadEncodedValue();
            }
        }
    }

    private static bool IsMatch(string requestedServerName, string allowedServerName)
    {
        if (string.Equals(requestedServerName, allowedServerName, StringComparison.Ordinal))
        {
            return true;
        }

        if (!allowedServerName.StartsWith("*.", StringComparison.Ordinal) ||
            allowedServerName.Length <= 2)
        {
            return false;
        }

        var suffix = allowedServerName[1..];
        if (!requestedServerName.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        var label = requestedServerName[..^suffix.Length];
        return label.Length > 0 && !label.Contains('.', StringComparison.Ordinal);
    }

    private static void AddServerName(
        string? value,
        ICollection<string> destination,
        ISet<string> seen)
    {
        var normalized = NormalizeServerName(value);
        if (string.IsNullOrWhiteSpace(normalized) || !seen.Add(normalized))
        {
            return;
        }

        destination.Add(normalized);
    }

    private static string NormalizeServerName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        if (IPAddress.TryParse(trimmed, out var address))
        {
            return address.ToString().ToLowerInvariant();
        }

        try
        {
            trimmed = new IdnMapping().GetAscii(trimmed);
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }

        return trimmed.ToLowerInvariant();
    }
}

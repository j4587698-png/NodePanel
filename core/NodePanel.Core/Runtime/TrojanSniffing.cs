using System.Buffers.Binary;
using System.Text;
using System.Text.RegularExpressions;

namespace NodePanel.Core.Runtime;

public interface ITrojanSniffingDefinition
{
    bool Enabled { get; }

    IReadOnlyList<string> DestinationOverride { get; }

    IReadOnlyList<string> DomainsExcluded { get; }

    bool MetadataOnly { get; }

    bool RouteOnly { get; }
}

public sealed record TrojanSniffingRuntime : ITrojanSniffingDefinition
{
    public static ITrojanSniffingDefinition Disabled { get; } = new TrojanSniffingRuntime();

    public bool Enabled { get; init; }

    public IReadOnlyList<string> DestinationOverride { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DomainsExcluded { get; init; } = Array.Empty<string>();

    public bool MetadataOnly { get; init; }

    public bool RouteOnly { get; init; }
}

public sealed record TrojanSniffingDecision
{
    public string Protocol { get; init; } = string.Empty;

    public string Domain { get; init; } = string.Empty;

    public bool OverrideMatched { get; init; }

    public bool RouteOnly { get; init; }

    public DispatchDestination? OverrideDestination { get; init; }
}

public static class TrojanSniffingEvaluator
{
    public static TrojanSniffingDecision Evaluate(
        ITrojanSniffingDefinition sniffing,
        ReadOnlySpan<byte> payload,
        DispatchNetwork network,
        DispatchDestination destination)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(destination);

        if (!sniffing.Enabled || payload.Length == 0)
        {
            return new TrojanSniffingDecision();
        }

        var detection = Detect(payload, network);
        if (string.IsNullOrWhiteSpace(detection.Protocol))
        {
            return new TrojanSniffingDecision();
        }

        var normalizedDomain = NormalizeDomain(detection.Domain);
        var overrideMatched = ShouldOverride(sniffing, detection.Protocol, normalizedDomain);
        return new TrojanSniffingDecision
        {
            Protocol = detection.Protocol,
            Domain = normalizedDomain,
            OverrideMatched = overrideMatched,
            RouteOnly = sniffing.RouteOnly && overrideMatched && !string.IsNullOrWhiteSpace(normalizedDomain),
            OverrideDestination = overrideMatched &&
                                  !sniffing.RouteOnly &&
                                  !string.IsNullOrWhiteSpace(normalizedDomain)
                ? destination with { Host = normalizedDomain }
                : null
        };
    }

    private static TrojanSniffingDecision Detect(ReadOnlySpan<byte> payload, DispatchNetwork network)
    {
        if (network == DispatchNetwork.Tcp)
        {
            if (TryDetectHttp(payload, out var httpDomain))
            {
                return new TrojanSniffingDecision
                {
                    Protocol = RoutingProtocols.Http,
                    Domain = httpDomain
                };
            }

            if (TryDetectTls(payload, out var tlsDomain))
            {
                return new TrojanSniffingDecision
                {
                    Protocol = RoutingProtocols.Tls,
                    Domain = tlsDomain
                };
            }

            if (TryDetectBitTorrentTcp(payload))
            {
                return new TrojanSniffingDecision
                {
                    Protocol = RoutingProtocols.BitTorrent
                };
            }
        }
        else if (network == DispatchNetwork.Udp)
        {
            if (TryDetectQuic(payload))
            {
                return new TrojanSniffingDecision
                {
                    Protocol = RoutingProtocols.Quic
                };
            }

            if (TryDetectBitTorrentUtp(payload))
            {
                return new TrojanSniffingDecision
                {
                    Protocol = RoutingProtocols.BitTorrent
                };
            }
        }

        return new TrojanSniffingDecision();
    }

    private static bool ShouldOverride(ITrojanSniffingDefinition sniffing, string protocol, string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        foreach (var candidate in sniffing.DomainsExcluded)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }

            var trimmed = candidate.Trim();
            if (trimmed.StartsWith("regexp:", StringComparison.OrdinalIgnoreCase))
            {
                var pattern = trimmed[7..];
                if (pattern.Length == 0)
                {
                    continue;
                }

                try
                {
                    if (Regex.IsMatch(domain, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    {
                        return false;
                    }
                }
                catch (ArgumentException)
                {
                }

                continue;
            }

            if (string.Equals(domain, NormalizeDomain(trimmed), StringComparison.Ordinal))
            {
                return false;
            }
        }

        foreach (var overrideProtocol in sniffing.DestinationOverride)
        {
            var normalizedOverride = RoutingProtocols.Normalize(overrideProtocol);
            if (string.IsNullOrWhiteSpace(normalizedOverride))
            {
                continue;
            }

            if (protocol.StartsWith(normalizedOverride, StringComparison.Ordinal) ||
                normalizedOverride.StartsWith(protocol, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryDetectHttp(ReadOnlySpan<byte> payload, out string domain)
    {
        domain = string.Empty;
        if (payload.Length == 0)
        {
            return false;
        }

        var text = Encoding.ASCII.GetString(payload);
        var firstLineEnd = text.IndexOf('\n');
        if (firstLineEnd <= 0)
        {
            return false;
        }

        var firstLine = text[..firstLineEnd].TrimEnd('\r');
        if (!IsHttpRequestLine(firstLine))
        {
            return false;
        }

        foreach (var line in text.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            if (!line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            domain = NormalizeDomain(line[5..]);
            return true;
        }

        if (firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length >= 2)
            {
                domain = NormalizeDomain(parts[1]);
            }
        }

        return true;
    }

    private static bool TryDetectTls(ReadOnlySpan<byte> payload, out string domain)
    {
        domain = string.Empty;
        if (payload.Length < 5 || payload[0] != 0x16 || payload[1] != 0x03)
        {
            return false;
        }

        if (payload.Length < 9 || payload[5] != 0x01)
        {
            return true;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        var availableLength = Math.Min(payload.Length, recordLength + 5);
        var position = 9;

        if (availableLength < position + 34)
        {
            return true;
        }

        position += 2;
        position += 32;

        if (!TryAdvanceVariableBlock(payload, availableLength, ref position, 1) ||
            !TryAdvanceVariableBlock(payload, availableLength, ref position, 2) ||
            !TryAdvanceVariableBlock(payload, availableLength, ref position, 1))
        {
            return true;
        }

        if (position + 2 > availableLength)
        {
            return true;
        }

        var extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
        position += 2;
        var extensionsEnd = Math.Min(availableLength, position + extensionsLength);

        while (position + 4 <= extensionsEnd)
        {
            var extensionType = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2));
            var extensionLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position + 2, 2));
            position += 4;

            if (position + extensionLength > extensionsEnd)
            {
                return true;
            }

            if (extensionType == 0x0000 &&
                extensionLength >= 5 &&
                TryExtractTlsServerName(payload.Slice(position, extensionLength), out domain))
            {
                return true;
            }

            position += extensionLength;
        }

        return true;
    }

    private static bool TryDetectQuic(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 6 || (payload[0] & 0x80) == 0)
        {
            return false;
        }

        var version = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(1, 4));
        return version != 0;
    }

    private static bool TryDetectBitTorrentTcp(ReadOnlySpan<byte> payload)
        => payload.Length >= 20 &&
           payload[0] == 19 &&
           payload.Slice(1, 19).SequenceEqual("BitTorrent protocol"u8);

    private static bool TryDetectBitTorrentUtp(ReadOnlySpan<byte> payload)
        => payload.Length >= 20 &&
           (payload[0] >> 4) is >= 1 and <= 4 &&
           BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2)) == 1;

    private static bool IsHttpRequestLine(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("PUT ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("DELETE ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("OPTIONS ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("PATCH ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("TRACE ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("PRI * HTTP/2.0", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryAdvanceVariableBlock(ReadOnlySpan<byte> payload, int availableLength, ref int position, int lengthBytes)
    {
        if (position + lengthBytes > availableLength)
        {
            return false;
        }

        var length = lengthBytes switch
        {
            1 => payload[position],
            2 => BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(position, 2)),
            _ => 0
        };
        position += lengthBytes;

        if (position + length > availableLength)
        {
            return false;
        }

        position += length;
        return true;
    }

    private static bool TryExtractTlsServerName(ReadOnlySpan<byte> extension, out string domain)
    {
        domain = string.Empty;
        if (extension.Length < 5)
        {
            return false;
        }

        var listLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(0, 2));
        var position = 2;
        var listEnd = Math.Min(extension.Length, position + listLength);

        while (position + 3 <= listEnd)
        {
            var nameType = extension[position];
            var nameLength = BinaryPrimitives.ReadUInt16BigEndian(extension.Slice(position + 1, 2));
            position += 3;
            if (position + nameLength > listEnd)
            {
                return false;
            }

            if (nameType == 0)
            {
                domain = NormalizeDomain(Encoding.ASCII.GetString(extension.Slice(position, nameLength)));
                return !string.IsNullOrWhiteSpace(domain);
            }

            position += nameLength;
        }

        return false;
    }

    private static string NormalizeDomain(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var trimmed = value.Trim().TrimEnd('.');
        if (trimmed.StartsWith("[", StringComparison.Ordinal) && trimmed.Contains(']'))
        {
            trimmed = trimmed[1..trimmed.IndexOf(']', StringComparison.Ordinal)];
        }
        else
        {
            var colonIndex = trimmed.LastIndexOf(':');
            if (colonIndex > 0 && trimmed.Count(static c => c == ':') == 1)
            {
                trimmed = trimmed[..colonIndex];
            }
        }

        return trimmed.Trim().ToLowerInvariant();
    }
}

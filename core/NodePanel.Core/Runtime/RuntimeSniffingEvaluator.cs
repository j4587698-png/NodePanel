using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace NodePanel.Core.Runtime;

internal enum SniffContentProbeState
{
    Rejected = 0,
    NoClue = 1,
    NeedMoreData = 2,
    Matched = 3
}

internal readonly record struct FakeDnsMatch(string Domain, bool IsInPool)
{
    public static FakeDnsMatch None { get; } = new(string.Empty, false);
}

public static class RuntimeSniffingEvaluator
{
    private static readonly string[] TcpProbeProtocols =
    [
        RoutingProtocols.Http,
        RoutingProtocols.Tls,
        RoutingProtocols.BitTorrent
    ];

    private static readonly string[] UdpProbeProtocols =
    [
        RoutingProtocols.Quic,
        RoutingProtocols.BitTorrent
    ];

    public static RuntimeSniffingDecision Evaluate(
        IRuntimeSniffingDefinition sniffing,
        ReadOnlySpan<byte> payload,
        DispatchNetwork network,
        DispatchDestination destination,
        IFakeDnsEngine? fakeDnsEngine = null)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(destination);

        if (!sniffing.Enabled)
        {
            return new RuntimeSniffingDecision();
        }

        var fakeDnsMatch = DetectMetadata(destination, fakeDnsEngine);
        var detection = DetectContent(payload, network);
        return Compose(sniffing, destination, fakeDnsMatch, detection);
    }

    internal static FakeDnsMatch DetectMetadata(
        DispatchDestination destination,
        IFakeDnsEngine? fakeDnsEngine)
        => ResolveFakeDnsMatch(destination, fakeDnsEngine);

    internal static RuntimeSniffingDecision DetectContent(
        ReadOnlySpan<byte> payload,
        DispatchNetwork network)
        => payload.Length == 0
            ? new RuntimeSniffingDecision()
            : Detect(payload, network);

    internal static RuntimeSniffingDecision Compose(
        IRuntimeSniffingDefinition sniffing,
        DispatchDestination destination,
        FakeDnsMatch fakeDnsMatch,
        RuntimeSniffingDecision detection)
    {
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(destination);

        if (!sniffing.Enabled)
        {
            return new RuntimeSniffingDecision();
        }

        var hasExactFakeDnsMatch = !string.IsNullOrWhiteSpace(fakeDnsMatch.Domain);
        var detectedProtocol = RoutingProtocols.Normalize(detection.Protocol);
        var detectedDomain = NormalizeDomain(detection.Domain);
        var effectiveDomain = hasExactFakeDnsMatch
            ? fakeDnsMatch.Domain
            : detectedDomain;
        var effectiveProtocol = ResolveEffectiveProtocol(fakeDnsMatch, detectedProtocol);

        if (string.IsNullOrWhiteSpace(effectiveProtocol))
        {
            return new RuntimeSniffingDecision();
        }

        var overrideMatched = ShouldOverride(
            sniffing,
            detectedProtocol,
            effectiveProtocol,
            effectiveDomain,
            fakeDnsMatch.IsInPool,
            hasExactFakeDnsMatch);
        var routeTarget = overrideMatched &&
                          sniffing.RouteOnly &&
                          !fakeDnsMatch.IsInPool &&
                          !string.IsNullOrWhiteSpace(effectiveDomain)
            ? destination with { Host = effectiveDomain }
            : null;
        var overrideDestination = overrideMatched &&
                                  !string.IsNullOrWhiteSpace(effectiveDomain) &&
                                  (!sniffing.RouteOnly || fakeDnsMatch.IsInPool)
            ? destination with { Host = effectiveDomain }
            : null;

        return new RuntimeSniffingDecision
        {
            Protocol = effectiveProtocol,
            Domain = effectiveDomain,
            Content = ComposeContent(
                fakeDnsMatch,
                detection.Content,
                effectiveProtocol),
            OverrideMatched = overrideMatched,
            RouteOnly = routeTarget is not null,
            OverrideDestination = overrideDestination,
            RouteTarget = routeTarget
        };
    }

    internal static SniffContentProbeState ProbeContent(ReadOnlySpan<byte> payload, DispatchNetwork network)
        => network switch
        {
            DispatchNetwork.Tcp => ProbeTcpContent(payload),
            DispatchNetwork.Udp => ProbeUdpContent(payload),
            _ => SniffContentProbeState.Rejected
        };

    internal static IReadOnlyList<string> GetProbeProtocols(DispatchNetwork network)
        => network switch
        {
            DispatchNetwork.Tcp => TcpProbeProtocols,
            DispatchNetwork.Udp => UdpProbeProtocols,
            _ => Array.Empty<string>()
        };

    internal static SniffContentProbeState ProbeProtocol(
        string protocol,
        ReadOnlySpan<byte> payload,
        DispatchNetwork network)
    {
        var normalizedProtocol = RoutingProtocols.Normalize(protocol);
        return network switch
        {
            DispatchNetwork.Tcp => normalizedProtocol switch
            {
                RoutingProtocols.Http => ProbeHttp(payload),
                RoutingProtocols.Tls => ProbeTls(payload),
                RoutingProtocols.BitTorrent => ProbeBitTorrentTcp(payload),
                _ => SniffContentProbeState.Rejected
            },
            DispatchNetwork.Udp => normalizedProtocol switch
            {
                RoutingProtocols.Quic => ProbeQuic(payload),
                RoutingProtocols.BitTorrent => ProbeBitTorrentUtp(payload),
                _ => SniffContentProbeState.Rejected
            },
            _ => SniffContentProbeState.Rejected
        };
    }

    private static RuntimeSniffingDecision Detect(ReadOnlySpan<byte> payload, DispatchNetwork network)
    {
        if (network == DispatchNetwork.Tcp)
        {
            if (TryDetectHttp(payload, out var httpDecision))
            {
                return httpDecision;
            }

            if (TryDetectTls(payload, out var tlsDomain))
            {
                return new RuntimeSniffingDecision
                {
                    Protocol = RoutingProtocols.Tls,
                    Domain = tlsDomain,
                    Content = CreateSniffedContent(RoutingProtocols.Tls)
                };
            }

            if (TryDetectBitTorrentTcp(payload))
            {
                return new RuntimeSniffingDecision
                {
                    Protocol = RoutingProtocols.BitTorrent,
                    Content = CreateSniffedContent(RoutingProtocols.BitTorrent)
                };
            }
        }
        else if (network == DispatchNetwork.Udp)
        {
            if (TryDetectQuic(payload, out var quicDomain))
            {
                return new RuntimeSniffingDecision
                {
                    Protocol = RoutingProtocols.Quic,
                    Domain = quicDomain,
                    Content = CreateSniffedContent(RoutingProtocols.Quic)
                };
            }

            if (TryDetectBitTorrentUtp(payload))
            {
                return new RuntimeSniffingDecision
                {
                    Protocol = RoutingProtocols.BitTorrent,
                    Content = CreateSniffedContent(RoutingProtocols.BitTorrent)
                };
            }
        }

        return new RuntimeSniffingDecision();
    }

    private static SniffContentProbeState ProbeTcpContent(ReadOnlySpan<byte> payload)
    {
        var httpState = ProbeHttp(payload);
        if (httpState == SniffContentProbeState.Matched)
        {
            return httpState;
        }

        var tlsState = ProbeTls(payload);
        if (tlsState == SniffContentProbeState.Matched)
        {
            return tlsState;
        }

        var bitTorrentState = ProbeBitTorrentTcp(payload);
        if (bitTorrentState == SniffContentProbeState.Matched)
        {
            return bitTorrentState;
        }

        if (httpState == SniffContentProbeState.NeedMoreData ||
            tlsState == SniffContentProbeState.NeedMoreData ||
            bitTorrentState == SniffContentProbeState.NeedMoreData)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        if (httpState == SniffContentProbeState.NoClue ||
            tlsState == SniffContentProbeState.NoClue ||
            bitTorrentState == SniffContentProbeState.NoClue)
        {
            return SniffContentProbeState.NoClue;
        }

        return SniffContentProbeState.Rejected;
    }

    private static SniffContentProbeState ProbeUdpContent(ReadOnlySpan<byte> payload)
    {
        var quicState = ProbeQuic(payload);
        if (quicState == SniffContentProbeState.Matched)
        {
            return quicState;
        }

        var bitTorrentState = ProbeBitTorrentUtp(payload);
        if (bitTorrentState == SniffContentProbeState.Matched)
        {
            return bitTorrentState;
        }

        if (quicState == SniffContentProbeState.NeedMoreData ||
            bitTorrentState == SniffContentProbeState.NeedMoreData)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        if (quicState == SniffContentProbeState.NoClue ||
            bitTorrentState == SniffContentProbeState.NoClue)
        {
            return SniffContentProbeState.NoClue;
        }

        return SniffContentProbeState.Rejected;
    }

    private static DispatchContent ComposeContent(
        FakeDnsMatch fakeDnsMatch,
        DispatchContent detectionContent,
        string effectiveProtocol)
    {
        if (string.IsNullOrWhiteSpace(fakeDnsMatch.Domain) &&
            !fakeDnsMatch.IsInPool)
        {
            return detectionContent;
        }

        if (detectionContent.Attributes.Count == 0 &&
            !detectionContent.SkipDnsResolve)
        {
            return CreateSniffedContent(effectiveProtocol);
        }

        return CreateSniffedContent(
            effectiveProtocol,
            detectionContent.Attributes,
            detectionContent.SkipDnsResolve);
    }

    private static DispatchContent CreateSniffedContent(
        string protocol,
        IReadOnlyDictionary<string, string>? attributes = null,
        bool skipDnsResolve = false)
        => new()
        {
            Protocol = RoutingProtocols.Normalize(protocol),
            Attributes = attributes ?? new Dictionary<string, string>(StringComparer.Ordinal),
            SkipDnsResolve = skipDnsResolve
        };

    private static bool ShouldOverride(
        IRuntimeSniffingDefinition sniffing,
        string detectedProtocol,
        string effectiveProtocol,
        string domain,
        bool isFakeIpInPool,
        bool hasExactFakeDnsMatch)
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

            if (!string.IsNullOrWhiteSpace(effectiveProtocol) &&
                (effectiveProtocol.StartsWith(normalizedOverride, StringComparison.Ordinal) ||
                 normalizedOverride.StartsWith(effectiveProtocol, StringComparison.Ordinal)))
            {
                return true;
            }

            if (!hasExactFakeDnsMatch &&
                !string.IsNullOrWhiteSpace(detectedProtocol) &&
                (detectedProtocol.StartsWith(normalizedOverride, StringComparison.Ordinal) ||
                 normalizedOverride.StartsWith(detectedProtocol, StringComparison.Ordinal)))
            {
                return true;
            }

            if (isFakeIpInPool &&
                string.Equals(normalizedOverride, RoutingProtocols.FakeDns, StringComparison.Ordinal) &&
                !string.Equals(detectedProtocol, RoutingProtocols.BitTorrent, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static string ResolveEffectiveProtocol(FakeDnsMatch fakeDnsMatch, string detectedProtocol)
    {
        if (!string.IsNullOrWhiteSpace(fakeDnsMatch.Domain))
        {
            return RoutingProtocols.FakeDns;
        }

        if (fakeDnsMatch.IsInPool &&
            !string.IsNullOrWhiteSpace(detectedProtocol))
        {
            return RoutingProtocols.FakeDnsThenOthers;
        }

        return detectedProtocol;
    }

    private static FakeDnsMatch ResolveFakeDnsMatch(
        DispatchDestination destination,
        IFakeDnsEngine? fakeDnsEngine)
    {
        if (fakeDnsEngine is null ||
            string.IsNullOrWhiteSpace(destination.Host))
        {
            return FakeDnsMatch.None;
        }

        var host = destination.Host.Trim();
        if (host.Length > 1 &&
            host[0] == '[' &&
            host[^1] == ']')
        {
            host = host[1..^1];
        }

        if (!IPAddress.TryParse(host, out var parsedAddress) ||
            parsedAddress is null)
        {
            return FakeDnsMatch.None;
        }

        var address = parsedAddress.IsIPv4MappedToIPv6
            ? parsedAddress.MapToIPv4()
            : parsedAddress;
        var domain = NormalizeDomain(fakeDnsEngine.GetDomainFromFakeDns(address) ?? string.Empty);
        var isInPool = fakeDnsEngine.IsIPInPool(address) || !string.IsNullOrWhiteSpace(domain);
        return new FakeDnsMatch(domain, isInPool);
    }

    private static readonly string[] HttpMethodPrefixes =
    [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "PATCH",
        "TRACE",
        "CONNECT",
        "PRI * HTTP/2.0"
    ];

    private static SniffContentProbeState ProbeHttp(ReadOnlySpan<byte> payload)
    {
        if (payload.Length == 0)
        {
            return SniffContentProbeState.NoClue;
        }

        var prefixState = ProbeHttpMethodPrefix(payload);
        if (prefixState != SniffContentProbeState.Matched)
        {
            return prefixState;
        }

        return TryDetectHttp(payload, out var decision) &&
               !string.IsNullOrWhiteSpace(decision.Domain)
            ? SniffContentProbeState.Matched
            : SniffContentProbeState.NoClue;
    }

    private static SniffContentProbeState ProbeHttpMethodPrefix(ReadOnlySpan<byte> payload)
    {
        var text = Encoding.ASCII.GetString(payload);
        foreach (var candidate in HttpMethodPrefixes)
        {
            if (text.StartsWith(candidate, StringComparison.OrdinalIgnoreCase))
            {
                return SniffContentProbeState.Matched;
            }

            if (candidate.StartsWith(text, StringComparison.OrdinalIgnoreCase))
            {
                return SniffContentProbeState.NoClue;
            }
        }

        return SniffContentProbeState.Rejected;
    }

    private static bool TryDetectHttp(ReadOnlySpan<byte> payload, out RuntimeSniffingDecision decision)
    {
        decision = new RuntimeSniffingDecision();
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

        var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
        var requestLineParts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (requestLineParts.Length == 3)
        {
            attributes[":method"] = requestLineParts[0];
            attributes[":path"] = requestLineParts[1];
        }

        var domain = string.Empty;
        foreach (var line in text.Split(["\r\n", "\n"], StringSplitOptions.None).Skip(1))
        {
            if (line.Length == 0)
            {
                break;
            }

            if (!line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                var separator = line.IndexOf(':');
                if (separator <= 0)
                {
                    continue;
                }

                var key = line[..separator].Trim().ToLowerInvariant();
                if (key.Length == 0)
                {
                    continue;
                }

                attributes[key] = line[(separator + 1)..].Trim();
                continue;
            }

            var hostValue = line[5..].Trim();
            attributes["host"] = hostValue;
            domain = NormalizeDomain(hostValue);
        }

        if (firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length >= 2)
            {
                domain = NormalizeDomain(parts[1]);
            }
        }

        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        decision = new RuntimeSniffingDecision
        {
            Protocol = RoutingProtocols.Http,
            Domain = domain,
            Content = CreateSniffedContent(RoutingProtocols.Http, attributes)
        };
        return true;
    }

    private static SniffContentProbeState ProbeTls(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 5)
        {
            return SniffContentProbeState.NoClue;
        }

        if (payload[0] != 0x16 || payload[1] != 0x03)
        {
            return SniffContentProbeState.Rejected;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        if (payload.Length < recordLength + 5)
        {
            return SniffContentProbeState.NeedMoreData;
        }

        return TryDetectTls(payload, out var domain) &&
               !string.IsNullOrWhiteSpace(domain)
            ? SniffContentProbeState.Matched
            : SniffContentProbeState.Rejected;
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
            return false;
        }

        var recordLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(3, 2));
        if (payload.Length < recordLength + 5)
        {
            return false;
        }

        if (!RuntimeTlsClientHelloParser.TryParse(payload, out var metadata))
        {
            return false;
        }

        domain = metadata.ServerName;
        return !string.IsNullOrWhiteSpace(domain);
    }

    private static SniffContentProbeState ProbeQuic(ReadOnlySpan<byte> payload)
    {
        return QuicInitialSniffer.Detect(payload, out _);
    }

    private static bool TryDetectQuic(ReadOnlySpan<byte> payload, out string domain)
    {
        var state = QuicInitialSniffer.Detect(payload, out domain);
        return state == SniffContentProbeState.Matched;
    }

    private static SniffContentProbeState ProbeBitTorrentTcp(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 20)
        {
            return SniffContentProbeState.NoClue;
        }

        return TryDetectBitTorrentTcp(payload)
            ? SniffContentProbeState.Matched
            : SniffContentProbeState.Rejected;
    }

    private static bool TryDetectBitTorrentTcp(ReadOnlySpan<byte> payload)
        => payload.Length >= 20 &&
           payload[0] == 19 &&
           payload.Slice(1, 19).SequenceEqual("BitTorrent protocol"u8);

    private static SniffContentProbeState ProbeBitTorrentUtp(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 20)
        {
            return SniffContentProbeState.NoClue;
        }

        return TryDetectBitTorrentUtp(payload)
            ? SniffContentProbeState.Matched
            : SniffContentProbeState.Rejected;
    }

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

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace NodePanel.Core.Runtime;

internal static partial class HttpHeaderTemplateRenderer
{
    [GeneratedRegex(@"\{\{\s*([^{}]+?)\s*\}\}", RegexOptions.CultureInvariant)]
    private static partial Regex PlaceholderRegex();

    public static string Render(
        string template,
        DispatchContext context,
        DispatchDestination destination)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(destination);

        if (!template.Contains("{{", StringComparison.Ordinal) &&
            !template.Contains("}}", StringComparison.Ordinal))
        {
            return template;
        }

        var matchCount = 0;
        var rendered = PlaceholderRegex().Replace(
            template,
            match =>
            {
                matchCount++;
                return ResolveExpression(match.Groups[1].Value, context, destination);
            });

        if (matchCount == 0 ||
            rendered.Contains("{{", StringComparison.Ordinal) ||
            rendered.Contains("}}", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"HTTP outbound header template is invalid or unsupported: {template}.");
        }

        return rendered;
    }

    private static string ResolveExpression(
        string expression,
        DispatchContext context,
        DispatchDestination destination)
    {
        var trimmed = expression.Trim();
        if (!trimmed.StartsWith(".", StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unsupported HTTP outbound header template expression: {expression}.");
        }

        var segments = trimmed[1..]
            .Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length == 0)
        {
            throw new InvalidOperationException($"Unsupported HTTP outbound header template expression: {expression}.");
        }

        return segments[0] switch
        {
            "Source" => ResolveDestinationValue(
                TryBuildSource(context, out var source)
                    ? source
                    : throw new InvalidOperationException(
                        $"HTTP outbound header template requires a source endpoint, but none was available: {expression}."),
                segments,
                expression),
            "Target" => ResolveDestinationValue(
                BuildTarget(destination),
                segments,
                expression),
            _ => throw new InvalidOperationException(
                $"Unsupported HTTP outbound header template expression: {expression}.")
        };
    }

    private static string ResolveDestinationValue(
        HeaderTemplateDestination destination,
        IReadOnlyList<string> segments,
        string expression)
    {
        if (segments.Count == 1)
        {
            return destination.StringValue;
        }

        return segments[1] switch
        {
            "String" when segments.Count == 2 => destination.StringValue,
            "NetAddr" when segments.Count == 2 => destination.NetAddr,
            "Address" => ResolveLeafValue(destination.Address, segments, expression, segmentIndex: 2),
            "Port" => ResolveLeafValue(destination.Port, segments, expression, segmentIndex: 2),
            "Network" => ResolveNetworkValue(destination.Network, segments, expression, segmentIndex: 2),
            _ => throw new InvalidOperationException(
                $"Unsupported HTTP outbound header template expression: {expression}.")
        };
    }

    private static string ResolveLeafValue(
        string value,
        IReadOnlyList<string> segments,
        string expression,
        int segmentIndex)
    {
        if (segments.Count == segmentIndex)
        {
            return value;
        }

        if (segments.Count == segmentIndex + 1 &&
            string.Equals(segments[segmentIndex], "String", StringComparison.Ordinal))
        {
            return value;
        }

        throw new InvalidOperationException($"Unsupported HTTP outbound header template expression: {expression}.");
    }

    private static string ResolveNetworkValue(
        string value,
        IReadOnlyList<string> segments,
        string expression,
        int segmentIndex)
    {
        if (segments.Count == segmentIndex)
        {
            return value;
        }

        if (segments.Count == segmentIndex + 1 &&
            (string.Equals(segments[segmentIndex], "String", StringComparison.Ordinal) ||
             string.Equals(segments[segmentIndex], "SystemString", StringComparison.Ordinal)))
        {
            return value;
        }

        throw new InvalidOperationException($"Unsupported HTTP outbound header template expression: {expression}.");
    }

    private static bool TryBuildSource(
        DispatchContext context,
        out HeaderTemplateDestination source)
    {
        source = default;
        if (context.SourceEndPoint is not IPEndPoint ipEndPoint)
        {
            return false;
        }

        var address = ipEndPoint.Address;
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        source = new HeaderTemplateDestination(
            Host: address.ToString(),
            PortNumber: ipEndPoint.Port,
            Network: NormalizeNetwork(context.InboundSourceNetwork, fallback: RoutingNetworks.Tcp));
        return true;
    }

    private static HeaderTemplateDestination BuildTarget(DispatchDestination destination)
        => new(
            Host: destination.Host,
            PortNumber: destination.Port,
            Network: destination.Network switch
            {
                DispatchNetwork.Tcp => RoutingNetworks.Tcp,
                DispatchNetwork.Udp => RoutingNetworks.Udp,
                _ => destination.Network.ToString().ToLowerInvariant()
            });

    private static string NormalizeNetwork(string value, string fallback)
        => string.IsNullOrWhiteSpace(value)
            ? fallback
            : value.Trim().ToLowerInvariant();

    private static string FormatAddress(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return string.Empty;
        }

        var trimmed = host.Trim();
        if (trimmed.StartsWith("[", StringComparison.Ordinal) &&
            trimmed.EndsWith("]", StringComparison.Ordinal))
        {
            return trimmed;
        }

        return trimmed.Contains(':', StringComparison.Ordinal)
            ? $"[{trimmed}]"
            : trimmed;
    }

    private readonly record struct HeaderTemplateDestination(
        string Host,
        int PortNumber,
        string Network)
    {
        public string Address => FormatAddress(Host);

        public string Port => PortNumber.ToString(CultureInfo.InvariantCulture);

        public string NetAddr => HttpOutboundHandler.FormatAuthority(Host, PortNumber);

        public string StringValue => $"{Network}:{NetAddr}";
    }
}

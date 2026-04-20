using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Runtime;

public sealed class DokodemoInboundRuntimeCompiler : IInboundProtocolRuntimeCompiler
{
    public string Protocol => InboundProtocols.DokodemoDoor;

    public NodeServiceConfig Normalize(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return config with
        {
            Inbounds = config.Inbounds
                .Select(NormalizeInbound)
                .ToArray()
        };
    }

    public bool TryCompile(
        NodeServiceConfig config,
        out InboundProtocolRuntimeCompilation compilation,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (!DokodemoInboundRuntimePlanner.TryBuild(
                config.Inbounds.Cast<IDokodemoInboundDefinition>().ToArray(),
                out var plan,
                out error))
        {
            compilation = new InboundProtocolRuntimeCompilation
            {
                Plan = DokodemoInboundRuntimePlan.Empty
            };
            return false;
        }

        compilation = new InboundProtocolRuntimeCompilation
        {
            Plan = plan
        };
        error = null;
        return true;
    }

    private static InboundConfig NormalizeInbound(InboundConfig inbound)
    {
        var protocol = InboundProtocols.Normalize(inbound.Protocol);
        if (!string.Equals(protocol, InboundProtocols.DokodemoDoor, StringComparison.Ordinal))
        {
            return inbound;
        }

        return inbound with
        {
            Tag = inbound.Tag.Trim(),
            Protocol = protocol,
            ListenAddress = NormalizeListenAddress(inbound.ListenAddress),
            Port = NormalizeListenerPort(inbound.Port),
            DestinationHost = inbound.DestinationHost.Trim(),
            DestinationPort = NormalizeDestinationPort(inbound.DestinationPort),
            PortMap = NormalizePortMap(inbound.PortMap),
            UserLevel = NormalizeNonNegative(inbound.UserLevel),
            Mark = NormalizeNonNegative(inbound.Mark),
            Networks = NormalizeNetworks(inbound.Networks),
            Sniffing = NormalizeSniffing(inbound.Sniffing)
        };
    }

    private static InboundSniffingConfig NormalizeSniffing(InboundSniffingConfig sniffing)
        => sniffing with
        {
            DestinationOverride = NormalizeStringList(sniffing.DestinationOverride)
                .Select(RoutingProtocols.Normalize)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            DomainsExcluded = NormalizeStringList(sniffing.DomainsExcluded)
                .Select(static value => value.ToLowerInvariant())
                .ToArray()
        };

    private static IReadOnlyDictionary<string, string> NormalizePortMap(IReadOnlyDictionary<string, string> portMap)
    {
        var normalized = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (sourcePort, destination) in portMap)
        {
            if (string.IsNullOrWhiteSpace(sourcePort))
            {
                continue;
            }

            normalized[sourcePort.Trim()] = destination?.Trim() ?? string.Empty;
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeNetworks(IReadOnlyList<string> values)
    {
        var normalized = NormalizeStringList(values)
            .Select(RoutingNetworks.Normalize)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .ToArray();

        return normalized.Length == 0 ? [RoutingNetworks.Tcp] : normalized;
    }

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string> values)
        => values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static int NormalizeListenerPort(int value)
        => value is >= 0 and <= 65535 ? value : 0;

    private static int NormalizeDestinationPort(int value)
        => value is > 0 and <= 65535 ? value : 0;

    private static int NormalizeNonNegative(int value)
        => Math.Max(0, value);
}

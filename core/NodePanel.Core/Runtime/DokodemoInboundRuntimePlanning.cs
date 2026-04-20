using System.Net;

namespace NodePanel.Core.Runtime;

public interface IDokodemoInboundDefinition
{
    string Tag { get; }

    bool Enabled { get; }

    string Protocol { get; }

    string ListenAddress { get; }

    int Port { get; }

    string DestinationHost { get; }

    int DestinationPort { get; }

    IReadOnlyDictionary<string, string> PortMap { get; }

    int UserLevel { get; }

    int Mark { get; }

    IReadOnlyList<string> Networks { get; }

    bool FollowRedirect { get; }

    IRuntimeSniffingDefinition Sniffing { get; }
}

public sealed record DokodemoInboundRuntime
{
    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public string DestinationHost { get; init; } = string.Empty;

    public int DestinationPort { get; init; }

    public IReadOnlyDictionary<string, string> PortMap { get; init; }
        = new Dictionary<string, string>(StringComparer.Ordinal);

    public int UserLevel { get; init; }

    public int Mark { get; init; }

    public IReadOnlyList<string> Networks { get; init; } = [RoutingNetworks.Tcp];

    public bool FollowRedirect { get; init; }

    public RuntimeSniffingOptions Sniffing { get; init; } = new();

    public bool HasTcp => Networks.Contains(RoutingNetworks.Tcp, StringComparer.OrdinalIgnoreCase);

    public bool HasUdp => Networks.Contains(RoutingNetworks.Udp, StringComparer.OrdinalIgnoreCase);
}

public sealed record DokodemoInboundRuntimePlan : IInboundProtocolRuntimePlan
{
    public static DokodemoInboundRuntimePlan Empty { get; } = new();

    public string Protocol => InboundProtocols.DokodemoDoor;

    public IReadOnlyList<DokodemoInboundRuntime> Inbounds { get; init; } = Array.Empty<DokodemoInboundRuntime>();

    public bool RequiresCertificate => false;

    public bool RequiresReality => false;
}

public static class DokodemoInboundRuntimePlanner
{
    public static bool TryBuild(
        IReadOnlyList<IDokodemoInboundDefinition> inbounds,
        out DokodemoInboundRuntimePlan plan,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(inbounds);

        var compiled = new List<DokodemoInboundRuntime>(inbounds.Count);
        var bindingInputs = new List<BindingValidationInput>(inbounds.Count);
        var seenTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < inbounds.Count; index++)
        {
            var inbound = inbounds[index];
            if (inbound is null ||
                !inbound.Enabled ||
                !string.Equals(InboundProtocols.Normalize(inbound.Protocol), InboundProtocols.DokodemoDoor, StringComparison.Ordinal))
            {
                continue;
            }

            var tag = NormalizeTag(inbound.Tag, index);
            if (!seenTags.Add(tag))
            {
                plan = DokodemoInboundRuntimePlan.Empty;
                error = $"Duplicate dokodemo-door inbound tag: {tag}.";
                return false;
            }

            var listenAddress = NormalizeListenAddress(inbound.ListenAddress);
            var port = inbound.Port;
            if (!IsValidListenerBinding(listenAddress, port))
            {
                plan = DokodemoInboundRuntimePlan.Empty;
                error = $"Dokodemo-door inbound listener is invalid: {listenAddress}:{port}.";
                return false;
            }

            if (!TryNormalizeNetworks(inbound.Networks ?? Array.Empty<string>(), out var networks, out error))
            {
                plan = DokodemoInboundRuntimePlan.Empty;
                return false;
            }

            if (!TryNormalizePortMap(
                    inbound.PortMap ?? new Dictionary<string, string>(StringComparer.Ordinal),
                    out var portMap,
                    out error))
            {
                plan = DokodemoInboundRuntimePlan.Empty;
                return false;
            }

            var runtime = new DokodemoInboundRuntime
            {
                Tag = tag,
                Binding = new ListenerBinding(listenAddress, port),
                DestinationHost = NormalizeDestinationHost(inbound.DestinationHost),
                DestinationPort = NormalizeDestinationPort(inbound.DestinationPort),
                Networks = networks,
                FollowRedirect = inbound.FollowRedirect,
                PortMap = portMap,
                UserLevel = NormalizeUserLevel(inbound.UserLevel),
                Mark = NormalizeMark(inbound.Mark),
                Sniffing = NormalizeSniffing(inbound.Sniffing)
            };

            compiled.Add(runtime);
            bindingInputs.Add(new BindingValidationInput(runtime.Binding, runtime.Networks));
        }

        if (!ValidateBindingConflicts(bindingInputs, out error))
        {
            plan = DokodemoInboundRuntimePlan.Empty;
            return false;
        }

        plan = new DokodemoInboundRuntimePlan
        {
            Inbounds = compiled.ToArray()
        };
        error = null;
        return true;
    }

    private static bool TryNormalizeNetworks(
        IReadOnlyList<string> networks,
        out IReadOnlyList<string> normalizedNetworks,
        out string? error)
    {
        var normalized = networks
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(RoutingNetworks.Normalize)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (normalized.Length == 0)
        {
            normalizedNetworks = Array.Empty<string>();
            error = "Dokodemo-door inbound must declare at least one network.";
            return false;
        }

        foreach (var network in normalized)
        {
            if (string.Equals(network, RoutingNetworks.Tcp, StringComparison.Ordinal) ||
                string.Equals(network, RoutingNetworks.Udp, StringComparison.Ordinal))
            {
                continue;
            }

            normalizedNetworks = Array.Empty<string>();
            error = $"Unsupported dokodemo-door inbound network: {network}.";
            return false;
        }

        normalizedNetworks = normalized;
        error = null;
        return true;
    }

    private static bool TryNormalizePortMap(
        IReadOnlyDictionary<string, string> portMap,
        out IReadOnlyDictionary<string, string> normalizedPortMap,
        out string? error)
    {
        var normalized = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in portMap)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            if (!int.TryParse(key.Trim(), out var port) ||
                port is <= 0 or > 65535)
            {
                normalizedPortMap = new Dictionary<string, string>(StringComparer.Ordinal);
                error = $"Dokodemo-door port-map key '{key}' is invalid.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            normalized[port.ToString()] = value.Trim();
        }

        normalizedPortMap = normalized;
        error = null;
        return true;
    }

    private static bool ValidateBindingConflicts(
        IReadOnlyList<BindingValidationInput> inbounds,
        out string? error)
    {
        for (var i = 0; i < inbounds.Count; i++)
        {
            for (var j = i + 1; j < inbounds.Count; j++)
            {
                var left = inbounds[i];
                var right = inbounds[j];

                if (!string.Equals(left.Binding.ListenAddress, right.Binding.ListenAddress, StringComparison.OrdinalIgnoreCase) ||
                    left.Binding.Port != right.Binding.Port)
                {
                    continue;
                }

                if (!left.Networks.Intersect(right.Networks, StringComparer.OrdinalIgnoreCase).Any())
                {
                    continue;
                }

                error = $"Dokodemo-door inbounds cannot bind the same network on the same listener more than once: {left.Binding.ListenAddress}:{left.Binding.Port}.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static string NormalizeTag(string value, int index)
        => string.IsNullOrWhiteSpace(value)
            ? $"dokodemo-{index + 1}"
            : value.Trim();

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static string NormalizeDestinationHost(string value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static int NormalizeDestinationPort(int value)
        => value is > 0 and <= 65535 ? value : 0;

    private static int NormalizeUserLevel(int value)
        => Math.Max(0, value);

    private static int NormalizeMark(int value)
        => Math.Max(0, value);

    private static bool IsValidListenerBinding(string address, int port)
    {
        if (port == 0)
        {
            return !string.IsNullOrWhiteSpace(address) && !IPAddress.TryParse(address, out _);
        }

        return port is > 0 and <= 65535 && IPAddress.TryParse(address, out _);
    }

    private static RuntimeSniffingOptions NormalizeSniffing(IRuntimeSniffingDefinition sniffing)
    {
        ArgumentNullException.ThrowIfNull(sniffing);

        return new RuntimeSniffingOptions
        {
            Enabled = sniffing.Enabled,
            DestinationOverride = sniffing.DestinationOverride
                .Where(static protocol => !string.IsNullOrWhiteSpace(protocol))
                .Select(RoutingProtocols.Normalize)
                .Distinct(StringComparer.Ordinal)
                .ToArray(),
            DomainsExcluded = sniffing.DomainsExcluded
                .Where(static domain => !string.IsNullOrWhiteSpace(domain))
                .Select(static domain => domain.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            MetadataOnly = sniffing.MetadataOnly,
            RouteOnly = sniffing.RouteOnly
        };
    }

    private sealed record BindingValidationInput(
        ListenerBinding Binding,
        IReadOnlyList<string> Networks);
}

internal static class DokodemoInboundErrorMessages
{
    public const string UdpFollowRedirectOriginalDestinationUnavailable =
        "Dokodemo-door UDP inbound followRedirect could not resolve the original destination.";
}

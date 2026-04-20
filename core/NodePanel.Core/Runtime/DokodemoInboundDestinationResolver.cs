using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

internal static class DokodemoInboundDestinationResolver
{
    public static DispatchDestination Resolve(DokodemoInboundSessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var network = RoutingNetworks.Normalize(options.Network);
        if (!string.Equals(network, RoutingNetworks.Tcp, StringComparison.Ordinal) &&
            !string.Equals(network, RoutingNetworks.Udp, StringComparison.Ordinal))
        {
            throw new NotSupportedException($"Dokodemo-door inbound network '{network}' is not implemented yet.");
        }

        var configuredHost = options.DestinationHost;
        var configuredPort = options.DestinationPort;
        string host;
        int port;

        if (options.FollowRedirect)
        {
            host = configuredHost;
            port = configuredPort;

            if (options.OriginalDestinationEndPoint is IPEndPoint originalDestination)
            {
                host = NormalizeAddress(originalDestination.Address);
                port = originalDestination.Port;
            }
        }
        else
        {
            host = configuredHost;
            port = configuredPort;

            var localEndPoint = options.LocalEndPoint as IPEndPoint;
            if (string.IsNullOrWhiteSpace(host))
            {
                host = ResolveDefaultHost(localEndPoint);
            }

            if (port <= 0)
            {
                port = localEndPoint?.Port ?? 0;
            }

            ApplyPortMapOverride(options.PortMap, localEndPoint, ref host, ref port);
        }

        if (string.IsNullOrWhiteSpace(host) ||
            port is <= 0 or > 65535)
        {
            throw new InvalidOperationException("Dokodemo-door inbound could not resolve a valid target destination.");
        }

        return new DispatchDestination
        {
            Host = host,
            Port = port,
            Network = string.Equals(network, RoutingNetworks.Udp, StringComparison.Ordinal)
                ? DispatchNetwork.Udp
                : DispatchNetwork.Tcp
        };
    }

    private static string ResolveDefaultHost(IPEndPoint? localEndPoint)
    {
        if (localEndPoint is null)
        {
            return "localhost";
        }

        var address = localEndPoint.Address;
        if (address.IsIPv4MappedToIPv6 ||
            address.AddressFamily == AddressFamily.InterNetwork)
        {
            return IPAddress.Loopback.ToString();
        }

        return IPAddress.IPv6Loopback.ToString();
    }

    private static void ApplyPortMapOverride(
        IReadOnlyDictionary<string, string> portMap,
        IPEndPoint? localEndPoint,
        ref string host,
        ref int port)
    {
        if (localEndPoint is null ||
            !portMap.TryGetValue(localEndPoint.Port.ToString(), out var mappedValue) ||
            !TryParsePortMapOverride(mappedValue, out var mappedHost, out var mappedPort))
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(mappedHost))
        {
            host = mappedHost;
        }

        if (mappedPort is > 0 and <= 65535)
        {
            port = mappedPort.Value;
        }
    }

    private static bool TryParsePortMapOverride(
        string value,
        out string mappedHost,
        out int? mappedPort)
    {
        mappedHost = string.Empty;
        mappedPort = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim();
        if (int.TryParse(normalized, out var port) &&
            port is > 0 and <= 65535)
        {
            mappedPort = port;
            return true;
        }

        if (!Uri.TryCreate($"tcp://{normalized}", UriKind.Absolute, out var uri) ||
            uri.Port is <= 0 or > 65535)
        {
            return false;
        }

        mappedHost = uri.Host;
        mappedPort = uri.Port;
        return true;
    }

    private static string NormalizeAddress(IPAddress address)
        => address.IsIPv4MappedToIPv6
            ? address.MapToIPv4().ToString()
            : address.ToString();
}

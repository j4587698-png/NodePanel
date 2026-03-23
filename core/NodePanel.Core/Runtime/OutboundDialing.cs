using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

public interface IOutboundMultiplexDefinition
{
    bool Enabled { get; }

    int Concurrency { get; }

    int XudpConcurrency { get; }

    string XudpProxyUdp443 { get; }
}

public interface IOutboundSenderDefinition
{
    string Via { get; }

    string ViaCidr { get; }

    string TargetStrategy { get; }

    string ProxyOutboundTag { get; }

    IOutboundMultiplexDefinition GetMultiplexSettings();
}

public static class OutboundTargetStrategies
{
    public const string AsIs = "asis";
    public const string UseIp = "useip";
    public const string UseIpv4 = "useipv4";
    public const string UseIpv6 = "useipv6";
    public const string UseIpv4v6 = "useipv4v6";
    public const string UseIpv6v4 = "useipv6v4";
    public const string ForceIp = "forceip";
    public const string ForceIpv4 = "forceipv4";
    public const string ForceIpv6 = "forceipv6";
    public const string ForceIpv4v6 = "forceipv4v6";
    public const string ForceIpv6v4 = "forceipv6v4";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return AsIs;
        }

        var normalized = value
            .Trim()
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Replace("_", string.Empty, StringComparison.Ordinal)
            .ToLowerInvariant();

        return normalized switch
        {
            "asis" => AsIs,
            "useip" => UseIp,
            "useipv4" => UseIpv4,
            "useip4" => UseIpv4,
            "useipv6" => UseIpv6,
            "useip6" => UseIpv6,
            "useipv4v6" => UseIpv4v6,
            "useip46" => UseIpv4v6,
            "useipv6v4" => UseIpv6v4,
            "useip64" => UseIpv6v4,
            "forceip" => ForceIp,
            "forceipv4" => ForceIpv4,
            "forceip4" => ForceIpv4,
            "forceipv6" => ForceIpv6,
            "forceip6" => ForceIpv6,
            "forceipv4v6" => ForceIpv4v6,
            "forceip46" => ForceIpv4v6,
            "forceipv6v4" => ForceIpv6v4,
            "forceip64" => ForceIpv6v4,
            _ => AsIs
        };
    }

    public static bool HasStrategy(string? value)
        => Normalize(value) != AsIs;

    public static bool ForceIpResolution(string? value)
        => Normalize(value) is ForceIp or ForceIpv4 or ForceIpv6 or ForceIpv4v6 or ForceIpv6v4;

    public static string GetDynamicStrategy(string? value, AddressFamily originalAddressFamily)
        => Normalize(value) switch
        {
            UseIp when originalAddressFamily == AddressFamily.InterNetwork => UseIpv4v6,
            UseIp when originalAddressFamily == AddressFamily.InterNetworkV6 => UseIpv6v4,
            ForceIp when originalAddressFamily == AddressFamily.InterNetwork => ForceIpv4v6,
            ForceIp when originalAddressFamily == AddressFamily.InterNetworkV6 => ForceIpv6v4,
            _ => Normalize(value)
        };

    public static bool IsValid(string? value)
        => string.IsNullOrWhiteSpace(value) || Normalize(value) != AsIs || string.Equals(value.Trim(), AsIs, StringComparison.OrdinalIgnoreCase);
}

public static class OutboundXudpProxyModes
{
    public const string Reject = "reject";
    public const string Allow = "allow";
    public const string Skip = "skip";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Reject;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            Allow => Allow,
            Skip => Skip,
            _ => Reject
        };
    }
}

public sealed record OutboundMultiplexRuntime : IOutboundMultiplexDefinition
{
    public static OutboundMultiplexRuntime Disabled { get; } = new();

    public bool Enabled { get; init; }

    public int Concurrency { get; init; }

    public int XudpConcurrency { get; init; }

    public string XudpProxyUdp443 { get; init; } = OutboundXudpProxyModes.Reject;
}

public sealed record OutboundCommonSettings
{
    public required string Tag { get; init; }

    public required string Protocol { get; init; }

    public string Via { get; init; } = string.Empty;

    public string ViaCidr { get; init; } = string.Empty;

    public string TargetStrategy { get; init; } = OutboundTargetStrategies.AsIs;

    public string ProxyOutboundTag { get; init; } = string.Empty;

    public OutboundMultiplexRuntime MultiplexSettings { get; init; } = OutboundMultiplexRuntime.Disabled;
}

public interface IOutboundCommonSettingsProvider
{
    bool TryResolve(DispatchContext context, out OutboundCommonSettings settings);
}

public static class OutboundTargetStrategyResolver
{
    public static ValueTask<DispatchDestination> ResolveAsync(
        DispatchContext context,
        DispatchDestination destination,
        string? targetStrategy,
        CancellationToken cancellationToken)
        => ResolveAsync(
            context,
            destination,
            targetStrategy,
            SystemDnsResolver.Instance,
            cancellationToken);

    public static async ValueTask<DispatchDestination> ResolveAsync(
        DispatchContext context,
        DispatchDestination destination,
        string? targetStrategy,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        var effectiveStrategy = GetEffectiveStrategy(context, destination, targetStrategy);
        if (!OutboundTargetStrategies.HasStrategy(effectiveStrategy) ||
            IPAddress.TryParse(destination.Host, out _))
        {
            return destination;
        }

        var addresses = await dnsResolver.ResolveAsync(destination.Host, cancellationToken).ConfigureAwait(false);
        var ordered = FilterAddresses(addresses, effectiveStrategy);
        if (ordered.Count == 0)
        {
            if (OutboundTargetStrategies.ForceIpResolution(effectiveStrategy))
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }

            return destination;
        }

        var selected = ordered[RandomNumberGenerator.GetInt32(ordered.Count)];
        return destination with
        {
            Host = selected.ToString()
        };
    }

    private static string GetEffectiveStrategy(
        DispatchContext context,
        DispatchDestination destination,
        string? targetStrategy)
    {
        var normalized = OutboundTargetStrategies.Normalize(targetStrategy);
        if (destination.Network != DispatchNetwork.Udp ||
            !IPAddress.TryParse(context.OriginalDestinationHost, out var originalAddress))
        {
            return normalized;
        }

        return OutboundTargetStrategies.GetDynamicStrategy(normalized, originalAddress.AddressFamily);
    }

    private static IReadOnlyList<IPAddress> FilterAddresses(IReadOnlyList<IPAddress> addresses, string strategy)
    {
        static IEnumerable<IPAddress> Select(IReadOnlyList<IPAddress> values, params AddressFamily[] families)
            => values.Where(address => families.Contains(address.AddressFamily));

        return OutboundTargetStrategies.Normalize(strategy) switch
        {
            OutboundTargetStrategies.UseIp or OutboundTargetStrategies.ForceIp
                => Select(addresses, AddressFamily.InterNetwork, AddressFamily.InterNetworkV6).ToArray(),
            OutboundTargetStrategies.UseIpv4 or OutboundTargetStrategies.ForceIpv4
                => Select(addresses, AddressFamily.InterNetwork).ToArray(),
            OutboundTargetStrategies.UseIpv6 or OutboundTargetStrategies.ForceIpv6
                => Select(addresses, AddressFamily.InterNetworkV6).ToArray(),
            OutboundTargetStrategies.UseIpv4v6 or OutboundTargetStrategies.ForceIpv4v6
                => Select(addresses, AddressFamily.InterNetwork)
                    .Concat(Select(addresses, AddressFamily.InterNetworkV6))
                    .ToArray(),
            OutboundTargetStrategies.UseIpv6v4 or OutboundTargetStrategies.ForceIpv6v4
                => Select(addresses, AddressFamily.InterNetworkV6)
                    .Concat(Select(addresses, AddressFamily.InterNetwork))
                    .ToArray(),
            _ => Array.Empty<IPAddress>()
        };
    }
}

public static class OutboundSocketDialer
{
    public static Task<IReadOnlyList<IPEndPoint>> ResolveTcpEndPointsAsync(
        string host,
        int port,
        AddressFamily addressFamily,
        CancellationToken cancellationToken)
        => ResolveTcpEndPointsAsync(
            host,
            port,
            addressFamily,
            SystemDnsResolver.Instance,
            cancellationToken);

    public static async Task<IReadOnlyList<IPEndPoint>> ResolveTcpEndPointsAsync(
        string host,
        int port,
        AddressFamily addressFamily,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dnsResolver);

        if (IPAddress.TryParse(host, out var ipAddress))
        {
            if (addressFamily != AddressFamily.Unspecified && ipAddress.AddressFamily != addressFamily)
            {
                throw new InvalidDataException($"Destination address family does not match transport: {host}.");
            }

            return
            [
                new IPEndPoint(ipAddress, port)
            ];
        }

        var addresses = await dnsResolver.ResolveAsync(host, cancellationToken).ConfigureAwait(false);
        var selectedAddresses = addresses
            .Where(address =>
                (addressFamily == AddressFamily.Unspecified || address.AddressFamily == addressFamily) &&
                address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .OrderBy(static address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        if (selectedAddresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }

        return selectedAddresses
            .Select(address => new IPEndPoint(address, port))
            .ToArray();
    }

    public static async Task<Stream> OpenTcpStreamAsync(
        DispatchContext context,
        string? via,
        string? viaCidr,
        IReadOnlyList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;

        foreach (var endPoint in endPoints)
        {
            var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            try
            {
                BindSocketIfNeeded(socket, context, via, viaCidr, endPoint.AddressFamily);
                await socket.ConnectAsync(endPoint, cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                socket.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
                socket.Dispose();
            }
        }

        throw lastError ?? new SocketException((int)SocketError.HostNotFound);
    }

    public static Socket CreateUdpSocket(
        DispatchContext context,
        string? via,
        string? viaCidr,
        AddressFamily addressFamily)
    {
        var socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        BindSocketIfNeeded(socket, context, via, viaCidr, addressFamily);
        return socket;
    }

    private static void BindSocketIfNeeded(
        Socket socket,
        DispatchContext context,
        string? via,
        string? viaCidr,
        AddressFamily addressFamily)
    {
        var localAddress = ResolveBindAddress(context, via, viaCidr, addressFamily);
        if (localAddress is null)
        {
            return;
        }

        socket.Bind(new IPEndPoint(localAddress, 0));
    }

    private static IPAddress? ResolveBindAddress(
        DispatchContext context,
        string? via,
        string? viaCidr,
        AddressFamily addressFamily)
    {
        if (string.IsNullOrWhiteSpace(via))
        {
            return null;
        }

        var baseAddress = ResolveBaseAddress(context, via);
        if (baseAddress is null || baseAddress.AddressFamily != addressFamily)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(viaCidr))
        {
            return baseAddress;
        }

        return ApplyCidr(baseAddress, viaCidr);
    }

    private static IPAddress? ResolveBaseAddress(DispatchContext context, string via)
    {
        var normalized = via.Trim();
        if (string.Equals(normalized, "origin", StringComparison.OrdinalIgnoreCase))
        {
            return (context.LocalEndPoint as IPEndPoint)?.Address;
        }

        if (string.Equals(normalized, "srcip", StringComparison.OrdinalIgnoreCase))
        {
            return (context.SourceEndPoint as IPEndPoint)?.Address;
        }

        return IPAddress.TryParse(normalized, out var address) ? address : null;
    }

    private static IPAddress ApplyCidr(IPAddress address, string cidr)
    {
        var normalized = cidr.Trim().TrimStart('/');
        if (!int.TryParse(normalized, out var prefixLength))
        {
            return address;
        }

        var bytes = address.GetAddressBytes();
        var maxBits = bytes.Length * 8;
        if (prefixLength <= 0 || prefixLength >= maxBits)
        {
            return address;
        }

        var randomized = bytes.ToArray();
        RandomNumberGenerator.Fill(randomized);
        var networkBytes = bytes.ToArray();

        for (var bit = prefixLength; bit < maxBits; bit++)
        {
            var byteIndex = bit / 8;
            var bitIndex = 7 - (bit % 8);
            var mask = (byte)(1 << bitIndex);
            networkBytes[byteIndex] = (byte)((networkBytes[byteIndex] & ~mask) | (randomized[byteIndex] & mask));
        }

        return new IPAddress(networkBytes);
    }
}

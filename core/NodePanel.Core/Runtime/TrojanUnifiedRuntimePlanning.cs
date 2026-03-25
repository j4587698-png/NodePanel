using System.Net;
using NodePanel.Core.Cryptography;

namespace NodePanel.Core.Runtime;

public static class InboundProtocols
{
    public const string Trojan = "trojan";
    public const string Vless = "vless";
    public const string Vmess = "vmess";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Trojan
            : value.Trim().ToLowerInvariant();
}

public static class InboundTransports
{
    public const string Tls = "tls";
    public const string Wss = "wss";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Tls
            : value.Trim().ToLowerInvariant();
}

public static class OutboundProtocols
{
    public const string Freedom = "freedom";
    public const string Trojan = "trojan";
    public const string Selector = "selector";
    public const string UrlTest = "urltest";
    public const string Fallback = "fallback";
    public const string LoadBalance = "loadbalance";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Freedom
            : value.Trim().ToLowerInvariant() switch
            {
                Selector => Selector,
                "url-test" => UrlTest,
                UrlTest => UrlTest,
                Fallback => Fallback,
                "load-balance" => LoadBalance,
                LoadBalance => LoadBalance,
                Trojan => Trojan,
                _ => Freedom
            };
}

public static class RoutingNetworks
{
    public const string Tcp = "tcp";
    public const string Udp = "udp";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();
}

public interface ITrojanInboundDefinition
{
    string Tag { get; }

    bool Enabled { get; }

    string Protocol { get; }

    string Transport { get; }

    string ListenAddress { get; }

    int Port { get; }

    int HandshakeTimeoutSeconds { get; }

    bool AcceptProxyProtocol { get; }

    string Host { get; }

    string Path { get; }

    int EarlyDataBytes { get; }

    int HeartbeatPeriodSeconds { get; }

    IReadOnlyList<string> ApplicationProtocols { get; }
}

public interface ITrojanInboundScopeDefinition
{
    IReadOnlyList<ITrojanUserDefinition> GetUsers();

    IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks();

    ITrojanSniffingDefinition GetSniffing();

    bool GetReceiveOriginalDestination();
}

public interface IOutboundDefinition
{
    string Tag { get; }

    bool Enabled { get; }

    string Protocol { get; }
}

public interface IRoutingRuleDefinition
{
    bool Enabled { get; }

    IReadOnlyList<string> InboundTags { get; }

    IReadOnlyList<string> Protocols { get; }

    IReadOnlyList<string> Networks { get; }

    IReadOnlyList<string> UserIds { get; }

    IReadOnlyList<string> Domains { get; }

    IReadOnlyList<string> SourceCidrs { get; }

    IReadOnlyList<string> DestinationPorts { get; }

    string OutboundTag { get; }
}

public sealed record ListenerBinding(string ListenAddress, int Port)
{
    public bool IsUnix => Port == 0;
}

public sealed record TrojanTlsInboundRuntime
{
    public required string Tag { get; init; }

    public required string Transport { get; init; }

    public required ListenerBinding Binding { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public int EarlyDataBytes { get; init; }

    public int HeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public bool ReceiveOriginalDestination { get; init; }

    public TrojanSniffingRuntime Sniffing { get; init; } = new();

    public IReadOnlyDictionary<string, TrojanUser> UsersByHash { get; init; }
        = new Dictionary<string, TrojanUser>(StringComparer.Ordinal);

    public IReadOnlyList<TrojanFallbackRuntime> Fallbacks { get; init; } = Array.Empty<TrojanFallbackRuntime>();
}

public sealed record TrojanFallbackRuntime : ITrojanFallbackDefinition
{
    public string Name { get; init; } = string.Empty;

    public string Alpn { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public string Type { get; init; } = "tcp";

    public string Dest { get; init; } = string.Empty;

    public int ProxyProtocolVersion { get; init; }
}

public sealed record TrojanTlsListenerRuntime
{
    public required ListenerBinding Binding { get; init; }

    public bool AcceptProxyProtocol { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public TrojanTlsInboundRuntime? RawTlsInbound { get; init; }

    public TrojanTlsInboundRuntime? WebSocketInbound { get; init; }

    public bool IsShared => RawTlsInbound is not null && WebSocketInbound is not null;
}

public sealed record TrojanInboundRuntimePlan : IInboundProtocolRuntimePlan
{
    public static TrojanInboundRuntimePlan Empty { get; } = new();

    public string Protocol => InboundProtocols.Trojan;

    public IReadOnlyList<TrojanTlsListenerRuntime> TlsListeners { get; init; } = Array.Empty<TrojanTlsListenerRuntime>();

    public bool RequiresCertificate => TlsListeners.Count > 0;

    public bool HasTcpTls => TlsListeners.Any(static listener => listener.RawTlsInbound is not null);

    public bool HasWss => TlsListeners.Any(static listener => listener.WebSocketInbound is not null);
}

public static class TrojanInboundRuntimePlanner
{
    public static bool TryBuild(
        IReadOnlyList<ITrojanInboundDefinition> inbounds,
        out TrojanInboundRuntimePlan plan,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(inbounds);

        var normalized = Normalize(inbounds, out error);
        if (normalized is null)
        {
            plan = TrojanInboundRuntimePlan.Empty;
            return false;
        }

        if (!ValidateBindingConflicts(normalized, out error))
        {
            plan = TrojanInboundRuntimePlan.Empty;
            return false;
        }

        var listeners = BuildListeners(normalized, out error);
        if (listeners is null)
        {
            plan = TrojanInboundRuntimePlan.Empty;
            return false;
        }

        plan = new TrojanInboundRuntimePlan
        {
            TlsListeners = listeners
        };
        error = null;
        return true;
    }

    public static TrojanTlsInboundRuntime? SelectInbound(
        TrojanTlsListenerRuntime listener,
        ReadOnlySpan<byte> initialPayload)
    {
        ArgumentNullException.ThrowIfNull(listener);

        if (listener.RawTlsInbound is null)
        {
            return listener.WebSocketInbound;
        }

        if (listener.WebSocketInbound is null)
        {
            return listener.RawTlsInbound;
        }

        var requestPath = HttpRequestProbe.ExtractRequestPath(initialPayload);
        return string.Equals(requestPath, listener.WebSocketInbound.Path, StringComparison.Ordinal)
            ? listener.WebSocketInbound
            : listener.RawTlsInbound;
    }

    private static IReadOnlyList<NormalizedInbound>? Normalize(
        IReadOnlyList<ITrojanInboundDefinition> inbounds,
        out string? error)
    {
        var items = new List<NormalizedInbound>(inbounds.Count);

        for (var index = 0; index < inbounds.Count; index++)
        {
            var inbound = inbounds[index];
            if (!inbound.Enabled)
            {
                continue;
            }

            var protocol = InboundProtocols.Normalize(inbound.Protocol);
            if (!string.Equals(protocol, InboundProtocols.Trojan, StringComparison.Ordinal))
            {
                continue;
            }

            var transport = InboundTransports.Normalize(inbound.Transport);
            if (transport is not (InboundTransports.Tls or InboundTransports.Wss))
            {
                error = $"Unsupported trojan inbound transport: {inbound.Transport}.";
                return null;
            }

            var listenAddress = NormalizeListenAddress(inbound.ListenAddress);
            var port = NormalizeListenerPort(
                inbound.Port,
                transport == InboundTransports.Tls ? 443 : 8443);
            if (!IsValidListenerBinding(listenAddress, port))
            {
                error = $"Invalid {transport.ToUpperInvariant()} listen address: {listenAddress}.";
                return null;
            }

            items.Add(new NormalizedInbound
            {
                Tag = NormalizeTag(inbound.Tag, transport, index),
                Transport = transport,
                Binding = new ListenerBinding(listenAddress, port),
                HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 60),
                AcceptProxyProtocol = inbound.AcceptProxyProtocol,
                Host = inbound.Host.Trim(),
                Path = transport == InboundTransports.Wss ? NormalizePath(inbound.Path) : string.Empty,
                EarlyDataBytes = Math.Max(0, inbound.EarlyDataBytes),
                HeartbeatPeriodSeconds = Math.Max(0, inbound.HeartbeatPeriodSeconds),
                ApplicationProtocols = NormalizeInboundApplicationProtocols(transport, inbound.ApplicationProtocols),
                ReceiveOriginalDestination = inbound is ITrojanInboundScopeDefinition scopedReceiver &&
                                             scopedReceiver.GetReceiveOriginalDestination(),
                Sniffing = inbound is ITrojanInboundScopeDefinition scopedSniffing
                    ? NormalizeSniffing(scopedSniffing.GetSniffing())
                    : new TrojanSniffingRuntime(),
                UsersByHash = inbound is ITrojanInboundScopeDefinition scopedInbound
                    ? CompileUsers(scopedInbound.GetUsers())
                    : new Dictionary<string, TrojanUser>(StringComparer.Ordinal),
                Fallbacks = inbound is ITrojanInboundScopeDefinition scopedFallbacks
                    ? NormalizeFallbacks(scopedFallbacks.GetFallbacks())
                    : Array.Empty<TrojanFallbackRuntime>()
            });
        }

        error = null;
        return items;
    }

    private static bool ValidateBindingConflicts(
        IReadOnlyList<NormalizedInbound> inbounds,
        out string? error)
    {
        for (var i = 0; i < inbounds.Count; i++)
        {
            for (var j = i + 1; j < inbounds.Count; j++)
            {
                var left = inbounds[i];
                var right = inbounds[j];

                if (left.Binding.IsUnix && right.Binding.IsUnix)
                {
                    if (string.Equals(left.Binding.ListenAddress, right.Binding.ListenAddress, StringComparison.OrdinalIgnoreCase))
                    {
                        error = "Trojan inbounds cannot bind the same UNIX listener path more than once.";
                        return false;
                    }

                    continue;
                }

                if (left.Binding.IsUnix || right.Binding.IsUnix)
                {
                    continue;
                }

                if (left.Binding.Port != right.Binding.Port)
                {
                    continue;
                }

                if (string.Equals(left.Binding.ListenAddress, right.Binding.ListenAddress, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (IsWildcardAddress(left.Binding.ListenAddress) || IsWildcardAddress(right.Binding.ListenAddress))
                {
                    error = "Trojan inbounds cannot bind the same TCP port when one side uses a wildcard listen address unless both listeners share the exact same address.";
                    return false;
                }
            }
        }

        error = null;
        return true;
    }

    private static IReadOnlyList<TrojanTlsListenerRuntime>? BuildListeners(
        IReadOnlyList<NormalizedInbound> inbounds,
        out string? error)
    {
        var groups = inbounds
            .GroupBy(static inbound => GetBindingKey(inbound.Binding), StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal);

        var listeners = new List<TrojanTlsListenerRuntime>();

        foreach (var group in groups)
        {
            var entries = group.ToArray();
            var binding = entries[0].Binding;

            if (binding.IsUnix && entries.Length > 1)
            {
                error = "Trojan inbounds cannot share the same UNIX listener path.";
                return null;
            }

            if (entries.Select(static item => item.AcceptProxyProtocol).Distinct().Count() > 1)
            {
                error = "Trojan inbounds that share the same listener binding must use the same AcceptProxyProtocol setting.";
                return null;
            }

            var rawTlsInbound = entries.SingleOrDefault(static item => item.Transport == InboundTransports.Tls);
            var webSocketInbound = entries.SingleOrDefault(static item => item.Transport == InboundTransports.Wss);
            if (entries.Count(static item => item.Transport == InboundTransports.Tls) > 1 ||
                entries.Count(static item => item.Transport == InboundTransports.Wss) > 1)
            {
                error = $"Trojan listener {group.Key} defines duplicate transports on the same binding.";
                return null;
            }

            listeners.Add(new TrojanTlsListenerRuntime
            {
                Binding = binding,
                AcceptProxyProtocol = entries[0].AcceptProxyProtocol,
                ApplicationProtocols = BuildListenerApplicationProtocols(entries),
                RawTlsInbound = rawTlsInbound is null ? null : ToRuntime(rawTlsInbound),
                WebSocketInbound = webSocketInbound is null ? null : ToRuntime(webSocketInbound)
            });
        }

        error = null;
        return listeners;
    }

    private static TrojanTlsInboundRuntime ToRuntime(NormalizedInbound inbound)
        => new()
        {
            Tag = inbound.Tag,
            Transport = inbound.Transport,
            Binding = inbound.Binding,
            HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds,
            Host = inbound.Host,
            Path = inbound.Path,
            EarlyDataBytes = inbound.EarlyDataBytes,
            HeartbeatPeriodSeconds = inbound.HeartbeatPeriodSeconds,
            ApplicationProtocols = inbound.ApplicationProtocols,
            ReceiveOriginalDestination = inbound.ReceiveOriginalDestination,
            Sniffing = inbound.Sniffing,
            UsersByHash = inbound.UsersByHash,
            Fallbacks = inbound.Fallbacks
        };

    private static IReadOnlyList<string> BuildListenerApplicationProtocols(IReadOnlyList<NormalizedInbound> inbounds)
    {
        var ordered = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (inbounds.Any(static inbound => inbound.Transport == InboundTransports.Wss))
        {
            AddApplicationProtocol("http/1.1", ordered, seen);
        }

        foreach (var inbound in inbounds)
        {
            if (inbound.Transport != InboundTransports.Tls)
            {
                continue;
            }

            foreach (var applicationProtocol in inbound.ApplicationProtocols)
            {
                AddApplicationProtocol(applicationProtocol, ordered, seen);
            }

            foreach (var fallback in inbound.Fallbacks)
            {
                AddApplicationProtocol(fallback.Alpn, ordered, seen);
            }
        }

        return ordered;
    }

    private static IReadOnlyDictionary<string, TrojanUser> CompileUsers(IReadOnlyList<ITrojanUserDefinition> users)
    {
        if (users.Count == 0)
        {
            return new Dictionary<string, TrojanUser>(StringComparer.Ordinal);
        }

        var byHash = new Dictionary<string, TrojanUser>(users.Count, StringComparer.Ordinal);
        foreach (var user in users)
        {
            if (string.IsNullOrWhiteSpace(user.UserId) || string.IsNullOrWhiteSpace(user.Password))
            {
                continue;
            }

            var passwordHash = TrojanPassword.ComputeHash(user.Password.Trim());
            byHash[passwordHash] = new TrojanUser
            {
                UserId = user.UserId.Trim(),
                PasswordHash = passwordHash,
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            };
        }

        return byHash;
    }

    private static IReadOnlyList<TrojanFallbackRuntime> NormalizeFallbacks(IReadOnlyList<ITrojanFallbackDefinition> fallbacks)
    {
        if (fallbacks.Count == 0)
        {
            return Array.Empty<TrojanFallbackRuntime>();
        }

        return fallbacks
            .Where(static fallback => !string.IsNullOrWhiteSpace(fallback.Dest))
            .Select(static fallback =>
            {
                var normalizedType = TrojanFallbackCompatibility.NormalizeType(fallback.Type, fallback.Dest);
                return new TrojanFallbackRuntime
                {
                    Name = string.IsNullOrWhiteSpace(fallback.Name) ? string.Empty : fallback.Name.Trim().ToLowerInvariant(),
                    Alpn = string.IsNullOrWhiteSpace(fallback.Alpn) ? string.Empty : fallback.Alpn.Trim().ToLowerInvariant(),
                    Path = TrojanFallbackCompatibility.NormalizePath(fallback.Path),
                    Type = normalizedType,
                    Dest = TrojanFallbackCompatibility.NormalizeDestination(normalizedType, fallback.Dest),
                    ProxyProtocolVersion = TrojanFallbackCompatibility.NormalizeProxyProtocolVersion(fallback.ProxyProtocolVersion)
                };
            })
            .ToArray();
    }

    private static TrojanSniffingRuntime NormalizeSniffing(ITrojanSniffingDefinition sniffing)
        => new()
        {
            Enabled = sniffing.Enabled,
            DestinationOverride = sniffing.DestinationOverride
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => RoutingProtocols.Normalize(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            DomainsExcluded = sniffing.DomainsExcluded
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim().ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            MetadataOnly = sniffing.MetadataOnly,
            RouteOnly = sniffing.RouteOnly
        };

    private static string NormalizeTag(string value, string transport, int index)
        => string.IsNullOrWhiteSpace(value)
            ? $"trojan-{transport}-{index + 1}"
            : value.Trim();

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static int NormalizeListenerPort(int value, int fallback)
        => value is >= 0 and <= 65535 ? value : fallback;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/ws";
        }

        var trimmed = value.Trim();
        return trimmed.StartsWith("/", StringComparison.Ordinal) ? trimmed : "/" + trimmed;
    }

    private static IReadOnlyList<string> NormalizeApplicationProtocols(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return Array.Empty<string>();
        }

        var normalized = new List<string>(values.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in values)
        {
            AddApplicationProtocol(value, normalized, seen);
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeInboundApplicationProtocols(
        string transport,
        IReadOnlyList<string> values)
        => transport switch
        {
            InboundTransports.Tls => NormalizeApplicationProtocols(values),
            InboundTransports.Wss => ["http/1.1"],
            _ => Array.Empty<string>()
        };

    private static void AddApplicationProtocol(
        string? value,
        ICollection<string> destination,
        ISet<string> seen)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var normalized = value.Trim();
        if (!seen.Add(normalized))
        {
            return;
        }

        destination.Add(normalized);
    }

    private static bool IsValidListenerBinding(string address, int port)
    {
        if (port == 0)
        {
            return !string.IsNullOrWhiteSpace(address) && !IPAddress.TryParse(address, out _);
        }

        return IPAddress.TryParse(address, out _);
    }

    private static bool IsWildcardAddress(string value)
        => string.Equals(value, "0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(value, "::", StringComparison.OrdinalIgnoreCase);

    private static string GetBindingKey(ListenerBinding binding)
        => binding.IsUnix
            ? "unix:" + binding.ListenAddress
            : binding.ListenAddress + ":" + binding.Port.ToString();

    private sealed record NormalizedInbound
    {
        public string Tag { get; init; } = string.Empty;

        public string Transport { get; init; } = InboundTransports.Tls;

        public required ListenerBinding Binding { get; init; }

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public bool ReceiveOriginalDestination { get; init; }

        public TrojanSniffingRuntime Sniffing { get; init; } = new();

        public IReadOnlyDictionary<string, TrojanUser> UsersByHash { get; init; }
            = new Dictionary<string, TrojanUser>(StringComparer.Ordinal);

        public IReadOnlyList<TrojanFallbackRuntime> Fallbacks { get; init; } = Array.Empty<TrojanFallbackRuntime>();
    }
}

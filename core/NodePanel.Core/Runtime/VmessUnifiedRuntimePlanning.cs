using System.Net;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public interface IVmessUserDefinition : IRuntimeUserDefinition
{
    string Uuid { get; }
}

public interface IVmessInboundDefinition
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

public interface IVmessInboundScopeDefinition
{
    IReadOnlyList<IVmessUserDefinition> GetVmessUsers();

    ITrojanSniffingDefinition GetSniffing();

    bool GetReceiveOriginalDestination();
}

public sealed record VmessUser : IRuntimeUserDefinition
{
    public required string UserId { get; init; }

    public required string Uuid { get; init; }

    public required byte[] CmdKey { get; init; }

    public required long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

public sealed record VmessTlsInboundRuntime
{
    internal VmessInboundRuntimeState RuntimeState { get; init; } = new(Array.Empty<VmessUser>());

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

    public IReadOnlyList<VmessUser> Users { get; init; } = Array.Empty<VmessUser>();

    public ulong BehaviorSeed => RuntimeState.BehaviorSeed;
}

public sealed record VmessTlsListenerRuntime
{
    public required ListenerBinding Binding { get; init; }

    public bool AcceptProxyProtocol { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public VmessTlsInboundRuntime? RawTlsInbound { get; init; }

    public VmessTlsInboundRuntime? WebSocketInbound { get; init; }

    public bool IsShared => RawTlsInbound is not null && WebSocketInbound is not null;
}

public sealed record VmessInboundRuntimePlan : IInboundProtocolRuntimePlan
{
    public static VmessInboundRuntimePlan Empty { get; } = new();

    public string Protocol => InboundProtocols.Vmess;

    public IReadOnlyList<VmessTlsListenerRuntime> TlsListeners { get; init; } = Array.Empty<VmessTlsListenerRuntime>();

    public bool RequiresCertificate => TlsListeners.Count > 0;

    public bool HasTcpTls => TlsListeners.Any(static listener => listener.RawTlsInbound is not null);

    public bool HasWss => TlsListeners.Any(static listener => listener.WebSocketInbound is not null);
}

public static class VmessInboundRuntimePlanner
{
    private static readonly byte[] CmdKeySalt = Encoding.ASCII.GetBytes("c48619fe-8f02-49e0-b9e9-edf763e17e21");

    public static bool TryBuild(
        IReadOnlyList<IVmessInboundDefinition> inbounds,
        out VmessInboundRuntimePlan plan,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(inbounds);

        var normalized = Normalize(inbounds, out error);
        if (normalized is null)
        {
            plan = VmessInboundRuntimePlan.Empty;
            return false;
        }

        if (!ValidateBindingConflicts(normalized, out error))
        {
            plan = VmessInboundRuntimePlan.Empty;
            return false;
        }

        var listeners = BuildListeners(normalized, out error);
        if (listeners is null)
        {
            plan = VmessInboundRuntimePlan.Empty;
            return false;
        }

        plan = new VmessInboundRuntimePlan
        {
            TlsListeners = listeners
        };
        error = null;
        return true;
    }

    public static VmessTlsInboundRuntime? SelectInbound(
        VmessTlsListenerRuntime listener,
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
        IReadOnlyList<IVmessInboundDefinition> inbounds,
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

            if (!string.Equals(InboundProtocols.Normalize(inbound.Protocol), InboundProtocols.Vmess, StringComparison.Ordinal))
            {
                continue;
            }

            var transport = InboundTransports.Normalize(inbound.Transport);
            if (transport is not (InboundTransports.Tls or InboundTransports.Wss))
            {
                error = $"Unsupported VMess inbound transport: {inbound.Transport}.";
                return null;
            }

            var listenAddress = NormalizeListenAddress(inbound.ListenAddress);
            var port = NormalizeListenerPort(inbound.Port, transport == InboundTransports.Tls ? 443 : 8443);
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
                ReceiveOriginalDestination = inbound is IVmessInboundScopeDefinition scopedReceiver &&
                                             scopedReceiver.GetReceiveOriginalDestination(),
                Sniffing = inbound is IVmessInboundScopeDefinition scopedSniffing
                    ? NormalizeSniffing(scopedSniffing.GetSniffing())
                    : new TrojanSniffingRuntime(),
                Users = inbound is IVmessInboundScopeDefinition scopedInbound
                    ? CompileUsers(scopedInbound.GetVmessUsers())
                    : Array.Empty<VmessUser>()
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
                        error = "VMess inbounds cannot bind the same UNIX listener path more than once.";
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
                    error = "VMess inbounds cannot bind the same TCP port when one side uses a wildcard listen address unless both listeners share the exact same address.";
                    return false;
                }
            }
        }

        error = null;
        return true;
    }

    private static IReadOnlyList<VmessTlsListenerRuntime>? BuildListeners(
        IReadOnlyList<NormalizedInbound> inbounds,
        out string? error)
    {
        var groups = inbounds
            .GroupBy(static inbound => GetBindingKey(inbound.Binding), StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal);

        var listeners = new List<VmessTlsListenerRuntime>();

        foreach (var group in groups)
        {
            var entries = group.ToArray();
            var binding = entries[0].Binding;

            if (binding.IsUnix && entries.Length > 1)
            {
                error = "VMess inbounds cannot share the same UNIX listener path.";
                return null;
            }

            if (entries.Select(static item => item.AcceptProxyProtocol).Distinct().Count() > 1)
            {
                error = "VMess inbounds that share the same listener binding must use the same AcceptProxyProtocol setting.";
                return null;
            }

            var rawTlsInbound = entries.SingleOrDefault(static item => item.Transport == InboundTransports.Tls);
            var webSocketInbound = entries.SingleOrDefault(static item => item.Transport == InboundTransports.Wss);
            if (entries.Count(static item => item.Transport == InboundTransports.Tls) > 1 ||
                entries.Count(static item => item.Transport == InboundTransports.Wss) > 1)
            {
                error = $"VMess listener {group.Key} defines duplicate transports on the same binding.";
                return null;
            }

            listeners.Add(new VmessTlsListenerRuntime
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

    private static VmessTlsInboundRuntime ToRuntime(NormalizedInbound inbound)
        => new()
        {
            RuntimeState = new VmessInboundRuntimeState(inbound.Users),
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
            Users = inbound.Users
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
        }

        return ordered;
    }

    private static IReadOnlyList<VmessUser> CompileUsers(IReadOnlyList<IVmessUserDefinition> users)
    {
        if (users.Count == 0)
        {
            return Array.Empty<VmessUser>();
        }

        var compiled = new List<VmessUser>(users.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var user in users)
        {
            if (string.IsNullOrWhiteSpace(user.UserId) ||
                !ProtocolUuid.TryNormalize(user.Uuid, out var normalizedUuid) ||
                !seen.Add(normalizedUuid))
            {
                continue;
            }

            compiled.Add(new VmessUser
            {
                UserId = user.UserId.Trim(),
                Uuid = normalizedUuid,
                CmdKey = CreateCmdKey(normalizedUuid),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            });
        }

        return compiled;
    }

    private static byte[] CreateCmdKey(string normalizedUuid)
    {
        Span<byte> uuidBytes = stackalloc byte[16];
        if (!ProtocolUuid.TryWriteBytes(normalizedUuid, uuidBytes))
        {
            return Array.Empty<byte>();
        }

        var buffer = new byte[uuidBytes.Length + CmdKeySalt.Length];
        uuidBytes.CopyTo(buffer);
        CmdKeySalt.CopyTo(buffer.AsSpan(uuidBytes.Length));
        return MD5.HashData(buffer);
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
            ? $"vmess-{transport}-{index + 1}"
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

        public IReadOnlyList<VmessUser> Users { get; init; } = Array.Empty<VmessUser>();
    }
}

using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class VlessInboundRuntimeCompiler : IInboundProtocolRuntimeCompiler
{
    public string Protocol => InboundProtocols.Vless;

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

        if (!VlessInboundRuntimePlanner.TryBuild(
                config.Inbounds.Cast<IVlessInboundDefinition>().ToArray(),
                out var plan,
                out error))
        {
            compilation = new InboundProtocolRuntimeCompilation
            {
                Plan = VlessInboundRuntimePlan.Empty
            };
            return false;
        }

        compilation = new InboundProtocolRuntimeCompilation
        {
            Plan = plan,
            ActiveUsers = GetActiveUsers(config.Inbounds)
        };
        error = null;
        return true;
    }

    private static InboundConfig NormalizeInbound(InboundConfig inbound)
    {
        var protocol = InboundProtocols.Normalize(inbound.Protocol);
        if (!string.Equals(protocol, InboundProtocols.Vless, StringComparison.Ordinal))
        {
            return inbound;
        }

        var transport = InboundTransports.Normalize(inbound.Transport);
        var users = NormalizeUsers(inbound.Users);

        return inbound with
        {
            Tag = inbound.Tag.Trim(),
            Protocol = protocol,
            Transport = transport,
            ListenAddress = NormalizeListenAddress(inbound.ListenAddress),
            Port = NormalizeListenerPort(inbound.Port, transport == InboundTransports.Tls ? 443 : 8443),
            HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 60),
            Host = inbound.Host.Trim(),
            Path = transport == InboundTransports.Wss ? NormalizePath(inbound.Path) : string.Empty,
            EarlyDataBytes = Math.Max(0, inbound.EarlyDataBytes),
            HeartbeatPeriodSeconds = Math.Max(0, inbound.HeartbeatPeriodSeconds),
            ApplicationProtocols = NormalizeInboundApplicationProtocols(transport, inbound.ApplicationProtocols),
            Sniffing = NormalizeSniffing(inbound.Sniffing),
            Users = users
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

    private static IReadOnlyList<TrojanUserConfig> NormalizeUsers(IReadOnlyList<TrojanUserConfig> users)
        => users
            .Where(static user => !string.IsNullOrWhiteSpace(user.UserId) && TryNormalizeUuid(user.Uuid, out _))
            .Select(static user => user with
            {
                UserId = user.UserId.Trim(),
                Uuid = NormalizeUuid(user.Uuid),
                Password = string.IsNullOrWhiteSpace(user.Password) ? string.Empty : user.Password.Trim(),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            })
            .ToArray();

    private static IReadOnlyList<IRuntimeUserDefinition> GetActiveUsers(IReadOnlyList<InboundConfig> inbounds)
        => inbounds
            .Where(static inbound => inbound.Enabled &&
                                     (NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, InboundTransports.Tls) ||
                                      NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, InboundTransports.Wss)))
            .SelectMany(static inbound => inbound.Users)
            .Where(static user => !string.IsNullOrWhiteSpace(user.UserId) && TryNormalizeUuid(user.Uuid, out _))
            .Cast<IRuntimeUserDefinition>()
            .ToArray();

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

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string> values)
        => values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> NormalizeInboundApplicationProtocols(
        string transport,
        IReadOnlyList<string> values)
        => transport switch
        {
            InboundTransports.Tls => NormalizeStringList(values),
            InboundTransports.Wss => ["http/1.1"],
            _ => Array.Empty<string>()
        };

    private static bool TryNormalizeUuid(string? value, out string normalized)
    {
        if (Guid.TryParse(value?.Trim(), out var uuid))
        {
            normalized = uuid.ToString("D");
            return true;
        }

        normalized = string.Empty;
        return false;
    }

    private static string NormalizeUuid(string? value)
        => TryNormalizeUuid(value, out var normalized) ? normalized : string.Empty;
}

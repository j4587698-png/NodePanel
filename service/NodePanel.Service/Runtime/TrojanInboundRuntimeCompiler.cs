using System.Net;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class TrojanInboundRuntimeCompiler : IInboundProtocolRuntimeCompiler
{
    public string Protocol => InboundProtocols.Trojan;

    public NodeServiceConfig Normalize(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var lifted = NodeServiceConfigInbounds.LiftLegacyTrojanScope(config);
        return lifted with
        {
            Inbounds = lifted.Inbounds
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

        if (!ValidateFallbacks(config.Inbounds, out error))
        {
            compilation = new InboundProtocolRuntimeCompilation
            {
                Plan = TrojanInboundRuntimePlan.Empty
            };
            return false;
        }

        if (!TrojanInboundRuntimePlanner.TryBuild(
                config.Inbounds.Cast<ITrojanInboundDefinition>().ToArray(),
                out var plan,
                out error))
        {
            compilation = new InboundProtocolRuntimeCompilation
            {
                Plan = TrojanInboundRuntimePlan.Empty
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
        if (!string.Equals(protocol, InboundProtocols.Trojan, StringComparison.Ordinal))
        {
            return inbound;
        }

        var transport = InboundTransports.Normalize(inbound.Transport);
        var users = NormalizeUsers(inbound.Users);
        var fallbacks = NormalizeFallbacks(inbound.Fallbacks);

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
            Users = users,
            Fallbacks = fallbacks
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
            .Where(static user => !string.IsNullOrWhiteSpace(user.UserId) && !string.IsNullOrWhiteSpace(user.Password))
            .Select(static user => user with
            {
                UserId = user.UserId.Trim(),
                Password = user.Password.Trim(),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            })
            .ToArray();

    private static IReadOnlyList<TrojanFallbackConfig> NormalizeFallbacks(IReadOnlyList<TrojanFallbackConfig> fallbacks)
        => fallbacks
            .Where(static fallback => !string.IsNullOrWhiteSpace(fallback.Dest))
            .Select(static fallback =>
            {
                var normalizedType = TrojanFallbackCompatibility.NormalizeType(fallback.Type, fallback.Dest);
                return fallback with
                {
                    Name = fallback.Name.Trim().ToLowerInvariant(),
                    Alpn = fallback.Alpn.Trim().ToLowerInvariant(),
                    Path = TrojanFallbackCompatibility.NormalizePath(fallback.Path),
                    Type = normalizedType,
                    Dest = TrojanFallbackCompatibility.NormalizeDestination(normalizedType, fallback.Dest),
                    ProxyProtocolVersion = TrojanFallbackCompatibility.NormalizeProxyProtocolVersion(fallback.ProxyProtocolVersion)
                };
            })
            .ToArray();

    private static IReadOnlyList<IRuntimeUserDefinition> GetActiveUsers(IReadOnlyList<InboundConfig> inbounds)
        => inbounds
            .Where(static inbound => inbound.Enabled && NodeServiceConfigInbounds.IsTrojanTlsOrWss(inbound))
            .SelectMany(static inbound => inbound.Users)
            .Cast<IRuntimeUserDefinition>()
            .ToArray();

    private static bool ValidateFallbacks(IReadOnlyList<InboundConfig> inbounds, out string? error)
    {
        foreach (var fallback in inbounds
                     .Where(NodeServiceConfigInbounds.IsTrojanTlsOrWss)
                     .SelectMany(static inbound => inbound.Fallbacks))
        {
            if (!TrojanFallbackCompatibility.IsSupportedTransportType(fallback.Type))
            {
                error = $"Unsupported trojan fallback transport type: {fallback.Type}.";
                return false;
            }

            if (!TrojanFallbackCompatibility.IsValidDestination(fallback.Type, fallback.Dest))
            {
                error = $"Invalid trojan fallback destination: {fallback.Dest}.";
                return false;
            }

            if (fallback.ProxyProtocolVersion is not (0 or 1 or 2))
            {
                error = $"Unsupported trojan fallback PROXY protocol version: {fallback.ProxyProtocolVersion}.";
                return false;
            }
        }

        error = null;
        return true;
    }

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
}

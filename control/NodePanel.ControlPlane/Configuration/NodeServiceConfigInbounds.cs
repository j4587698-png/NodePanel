using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public static class NodeServiceConfigInbounds
{
    private static readonly string[] CertificateInboundTransports =
    [
        InboundTransports.Tls,
        InboundTransports.Wss
    ];

    public static IReadOnlyList<InboundConfig> GetEffectiveInbounds(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return config.Inbounds;
    }

    public static NodeServiceConfig LiftLegacyTrojanScope(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var migratedInbounds = config.Inbounds
            .Select(inbound =>
            {
                if (!IsTrojanTlsOrWss(inbound))
                {
                    return inbound;
                }

                return inbound with
                {
                    Users = inbound.Users.Count == 0 ? config.Users : inbound.Users,
                    Fallbacks = inbound.Fallbacks.Count == 0 ? config.Fallbacks : inbound.Fallbacks
                };
            })
            .ToArray();

        return config with
        {
            Inbounds = migratedInbounds,
            Users = Array.Empty<TrojanUserConfig>(),
            Fallbacks = Array.Empty<TrojanFallbackConfig>()
        };
    }

    public static IReadOnlyList<InboundConfig> GetTrojanInbounds(NodeServiceConfig config)
        => GetProtocolInbounds(config, InboundProtocols.Trojan)
            .Where(inbound => IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Tls) ||
                              IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Wss))
            .ToArray();

    public static IReadOnlyList<InboundConfig> GetProtocolInbounds(NodeServiceConfig config, string protocol)
    {
        ArgumentNullException.ThrowIfNull(config);

        var normalizedProtocol = InboundProtocols.Normalize(protocol);
        return GetEffectiveInbounds(config)
            .Where(inbound => string.Equals(InboundProtocols.Normalize(inbound.Protocol), normalizedProtocol, StringComparison.Ordinal))
            .ToArray();
    }

    public static InboundConfig GetTrojanTransportInbound(NodeServiceConfig config, string transport)
        => GetProtocolTransportInbound(config, InboundProtocols.Trojan, transport);

    public static InboundConfig GetProtocolTransportInbound(NodeServiceConfig config, string protocol, string transport)
    {
        ArgumentNullException.ThrowIfNull(config);

        var normalizedProtocol = InboundProtocols.Normalize(protocol);
        var normalizedTransport = InboundTransports.Normalize(transport);
        return GetProtocolInbounds(config, normalizedProtocol)
                   .FirstOrDefault(item => IsProtocolTransport(item, normalizedProtocol, normalizedTransport))
               ?? CreateDefaultInbound(normalizedProtocol, normalizedTransport);
    }

    public static bool RequiresCertificate(NodeServiceConfig config)
        => GetEffectiveInbounds(config)
            .Any(inbound => inbound.Enabled && CertificateInboundTransports.Contains(
                InboundTransports.Normalize(inbound.Transport),
                StringComparer.OrdinalIgnoreCase));

    public static IReadOnlyList<InboundConfig> ReplaceTrojanUsers(
        IReadOnlyList<InboundConfig> inbounds,
        IReadOnlyList<TrojanUserConfig> users)
        => ReplaceProtocolUsers(inbounds, users, InboundProtocols.Trojan);

    public static IReadOnlyList<InboundConfig> ReplaceProtocolUsers(
        IReadOnlyList<InboundConfig> inbounds,
        IReadOnlyList<TrojanUserConfig> users,
        string protocol)
    {
        ArgumentNullException.ThrowIfNull(inbounds);
        ArgumentNullException.ThrowIfNull(users);

        var normalizedProtocol = InboundProtocols.Normalize(protocol);
        var projectedUsers = users
            .Where(user => !string.IsNullOrWhiteSpace(user.UserId) && HasUsableCredentials(user, normalizedProtocol))
            .ToArray();

        return inbounds
            .Select(inbound =>
            {
                if (!string.Equals(InboundProtocols.Normalize(inbound.Protocol), normalizedProtocol, StringComparison.Ordinal))
                {
                    return inbound;
                }

                return inbound with
                {
                    Users = MergeUsers(projectedUsers, inbound.Users)
                };
            })
            .ToArray();
    }

    public static InboundConfig CreateDefaultTrojanInbound(string transport)
        => CreateDefaultInbound(InboundProtocols.Trojan, transport);

    public static InboundConfig CreateDefaultInbound(string protocol, string transport)
    {
        var normalizedProtocol = InboundProtocols.Normalize(protocol);
        var normalizedTransport = InboundTransports.Normalize(transport);
        return normalizedTransport switch
        {
            InboundTransports.Wss => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-wss",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Wss,
                ListenAddress = "0.0.0.0",
                Port = 8443,
                HandshakeTimeoutSeconds = 10,
                Path = "/ws"
            },
            _ => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-tcp-tls",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Tls,
                ListenAddress = "0.0.0.0",
                Port = 443,
                HandshakeTimeoutSeconds = 10
            }
        };
    }

    public static bool IsTrojanTlsOrWss(InboundConfig inbound)
    {
        ArgumentNullException.ThrowIfNull(inbound);

        return IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Tls) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Wss);
    }

    public static bool IsProtocolTransport(InboundConfig inbound, string protocol, string transport)
        => string.Equals(InboundProtocols.Normalize(inbound.Protocol), InboundProtocols.Normalize(protocol), StringComparison.Ordinal) &&
           string.Equals(InboundTransports.Normalize(inbound.Transport), InboundTransports.Normalize(transport), StringComparison.Ordinal);

    private static IReadOnlyList<TrojanUserConfig> MergeUsers(
        IReadOnlyList<TrojanUserConfig> primary,
        IReadOnlyList<TrojanUserConfig> secondary)
    {
        var result = new List<TrojanUserConfig>(primary.Count + secondary.Count);
        var seen = new HashSet<string>(StringComparer.Ordinal);

        AppendUsers(primary, result, seen);
        AppendUsers(secondary, result, seen);
        return result;
    }

    private static void AppendUsers(
        IReadOnlyList<TrojanUserConfig> source,
        ICollection<TrojanUserConfig> destination,
        ISet<string> seen)
    {
        foreach (var user in source)
        {
            if (string.IsNullOrWhiteSpace(user.UserId))
            {
                continue;
            }

            var key = user.UserId.Trim();
            if (!seen.Add(key))
            {
                continue;
            }

            destination.Add(user with
            {
                UserId = key,
                Uuid = NormalizeUuid(user.Uuid),
                Password = string.IsNullOrWhiteSpace(user.Password) ? string.Empty : user.Password.Trim(),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            });
        }
    }

    private static bool HasUsableCredentials(TrojanUserConfig user, string protocol)
        => string.Equals(protocol, InboundProtocols.Trojan, StringComparison.Ordinal)
            ? !string.IsNullOrWhiteSpace(user.Password)
            : !string.IsNullOrWhiteSpace(NormalizeUuid(user.Uuid));

    private static string NormalizeUuid(string value)
        => Guid.TryParse(value?.Trim(), out var uuid)
            ? uuid.ToString("D")
            : string.Empty;
}

using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public static class NodeServiceConfigInbounds
{
    private static readonly string[] CertificateInboundTransports =
    [
        InboundTransports.Tls,
        InboundTransports.Wss,
        InboundTransports.Grpc,
        InboundTransports.SplitHttp
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
                if (!SupportsLegacyTrojanTopLevelUsers(inbound))
                {
                    return inbound;
                }

                return inbound with
                {
                    Users = inbound.Users.Count == 0 ? config.Users : inbound.Users,
                    Fallbacks = SupportsLegacyTrojanTopLevelFallbacks(inbound) && inbound.Fallbacks.Count == 0
                        ? config.Fallbacks
                        : inbound.Fallbacks
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
            .Where(IsTrojanTransportWithRuntimeUsers)
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
            .Any(static inbound => inbound.Enabled && RequiresCertificate(inbound));

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
        if (string.Equals(normalizedProtocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            return new InboundConfig
            {
                Tag = $"{normalizedProtocol}-tcp",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Tcp,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                ListenAddress = "0.0.0.0",
                Port = 8388,
                HandshakeTimeoutSeconds = 10
            };
        }

        return normalizedTransport switch
        {
            InboundTransports.Wss => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-wss",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Wss,
                TransportProtocol = RuntimeInternetTransportProtocols.Ws,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "0.0.0.0",
                Port = 8443,
                HandshakeTimeoutSeconds = 10,
                Path = "/ws"
            },
            InboundTransports.HttpUpgrade => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-httpupgrade",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.HttpUpgrade,
                TransportProtocol = RuntimeInternetTransportProtocols.HttpUpgrade,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "0.0.0.0",
                Port = 8443,
                HandshakeTimeoutSeconds = 10,
                Path = "/upgrade"
            },
            InboundTransports.Grpc => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-grpc",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Grpc,
                TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "0.0.0.0",
                Port = 443,
                HandshakeTimeoutSeconds = 10,
                GrpcServiceName = $"/{normalizedProtocol}/service"
            },
            InboundTransports.SplitHttp => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-splithttp",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.SplitHttp,
                TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                ListenAddress = "0.0.0.0",
                Port = 443,
                HandshakeTimeoutSeconds = 10,
                Path = "/xhttp"
            },
            _ => new InboundConfig
            {
                Tag = $"{normalizedProtocol}-tcp-tls",
                Enabled = false,
                Protocol = normalizedProtocol,
                Transport = InboundTransports.Tls,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
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

    public static bool IsTrojanTlsOrWssOrGrpc(InboundConfig inbound)
    {
        ArgumentNullException.ThrowIfNull(inbound);

        return IsTrojanTlsOrWss(inbound) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Grpc);
    }

    public static bool IsTrojanTlsOrWssOrGrpcOrSplitHttp(InboundConfig inbound)
    {
        ArgumentNullException.ThrowIfNull(inbound);

        return IsTrojanTlsOrWssOrGrpc(inbound) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.SplitHttp);
    }

    public static bool IsTrojanTransportWithRuntimeUsers(InboundConfig inbound)
    {
        ArgumentNullException.ThrowIfNull(inbound);

        return IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Tls) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Wss) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, RuntimeInternetTransportProtocols.HttpUpgrade) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.Grpc) ||
               IsProtocolTransport(inbound, InboundProtocols.Trojan, InboundTransports.SplitHttp);
    }

    public static bool IsProtocolTransport(InboundConfig inbound, string protocol, string transport)
        => string.Equals(InboundProtocols.Normalize(inbound.Protocol), InboundProtocols.Normalize(protocol), StringComparison.Ordinal) &&
           string.Equals(ResolveTransportAlias(inbound), InboundTransports.Normalize(transport), StringComparison.Ordinal);

    private static bool RequiresCertificate(InboundConfig inbound)
    {
        if (InboundInternetStackResolver.TryResolve(
                inbound.Transport,
                inbound.TransportProtocol,
                inbound.TransportSecurity,
                out var stack,
                out _))
        {
            return stack.UsesTlsLikeSecurity;
        }

        return CertificateInboundTransports.Contains(
            InboundTransports.Normalize(inbound.Transport),
            StringComparer.OrdinalIgnoreCase);
    }

    private static string ResolveTransportAlias(InboundConfig inbound)
    {
        if (InboundInternetStackResolver.TryResolve(
                inbound.Transport,
                inbound.TransportProtocol,
                inbound.TransportSecurity,
                out var stack,
                out _))
        {
            return stack.Transport;
        }

        return InboundTransports.Normalize(inbound.Transport);
    }

    private static bool SupportsLegacyTrojanTopLevelUsers(InboundConfig inbound)
        => IsTrojanTransportWithRuntimeUsers(inbound);

    private static bool SupportsLegacyTrojanTopLevelFallbacks(InboundConfig inbound)
        => IsTrojanTlsOrWss(inbound);

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
                Level = Math.Max(0, user.Level),
                Uuid = NormalizeUuid(user.Uuid),
                Password = string.IsNullOrWhiteSpace(user.Password) ? string.Empty : user.Password.Trim(),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            });
        }
    }

    private static bool HasUsableCredentials(TrojanUserConfig user, string protocol)
        => protocol switch
        {
            InboundProtocols.Trojan => !string.IsNullOrWhiteSpace(user.Password),
            InboundProtocols.Shadowsocks => !string.IsNullOrWhiteSpace(user.Cipher) &&
                                            !string.IsNullOrWhiteSpace(user.Password),
            _ => !string.IsNullOrWhiteSpace(NormalizeUuid(user.Uuid))
        };

    private static string NormalizeUuid(string value)
        => Guid.TryParse(value?.Trim(), out var uuid)
            ? uuid.ToString("D")
            : string.Empty;
}

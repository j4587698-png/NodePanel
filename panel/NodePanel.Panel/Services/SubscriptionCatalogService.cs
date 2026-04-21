using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class SubscriptionCatalogService
{
    private readonly DatabaseService _db;

    public SubscriptionCatalogService(DatabaseService db)
    {
        _db = db;
    }

    public async Task<(bool Success, SubscriptionCatalog Catalog, string Error)> TryBuildAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException(null, nameof(token));
        if (!_db.IsConfigured) return (false, CreateEmptyCatalog(), "Database not configured.");

        var userEntity = await _db.FSql.Select<UserEntity>().Where(item => item.SubscriptionToken == token).FirstAsync(cancellationToken);
        return await TryBuildInnerAsync(userEntity, cancellationToken);
    }

    public async Task<(bool Success, SubscriptionCatalog Catalog, string Error)> TryBuildByUserIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException(null, nameof(userId));
        if (!_db.IsConfigured) return (false, CreateEmptyCatalog(), "Database not configured.");

        var userEntity = await _db.FSql.Select<UserEntity>().Where(item => item.UserId == userId).FirstAsync(cancellationToken);
        return await TryBuildInnerAsync(userEntity, cancellationToken);
    }

    private async Task<(bool Success, SubscriptionCatalog Catalog, string Error)> TryBuildInnerAsync(UserEntity? userEntity, CancellationToken cancellationToken)
    {
        if (userEntity is null || !userEntity.Enabled)
        {
            return (false, CreateEmptyCatalog(), "User not found or disabled.");
        }

        var user = userEntity.ToRecord();

        var nodesQuery = _db.FSql.Select<NodeEntity>().Where(n => n.Enabled);
        var allAssignedNodesList = await nodesQuery.OrderBy(n => n.NodeId).ToListAsync(cancellationToken);

        var assignedNodes = allAssignedNodesList
            .Select(n => n.ToRecord())
            .Where(n => n.GroupIds.Contains(user.GroupId) || user.NodeIds.Contains(n.NodeId))
            .ToArray();

        var catalog = new SubscriptionCatalog
        {
            User = user,
            AssignedNodes = assignedNodes,
            Endpoints = assignedNodes
                .SelectMany(BuildEndpoints)
                .ToArray()
        };

        return (true, catalog, string.Empty);
    }

    private static SubscriptionCatalog CreateEmptyCatalog() => new SubscriptionCatalog
    {
        User = new PanelUserRecord(),
        AssignedNodes = Array.Empty<PanelNodeRecord>(),
        Endpoints = Array.Empty<SubscriptionEndpoint>()
    };

    public string BuildUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(endpoint);

        return string.Equals(endpoint.Protocol, "vless", StringComparison.OrdinalIgnoreCase)
            ? BuildVlessUri(user, endpoint)
            : string.Equals(endpoint.Protocol, "vmess", StringComparison.OrdinalIgnoreCase)
                ? BuildVmessUri(user, endpoint)
                : string.Equals(endpoint.Protocol, "shadowsocks", StringComparison.OrdinalIgnoreCase)
                    ? BuildShadowsocksUri(user, endpoint)
                    : BuildTrojanUri(user, endpoint);
    }

    private string BuildTrojanUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var query = new List<string> { "security=tls" };
        AppendTransportQuery(query, endpoint);

        if (!string.IsNullOrWhiteSpace(endpoint.Sni)) query.Add($"sni={Uri.EscapeDataString(endpoint.Sni)}");
        if (endpoint.SkipCertificateVerification) query.Add("allowInsecure=1");

        return $"trojan://{Uri.EscapeDataString(user.TrojanPassword)}@{endpoint.Host}:{endpoint.Port}?{string.Join("&", query)}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private string BuildVlessUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var query = new List<string> { "encryption=none", "security=tls" };
        AppendTransportQuery(query, endpoint);

        if (!string.IsNullOrWhiteSpace(endpoint.Sni)) query.Add($"sni={Uri.EscapeDataString(endpoint.Sni)}");
        if (endpoint.SkipCertificateVerification) query.Add("allowInsecure=1");

        var uuid = ResolveProtocolUuid(user);
        return $"vless://{Uri.EscapeDataString(uuid)}@{endpoint.Host}:{endpoint.Port}?{string.Join("&", query)}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private string BuildVmessUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var transport = NormalizeEndpointTransport(endpoint.Transport);
        var config = new
        {
            v = "2",
            ps = endpoint.Label,
            add = endpoint.Host,
            port = endpoint.Port,
            id = ResolveProtocolUuid(user),
            aid = "0",
            scy = "none",
            net = transport,
            type = "none",
            host = endpoint.WsHost,
            path = string.Equals(transport, InboundTransports.Grpc, StringComparison.OrdinalIgnoreCase)
                ? endpoint.GrpcServiceName
                : endpoint.Path,
            tls = "tls",
            sni = endpoint.Sni,
            alpn = ""
        };

        var json = System.Text.Json.JsonSerializer.Serialize(config);
        var base64 = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json));
        return $"vmess://{base64}";
    }

    private string BuildShadowsocksUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var method = string.IsNullOrWhiteSpace(ShadowsocksCipherTypes.Normalize(user.ShadowsocksCipher))
            ? ShadowsocksCipherTypes.ChaCha20Poly1305
            : ShadowsocksCipherTypes.Normalize(user.ShadowsocksCipher);
        var password = string.IsNullOrWhiteSpace(user.ShadowsocksPassword)
            ? user.TrojanPassword
            : user.ShadowsocksPassword;
        var auth = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{method}:{password}"));
        return $"ss://{auth}@{endpoint.Host}:{endpoint.Port}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private static IEnumerable<SubscriptionEndpoint> BuildEndpoints(PanelNodeRecord node)
    {
        var normalizedProtocol = InboundProtocols.Normalize(node.Protocol);
        var host = ResolveSubscriptionHost(node, normalizedProtocol);
        if (string.IsNullOrWhiteSpace(host)) yield break;

        var displayName = ResolveSubscriptionDisplayName(node, host);
        var sni = ResolveSubscriptionSni(node, host, normalizedProtocol);

        foreach (var inbound in NodeServiceConfigInbounds
                     .GetProtocolInbounds(node.Config, normalizedProtocol)
                     .Where(static inbound => inbound.Enabled))
        {
            var transport = ResolveEndpointTransport(normalizedProtocol, inbound);
            if (string.IsNullOrWhiteSpace(transport))
            {
                continue;
            }

            yield return new SubscriptionEndpoint
            {
                NodeId = node.NodeId,
                DisplayName = displayName,
                Host = host,
                Port = inbound.Port,
                Sni = sni,
                Label = $"{displayName}-{BuildEndpointSuffix(normalizedProtocol, transport)}",
                Protocol = normalizedProtocol,
                Transport = transport,
                Path = inbound.Path,
                WsHost = string.IsNullOrWhiteSpace(inbound.Host)
                    ? sni
                    : inbound.Host,
                GrpcServiceName = inbound.GrpcServiceName,
                SkipCertificateVerification = !string.Equals(normalizedProtocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal) &&
                                             node.SubscriptionAllowInsecure
            };
        }
    }

    private static string? ResolveSubscriptionHost(PanelNodeRecord node, string normalizedProtocol)
    {
        if (!string.IsNullOrWhiteSpace(node.SubscriptionHost)) return node.SubscriptionHost;
        foreach (var inbound in NodeServiceConfigInbounds
                     .GetProtocolInbounds(node.Config, normalizedProtocol)
                     .Where(static inbound => inbound.Enabled))
        {
            if (IsUsableAddress(inbound.ListenAddress))
            {
                return inbound.ListenAddress;
            }
        }

        return null;
    }

    private static string ResolveSubscriptionSni(PanelNodeRecord node, string host, string normalizedProtocol)
        => string.Equals(normalizedProtocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal)
            ? string.Empty
            : string.IsNullOrWhiteSpace(node.SubscriptionSni)
                ? host
                : node.SubscriptionSni;

    private static string ResolveSubscriptionDisplayName(PanelNodeRecord node, string host)
    {
        if (!string.IsNullOrWhiteSpace(node.DisplayName))
        {
            return node.DisplayName.Trim();
        }

        if (!string.IsNullOrWhiteSpace(node.NodeId))
        {
            return node.NodeId.Trim();
        }

        return host.Trim();
    }

    private static string ResolveProtocolUuid(PanelUserRecord user)
    {
        if (Guid.TryParse(user.V2rayUuid, out var configured))
        {
            return configured.ToString("D");
        }

        if (Guid.TryParse(user.UserId, out var fallback))
        {
            return fallback.ToString("D");
        }

        return string.Empty;
    }

    private static void AppendTransportQuery(ICollection<string> query, SubscriptionEndpoint endpoint)
    {
        var transport = NormalizeEndpointTransport(endpoint.Transport);
        switch (transport)
        {
            case "tcp":
                return;
            case "ws":
                query.Add("type=ws");
                if (!string.IsNullOrWhiteSpace(endpoint.Path)) query.Add($"path={Uri.EscapeDataString(endpoint.Path)}");
                if (!string.IsNullOrWhiteSpace(endpoint.WsHost)) query.Add($"host={Uri.EscapeDataString(endpoint.WsHost)}");
                return;
            case InboundTransports.HttpUpgrade:
                query.Add("type=httpupgrade");
                if (!string.IsNullOrWhiteSpace(endpoint.Path)) query.Add($"path={Uri.EscapeDataString(endpoint.Path)}");
                if (!string.IsNullOrWhiteSpace(endpoint.WsHost)) query.Add($"host={Uri.EscapeDataString(endpoint.WsHost)}");
                return;
            case InboundTransports.Grpc:
                query.Add("type=grpc");
                if (!string.IsNullOrWhiteSpace(endpoint.GrpcServiceName)) query.Add($"serviceName={Uri.EscapeDataString(endpoint.GrpcServiceName)}");
                return;
            case InboundTransports.SplitHttp:
                query.Add("type=splithttp");
                if (!string.IsNullOrWhiteSpace(endpoint.Path)) query.Add($"path={Uri.EscapeDataString(endpoint.Path)}");
                if (!string.IsNullOrWhiteSpace(endpoint.WsHost)) query.Add($"host={Uri.EscapeDataString(endpoint.WsHost)}");
                return;
        }
    }

    private static string ResolveEndpointTransport(string protocol, InboundConfig inbound)
    {
        if (string.Equals(protocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            return InboundTransports.Tcp;
        }

        if (NodeServiceConfigInbounds.IsProtocolTransport(inbound, protocol, InboundTransports.Wss))
        {
            return "ws";
        }

        if (NodeServiceConfigInbounds.IsProtocolTransport(inbound, protocol, InboundTransports.HttpUpgrade))
        {
            return InboundTransports.HttpUpgrade;
        }

        if (NodeServiceConfigInbounds.IsProtocolTransport(inbound, protocol, InboundTransports.Grpc))
        {
            return InboundTransports.Grpc;
        }

        if (NodeServiceConfigInbounds.IsProtocolTransport(inbound, protocol, InboundTransports.SplitHttp))
        {
            return InboundTransports.SplitHttp;
        }

        if (NodeServiceConfigInbounds.IsProtocolTransport(inbound, protocol, InboundTransports.Tls))
        {
            return "tcp";
        }

        return string.Empty;
    }

    private static string NormalizeEndpointTransport(string? transport)
        => string.Equals(transport, InboundTransports.Wss, StringComparison.OrdinalIgnoreCase)
            ? "ws"
            : string.IsNullOrWhiteSpace(transport)
                ? "tcp"
                : transport.Trim().ToLowerInvariant();

    private static string BuildEndpointSuffix(string protocol, string transport)
    {
        if (string.Equals(protocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            return "ss";
        }

        return NormalizeEndpointTransport(transport) switch
        {
            "tcp" => "tcp",
            "ws" => "wss",
            _ => NormalizeEndpointTransport(transport)
        };
    }

    private static bool IsUsableAddress(string address) => !string.IsNullOrWhiteSpace(address) && !string.Equals(address, "0.0.0.0", StringComparison.OrdinalIgnoreCase) && !string.Equals(address, "::", StringComparison.OrdinalIgnoreCase);
}

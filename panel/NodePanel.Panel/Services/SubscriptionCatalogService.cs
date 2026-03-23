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

        if (string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase))
        {
            query.Add("type=ws");
            if (!string.IsNullOrWhiteSpace(endpoint.Path)) query.Add($"path={Uri.EscapeDataString(endpoint.Path)}");
            if (!string.IsNullOrWhiteSpace(endpoint.WsHost)) query.Add($"host={Uri.EscapeDataString(endpoint.WsHost)}");
        }

        if (!string.IsNullOrWhiteSpace(endpoint.Sni)) query.Add($"sni={Uri.EscapeDataString(endpoint.Sni)}");
        if (endpoint.SkipCertificateVerification) query.Add("allowInsecure=1");

        return $"trojan://{Uri.EscapeDataString(user.TrojanPassword)}@{endpoint.Host}:{endpoint.Port}?{string.Join("&", query)}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private string BuildVlessUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var query = new List<string> { "encryption=none", "security=tls" };

        if (string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase))
        {
            query.Add("type=ws");
            if (!string.IsNullOrWhiteSpace(endpoint.Path)) query.Add($"path={Uri.EscapeDataString(endpoint.Path)}");
            if (!string.IsNullOrWhiteSpace(endpoint.WsHost)) query.Add($"host={Uri.EscapeDataString(endpoint.WsHost)}");
        }

        if (!string.IsNullOrWhiteSpace(endpoint.Sni)) query.Add($"sni={Uri.EscapeDataString(endpoint.Sni)}");
        if (endpoint.SkipCertificateVerification) query.Add("allowInsecure=1");

        var uuid = ResolveProtocolUuid(user);
        return $"vless://{Uri.EscapeDataString(uuid)}@{endpoint.Host}:{endpoint.Port}?{string.Join("&", query)}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private string BuildVmessUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var config = new
        {
            v = "2",
            ps = endpoint.Label,
            add = endpoint.Host,
            port = endpoint.Port,
            id = ResolveProtocolUuid(user),
            aid = "0",
            scy = "none",
            net = string.Equals(endpoint.Transport, "ws", StringComparison.OrdinalIgnoreCase) ? "ws" : "tcp",
            type = "none",
            host = endpoint.WsHost,
            path = endpoint.Path,
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
        // SS uses base64(method:password)@plugin
        var auth = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"chacha20-ietf-poly1305:{user.TrojanPassword}"));
        return $"ss://{auth}@{endpoint.Host}:{endpoint.Port}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private static IEnumerable<SubscriptionEndpoint> BuildEndpoints(PanelNodeRecord node)
    {
        var host = ResolveSubscriptionHost(node);
        if (string.IsNullOrWhiteSpace(host)) yield break;

        var sni = string.IsNullOrWhiteSpace(node.SubscriptionSni) ? host : node.SubscriptionSni;
        var normalizedProtocol = InboundProtocols.Normalize(node.Protocol);
        var tcpTls = NodeServiceConfigInbounds.GetProtocolTransportInbound(node.Config, normalizedProtocol, InboundTransports.Tls);
        if (tcpTls.Enabled)
        {
            yield return new SubscriptionEndpoint
            {
                NodeId = node.NodeId,
                DisplayName = node.DisplayName,
                Host = host,
                Port = tcpTls.Port,
                Sni = sni,
                Label = $"{node.DisplayName}-tcp",
                Protocol = node.Protocol,
                SkipCertificateVerification = node.SubscriptionAllowInsecure
            };
        }

        var wss = NodeServiceConfigInbounds.GetProtocolTransportInbound(node.Config, normalizedProtocol, InboundTransports.Wss);
        if (wss.Enabled)
        {
            yield return new SubscriptionEndpoint
            {
                NodeId = node.NodeId,
                DisplayName = node.DisplayName,
                Host = host,
                Port = wss.Port,
                Sni = sni,
                Label = $"{node.DisplayName}-wss",
                Protocol = node.Protocol,
                Transport = "ws",
                Path = wss.Path,
                WsHost = string.IsNullOrWhiteSpace(wss.Host) ? sni : wss.Host,
                SkipCertificateVerification = node.SubscriptionAllowInsecure
            };
        }
    }

    private static string? ResolveSubscriptionHost(PanelNodeRecord node)
    {
        if (!string.IsNullOrWhiteSpace(node.SubscriptionHost)) return node.SubscriptionHost;
        var normalizedProtocol = InboundProtocols.Normalize(node.Protocol);
        var tcpTls = NodeServiceConfigInbounds.GetProtocolTransportInbound(node.Config, normalizedProtocol, InboundTransports.Tls);
        if (IsUsableAddress(tcpTls.ListenAddress)) return tcpTls.ListenAddress;

        var wss = NodeServiceConfigInbounds.GetProtocolTransportInbound(node.Config, normalizedProtocol, InboundTransports.Wss);
        if (IsUsableAddress(wss.ListenAddress)) return wss.ListenAddress;

        return null;
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

    private static bool IsUsableAddress(string address) => !string.IsNullOrWhiteSpace(address) && !string.Equals(address, "0.0.0.0", StringComparison.OrdinalIgnoreCase) && !string.Equals(address, "::", StringComparison.OrdinalIgnoreCase);
}

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

        if (IsRealityEndpoint(endpoint) &&
            !string.Equals(endpoint.Protocol, "vless", StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

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
        var query = new List<string> { $"security={Uri.EscapeDataString(NormalizeEndpointSecurity(endpoint.Security))}" };
        AppendTransportQuery(query, endpoint);

        if (!string.IsNullOrWhiteSpace(endpoint.Sni)) query.Add($"sni={Uri.EscapeDataString(endpoint.Sni)}");
        if (endpoint.SkipCertificateVerification) query.Add("allowInsecure=1");

        return $"trojan://{Uri.EscapeDataString(user.TrojanPassword)}@{endpoint.Host}:{endpoint.Port}?{string.Join("&", query)}#{Uri.EscapeDataString(endpoint.Label)}";
    }

    private string BuildVlessUri(PanelUserRecord user, SubscriptionEndpoint endpoint)
    {
        var security = NormalizeEndpointSecurity(endpoint.Security);
        var query = new List<string> { "encryption=none", $"security={Uri.EscapeDataString(security)}" };
        AppendTransportQuery(query, endpoint);

        if (!string.IsNullOrWhiteSpace(endpoint.Sni)) query.Add($"sni={Uri.EscapeDataString(endpoint.Sni)}");
        if (IsRealityEndpoint(endpoint))
        {
            if (!string.IsNullOrWhiteSpace(endpoint.RealityFingerprint)) query.Add($"fp={Uri.EscapeDataString(endpoint.RealityFingerprint)}");
            if (!string.IsNullOrWhiteSpace(endpoint.RealityPublicKey)) query.Add($"pbk={Uri.EscapeDataString(endpoint.RealityPublicKey)}");
            if (!string.IsNullOrWhiteSpace(endpoint.RealityShortId)) query.Add($"sid={Uri.EscapeDataString(endpoint.RealityShortId)}");
            if (!string.IsNullOrWhiteSpace(endpoint.RealitySpiderX)) query.Add($"spx={Uri.EscapeDataString(endpoint.RealitySpiderX)}");
        }

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
            tls = NormalizeEndpointSecurity(endpoint.Security),
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
        var defaultSni = ResolveSubscriptionSni(node, host, normalizedProtocol);

        foreach (var inbound in NodeServiceConfigInbounds
                     .GetProtocolInbounds(node.Config, normalizedProtocol)
                     .Where(static inbound => inbound.Enabled))
        {
            var transport = ResolveEndpointTransport(normalizedProtocol, inbound, out var security);
            if (string.IsNullOrWhiteSpace(transport))
            {
                continue;
            }

            var reality = string.Equals(security, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal);
            var sni = reality
                ? ResolveRealityServerName(node.Config.Reality, defaultSni)
                : defaultSni;
            var realityPublicKey = reality && RuntimeRealityUtilities.TryDerivePublicKey(
                    node.Config.Reality?.PrivateKey ?? string.Empty,
                    out var derivedPublicKey,
                    out _)
                ? derivedPublicKey
                : string.Empty;
            var labelSuffix = BuildEndpointSuffix(normalizedProtocol, transport, security);

            yield return new SubscriptionEndpoint
            {
                NodeId = node.NodeId,
                DisplayName = displayName,
                Host = host,
                Port = inbound.Port,
                Sni = sni,
                Label = $"{displayName}-{labelSuffix}",
                Protocol = normalizedProtocol,
                Security = security,
                Transport = transport,
                Path = inbound.Path,
                WsHost = string.IsNullOrWhiteSpace(inbound.Host)
                    ? sni
                    : inbound.Host,
                GrpcServiceName = inbound.GrpcServiceName,
                RealityPublicKey = realityPublicKey,
                RealityShortId = reality ? ResolveRealityShortId(node.Config.Reality) : string.Empty,
                RealityFingerprint = reality ? "chrome" : string.Empty,
                RealitySpiderX = reality ? "/" : string.Empty,
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

    private static string ResolveEndpointTransport(string protocol, InboundConfig inbound, out string security)
    {
        if (string.Equals(protocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            security = RuntimeInternetSecurityTypes.None;
            return InboundTransports.Tcp;
        }

        if (!InboundInternetStackResolver.TryResolve(
                inbound.Transport,
                inbound.TransportProtocol,
                inbound.TransportSecurity,
                out var stack,
                out _))
        {
            security = string.Empty;
            return string.Empty;
        }

        security = stack.SecurityType;
        return string.Equals(stack.TransportProtocol, RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal)
            ? "ws"
            : stack.TransportProtocol;
    }

    private static string NormalizeEndpointTransport(string? transport)
        => string.Equals(transport, InboundTransports.Wss, StringComparison.OrdinalIgnoreCase)
            ? "ws"
            : string.IsNullOrWhiteSpace(transport)
                ? "tcp"
                : transport.Trim().ToLowerInvariant();

    private static string NormalizeEndpointSecurity(string? security)
        => string.IsNullOrWhiteSpace(security)
            ? RuntimeInternetSecurityTypes.Tls
            : security.Trim().ToLowerInvariant();

    private static string BuildEndpointSuffix(string protocol, string transport, string security)
    {
        if (string.Equals(protocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            return "ss";
        }

        var transportSuffix = NormalizeEndpointTransport(transport) switch
        {
            "tcp" => "tcp",
            "ws" => "wss",
            _ => NormalizeEndpointTransport(transport)
        };
        return string.Equals(security, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal)
            ? $"{transportSuffix}-reality"
            : transportSuffix;
    }

    private static string ResolveRealityServerName(RuntimeRealityServerOptions? options, string fallback)
        => options?.ServerNames.FirstOrDefault(static item => !string.IsNullOrWhiteSpace(item))?.Trim() ?? fallback;

    private static string ResolveRealityShortId(RuntimeRealityServerOptions? options)
        => options?.ShortIds.FirstOrDefault(static item => !string.IsNullOrWhiteSpace(item))?.Trim() ?? string.Empty;

    private static bool IsRealityEndpoint(SubscriptionEndpoint endpoint)
        => string.Equals(NormalizeEndpointSecurity(endpoint.Security), RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal);

    private static bool IsUsableAddress(string address) => !string.IsNullOrWhiteSpace(address) && !string.Equals(address, "0.0.0.0", StringComparison.OrdinalIgnoreCase) && !string.Equals(address, "::", StringComparison.OrdinalIgnoreCase);
}

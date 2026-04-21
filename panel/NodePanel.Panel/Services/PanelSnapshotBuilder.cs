using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelSnapshotBuilder
{
    private readonly DatabaseService _db;

    public PanelSnapshotBuilder(DatabaseService db)
    {
        _db = db;
    }

    public async Task<(bool Success, int Revision, NodeServiceConfig Config)> TryBuildAsync(string nodeId, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return (false, 0, new NodeServiceConfig());

        var node = await _db.FSql.Select<NodeEntity>().Where(item => item.NodeId == nodeId).FirstAsync(cancellationToken);
        if (node is null)
        {
            return (false, 0, new NodeServiceConfig());
        }

        var revision = node.DesiredRevision;
        var usersEntity = await _db.FSql.Select<UserEntity>().Where(u => u.Enabled).ToListAsync(cancellationToken);
        
        var users = usersEntity
            .Select(u => u.ToRecord())
            .Where(user => user.Enabled && IsAssignedToNode(user, nodeId))
            .Select(user => CreateRuntimeUser(user, InboundProtocols.Normalize(node.Protocol)))
            .Where(static user => user is not null)
            .Select(static user => user!)
            .OrderBy(static user => user.UserId, StringComparer.Ordinal)
            .ToArray();

        var normalizedProtocol = InboundProtocols.Normalize(node.Protocol);

        var config = node.Enabled
            ? node.Config with
            {
                Inbounds = ReplaceManagedUsers(node.Config.Inbounds, users, normalizedProtocol),
                Users = Array.Empty<TrojanUserConfig>()
            }
            : node.Config with
            {
                Inbounds = node.Config.Inbounds
                    .Select(static inbound => inbound with
                    {
                        Enabled = false,
                        Users = Array.Empty<TrojanUserConfig>()
                    })
                    .ToArray(),
                Users = Array.Empty<TrojanUserConfig>()
            };

        config = await InjectDistributedCertificateAsync(config, cancellationToken).ConfigureAwait(false);
        return (true, revision, config);
    }

    private async Task<NodeServiceConfig> InjectDistributedCertificateAsync(NodeServiceConfig config, CancellationToken cancellationToken)
    {
        var certificate = config.Certificate;
        if (CertificateModes.Normalize(certificate.Mode) != CertificateModes.PanelDistributed ||
            string.IsNullOrWhiteSpace(certificate.PanelCertificateId))
        {
            return config;
        }

        var entity = await _db.FSql
            .Select<PanelCertificateEntity>()
            .Where(item => item.CertificateId == certificate.PanelCertificateId)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            return config;
        }

        return config with
        {
            Certificate = certificate with
            {
                PfxPassword = entity.PfxPassword,
                DistributedAsset = new DistributedCertificateAsset
                {
                    Version = Math.Max(1, entity.AssetVersion),
                    PfxBase64 = entity.PfxBase64,
                    Thumbprint = entity.Thumbprint,
                    NotBefore = entity.NotBefore,
                    NotAfter = entity.NotAfter
                }
            }
        };
    }

    private static bool IsAssignedToNode(PanelUserRecord user, string nodeId)
        => user.NodeIds.Count == 0 || user.NodeIds.Contains(nodeId, StringComparer.Ordinal);

    private static TrojanUserConfig? CreateRuntimeUser(PanelUserRecord user, string protocol)
        => protocol switch
        {
            InboundProtocols.Trojan => string.IsNullOrWhiteSpace(user.TrojanPassword)
                ? null
                : new TrojanUserConfig
                {
                    UserId = user.UserId,
                    Password = user.TrojanPassword,
                    BytesPerSecond = user.BytesPerSecond,
                    DeviceLimit = user.DeviceLimit
                },
            InboundProtocols.Shadowsocks => string.IsNullOrWhiteSpace(user.ShadowsocksPassword)
                                            || string.IsNullOrWhiteSpace(ShadowsocksCipherTypes.Normalize(user.ShadowsocksCipher))
                ? null
                : new TrojanUserConfig
                {
                    UserId = user.UserId,
                    Cipher = ShadowsocksCipherTypes.Normalize(user.ShadowsocksCipher),
                    Password = user.ShadowsocksPassword,
                    BytesPerSecond = user.BytesPerSecond,
                    DeviceLimit = user.DeviceLimit
                },
            InboundProtocols.Vless or InboundProtocols.Vmess => Guid.TryParse(user.V2rayUuid, out var uuid)
                ? new TrojanUserConfig
                {
                    UserId = user.UserId,
                    Uuid = uuid.ToString("D"),
                    BytesPerSecond = user.BytesPerSecond,
                    DeviceLimit = user.DeviceLimit
                }
                : null,
            _ => null
        };

    private static IReadOnlyList<InboundConfig> ReplaceManagedUsers(
        IReadOnlyList<InboundConfig> inbounds,
        IReadOnlyList<TrojanUserConfig> users,
        string protocol)
    {
        var updated = NodeServiceConfigInbounds.ReplaceProtocolUsers(inbounds, users, protocol);
        if (!string.Equals(protocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            return updated;
        }

        return updated
            .Select(inbound => string.Equals(InboundProtocols.Normalize(inbound.Protocol), protocol, StringComparison.Ordinal)
                ? inbound with
                {
                    ShadowsocksUsers = Array.Empty<ShadowsocksUserConfig>()
                }
                : inbound)
            .ToArray();
    }
}

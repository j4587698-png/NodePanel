using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class ConfigOrchestrator
{
    private readonly SemaphoreSlim _applyLock = new(1, 1);
    private readonly ILogger<ConfigOrchestrator> _logger;
    private readonly PersistedNodeConfigStore _persistedNodeConfigStore;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly NodeRuntimeSnapshotBuilder _snapshotBuilder;
    private readonly IReadOnlyList<string> _supportedOutboundProtocols;
    private readonly string _baseDirectory;

    public ConfigOrchestrator(
        RuntimeConfigStore runtimeConfigStore,
        IEnumerable<string> supportedOutboundProtocols,
        IEnumerable<IInboundProtocolRuntimeCompiler> inboundProtocolCompilers,
        IEnumerable<IOutboundProtocolRuntimeCompiler> outboundProtocolCompilers,
        PersistedNodeConfigStore persistedNodeConfigStore,
        ILogger<ConfigOrchestrator> logger,
        string? baseDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(supportedOutboundProtocols);
        ArgumentNullException.ThrowIfNull(inboundProtocolCompilers);
        ArgumentNullException.ThrowIfNull(outboundProtocolCompilers);

        _runtimeConfigStore = runtimeConfigStore;
        _supportedOutboundProtocols = supportedOutboundProtocols
            .Where(static protocol => !string.IsNullOrWhiteSpace(protocol))
            .Select(static protocol => OutboundProtocols.Normalize(protocol))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        _snapshotBuilder = outboundProtocolCompilers.Any()
            ? new NodeRuntimeSnapshotBuilder(inboundProtocolCompilers, outboundProtocolCompilers)
            : new NodeRuntimeSnapshotBuilder(inboundProtocolCompilers);
        _persistedNodeConfigStore = persistedNodeConfigStore;
        _logger = logger;
        _baseDirectory = string.IsNullOrWhiteSpace(baseDirectory)
            ? AppContext.BaseDirectory
            : Path.GetFullPath(baseDirectory);
    }

    public ConfigOrchestrator(
        RuntimeConfigStore runtimeConfigStore,
        IEnumerable<IInboundProtocolRuntimeCompiler> inboundProtocolCompilers,
        PersistedNodeConfigStore persistedNodeConfigStore,
        ILogger<ConfigOrchestrator> logger,
        string? baseDirectory = null)
        : this(
            runtimeConfigStore,
            RuntimeCapabilities.SupportedOutboundProtocols,
            inboundProtocolCompilers,
            Array.Empty<IOutboundProtocolRuntimeCompiler>(),
            persistedNodeConfigStore,
            logger,
            baseDirectory)
    {
    }

    public ConfigOrchestrator(
        RuntimeConfigStore runtimeConfigStore,
        IEnumerable<string> supportedOutboundProtocols,
        IEnumerable<IInboundProtocolRuntimeCompiler> inboundProtocolCompilers,
        PersistedNodeConfigStore persistedNodeConfigStore,
        ILogger<ConfigOrchestrator> logger,
        string? baseDirectory = null)
        : this(
            runtimeConfigStore,
            supportedOutboundProtocols,
            inboundProtocolCompilers,
            Array.Empty<IOutboundProtocolRuntimeCompiler>(),
            persistedNodeConfigStore,
            logger,
            baseDirectory)
    {
    }

    public void ApplyBootstrap(NodeServiceConfig config, int revision = 0)
    {
        config = ApplyRoutingResourceDefaults(config);
        var normalized = _snapshotBuilder.Normalize(config);
        if (!TryCreateRuntimeSnapshot(revision, normalized, out var snapshot, out var error))
        {
            throw new InvalidOperationException(error ?? "Bootstrap config is invalid.");
        }

        _runtimeConfigStore.Bootstrap(snapshot);
        TryPersist(revision, snapshot.Config);
    }

    public async ValueTask<ApplyResultPayload> ApplySnapshotAsync(int revision, NodeServiceConfig config, CancellationToken cancellationToken)
    {
        await _applyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            config = ApplyRoutingResourceDefaults(config);
            var normalized = _snapshotBuilder.Normalize(config);
            if (!TryMaterializeDistributedCertificate(normalized.Certificate, out var certificate, out var assetError))
            {
                return new ApplyResultPayload
                {
                    RequestedRevision = revision,
                    Success = false,
                    Error = assetError
                };
            }

            normalized = normalized with
            {
                Certificate = certificate
            };

            if (!TryCreateRuntimeSnapshot(revision, normalized, out var snapshot, out var error))
            {
                return new ApplyResultPayload
                {
                    RequestedRevision = revision,
                    Success = false,
                    Error = error
                };
            }

            if (!_runtimeConfigStore.TryCommit(snapshot, out error))
            {
                return new ApplyResultPayload
                {
                    RequestedRevision = revision,
                    Success = false,
                    Error = error
                };
            }

            TryPersist(revision, snapshot.Config);

            return new ApplyResultPayload
            {
                RequestedRevision = revision,
                Success = true
            };
        }
        finally
        {
            _applyLock.Release();
        }
    }

    private bool TryCreateRuntimeSnapshot(
        int revision,
        NodeServiceConfig config,
        out NodeRuntimeSnapshot snapshot,
        out string? error)
        => _snapshotBuilder.TryBuildNormalized(revision, config, _supportedOutboundProtocols, out snapshot, out error);

    private NodeServiceConfig ApplyRoutingResourceDefaults(NodeServiceConfig config)
        => RoutingResourceLocator.ApplyDefaults(config, _baseDirectory);

    private static bool TryMaterializeDistributedCertificate(
        CertificateOptions certificate,
        out CertificateOptions normalized,
        out string? error)
    {
        normalized = certificate;
        if (CertificateModes.Normalize(certificate.Mode) != CertificateModes.PanelDistributed)
        {
            error = null;
            return true;
        }

        var asset = certificate.DistributedAsset;
        if (string.IsNullOrWhiteSpace(asset.PfxBase64))
        {
            error = null;
            return true;
        }

        if (string.IsNullOrWhiteSpace(certificate.PfxPath))
        {
            error = "Panel distributed certificate mode requires a local cache path.";
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(asset.PfxBase64);
            var fullPath = Path.GetFullPath(certificate.PfxPath);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = fullPath + ".tmp";
            File.WriteAllBytes(tempPath, bytes);
            File.Move(tempPath, fullPath, overwrite: true);

            normalized = certificate with
            {
                PfxPath = fullPath,
                DistributedAsset = asset with
                {
                    PfxBase64 = string.Empty
                }
            };

            error = null;
            return true;
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            error = $"Failed to materialize distributed certificate asset: {ex.Message}";
            return false;
        }
    }

    private void TryPersist(int revision, NodeServiceConfig config)
    {
        try
        {
            _persistedNodeConfigStore.Save(revision, config);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist node runtime config revision {Revision}.", revision);
        }
    }
}

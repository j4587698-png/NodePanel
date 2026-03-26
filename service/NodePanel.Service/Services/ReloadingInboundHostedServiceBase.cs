using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public abstract class ReloadingInboundHostedServiceBase : BackgroundService
{
    private readonly CertificateStateStore _certificateStateStore;
    private readonly ILogger _logger;
    private readonly RuntimeConfigStore _runtimeConfigStore;

    protected ReloadingInboundHostedServiceBase(
        RuntimeConfigStore runtimeConfigStore,
        CertificateStateStore certificateStateStore,
        ILogger logger)
    {
        _runtimeConfigStore = runtimeConfigStore;
        _certificateStateStore = certificateStateStore;
        _logger = logger;
    }

    protected abstract string HostDisplayName { get; }

    protected abstract bool HasActiveRuntime(NodeRuntimeSnapshot snapshot);

    protected abstract bool RequiresCertificate(NodeRuntimeSnapshot snapshot);

    protected abstract Task RunHostAsync(
        NodeRuntimeSnapshot snapshot,
        X509Certificate2? certificate,
        CancellationToken cancellationToken);

    protected virtual void OnRuntimeInactive(NodeRuntimeSnapshot snapshot)
    {
    }

    protected virtual void OnHostFault(NodeRuntimeSnapshot snapshot, Exception exception)
    {
    }

    protected virtual void OnHostUnexpectedStop(NodeRuntimeSnapshot snapshot)
    {
    }

    protected virtual string ResolveCertificatePath(NodeRuntimeSnapshot snapshot)
        => snapshot.Config.Certificate.PfxPath;

    protected virtual X509Certificate2 LoadCertificate(NodeRuntimeSnapshot snapshot)
        => CertificateLoader.Load(snapshot.Config.Certificate);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var snapshot = _runtimeConfigStore.GetSnapshot();
            if (!HasActiveRuntime(snapshot))
            {
                OnRuntimeInactive(snapshot);
                await _runtimeConfigStore.WaitForChangeAsync(snapshot.Revision, stoppingToken).ConfigureAwait(false);
                continue;
            }

            var requiresCertificate = RequiresCertificate(snapshot);
            var certificateAssetVersion = _certificateStateStore.GetSnapshot().AssetVersion;
            var certificatePath = ResolveCertificatePath(snapshot);

            if (requiresCertificate && string.IsNullOrWhiteSpace(certificatePath))
            {
                _logger.LogWarning("{Host} is enabled but certificate path is empty. Waiting for the next revision.", HostDisplayName);
                await WaitForReloadAsync(snapshot.Revision, certificateAssetVersion, stoppingToken).ConfigureAwait(false);
                continue;
            }

            X509Certificate2? certificate = null;
            if (requiresCertificate)
            {
                try
                {
                    certificate = LoadCertificate(snapshot);
                }
                catch (Exception ex)
                {
                    OnHostFault(snapshot, ex);
                    _logger.LogError(ex, "{Host} failed to load certificate from {Path}.", HostDisplayName, certificatePath);
                    await WaitForReloadAsync(snapshot.Revision, _certificateStateStore.GetSnapshot().AssetVersion, stoppingToken).ConfigureAwait(false);
                    continue;
                }
            }

            try
            {
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                var hostTask = RunHostAsync(snapshot, certificate, linkedCts.Token);
                var changeTask = _runtimeConfigStore.WaitForChangeAsync(snapshot.Revision, stoppingToken);
                var certificateChangeTask = requiresCertificate
                    ? _certificateStateStore.WaitForAssetChangeAsync(certificateAssetVersion, stoppingToken)
                    : WaitForCancellationAsync(stoppingToken);
                var completed = await Task.WhenAny(hostTask, changeTask, certificateChangeTask).ConfigureAwait(false);

                linkedCts.Cancel();

                try
                {
                    await hostTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
                {
                }

                if (completed == certificateChangeTask && !stoppingToken.IsCancellationRequested)
                {
                    _logger.LogInformation("{Host} detected a certificate asset change and will reload.", HostDisplayName);
                    continue;
                }

                if (completed == hostTask && !stoppingToken.IsCancellationRequested)
                {
                    OnHostUnexpectedStop(snapshot);
                    _logger.LogWarning("{Host} ended unexpectedly. Restarting on the current revision.", HostDisplayName);
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                OnHostFault(snapshot, ex);
                _logger.LogError(ex, "{Host} failed for revision {Revision}.", HostDisplayName, snapshot.Revision);
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
            }
            finally
            {
                certificate?.Dispose();
            }
        }
    }

    private async Task WaitForReloadAsync(int knownRevision, int knownAssetVersion, CancellationToken cancellationToken)
    {
        var configChange = _runtimeConfigStore.WaitForChangeAsync(knownRevision, cancellationToken);
        var assetChange = _certificateStateStore.WaitForAssetChangeAsync(knownAssetVersion, cancellationToken);
        await Task.WhenAny(configChange, assetChange).ConfigureAwait(false);
    }

    private static Task WaitForCancellationAsync(CancellationToken cancellationToken)
        => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
}

using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NodePanel.Core.Runtime;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class RuntimeLifecycleService : BackgroundService
{
    private readonly AppliedRuntimeSnapshotStore _appliedRuntimeSnapshotStore;
    private readonly CertificateStateStore _certificateStateStore;
    private readonly RuntimeFaultSignal _faultSignal = new();
    private readonly ILogger<RuntimeLifecycleService> _logger;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly IRuntime _runtime;
    private readonly XrayRuntimeOptions _xrayRuntimeOptions;

    private LoadedCertificatePackage? _loadedCertificatePackage;
    private bool _runtimeStarted;

    public RuntimeLifecycleService(
        RuntimeConfigStore runtimeConfigStore,
        AppliedRuntimeSnapshotStore appliedRuntimeSnapshotStore,
        CertificateStateStore certificateStateStore,
        IRuntime runtime,
        XrayRuntimeOptions xrayRuntimeOptions,
        ILogger<RuntimeLifecycleService> logger)
    {
        _runtimeConfigStore = runtimeConfigStore;
        _appliedRuntimeSnapshotStore = appliedRuntimeSnapshotStore;
        _certificateStateStore = certificateStateStore;
        _runtime = runtime;
        _xrayRuntimeOptions = xrayRuntimeOptions;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var eventTask = ObserveRuntimeEventsAsync(stoppingToken);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var snapshot = _runtimeConfigStore.GetSnapshot();
                if (!HasActiveRuntime(snapshot))
                {
                    await StopRuntimeAsync(stoppingToken).ConfigureAwait(false);
                    _appliedRuntimeSnapshotStore.MarkApplied(snapshot);
                    await WaitForNextChangeAsync(snapshot, requiresCertificate: false, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                if (!TryPreparePlan(snapshot, out var preparedPlan, out var error))
                {
                    _logger.LogWarning(
                        "Runtime cannot apply revision {Revision}: {Error}",
                        snapshot.Revision,
                        error);
                    await StopRuntimeAsync(stoppingToken).ConfigureAwait(false);
                    await WaitForNextChangeAsync(snapshot, snapshot.RequiresCertificate, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                try
                {
                    await ApplyPreparedPlanAsync(snapshot, preparedPlan, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    preparedPlan.Dispose();
                    break;
                }
                catch (Exception ex)
                {
                    preparedPlan.Dispose();
                    _logger.LogError(ex, "Runtime failed to apply revision {Revision}.", snapshot.Revision);
                    await StopRuntimeAsync(stoppingToken).ConfigureAwait(false);
                    await WaitForNextChangeAsync(snapshot, snapshot.RequiresCertificate, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                await WaitForNextChangeAsync(snapshot, snapshot.RequiresCertificate, stoppingToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await StopRuntimeAsync(CancellationToken.None).ConfigureAwait(false);

            try
            {
                await eventTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
        }
    }

    private async Task ApplyPreparedPlanAsync(
        NodeRuntimeSnapshot snapshot,
        PreparedRuntimePlan preparedPlan,
        CancellationToken cancellationToken)
    {
        var previousCertificatePackage = _loadedCertificatePackage;

        try
        {
            if (_runtimeStarted)
            {
                await _runtime.ReloadAsync(preparedPlan.Plan, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await _runtime.StartAsync(preparedPlan.Plan, cancellationToken).ConfigureAwait(false);
                _runtimeStarted = true;
            }

            _loadedCertificatePackage = preparedPlan.DetachCertificatePackage();
            _appliedRuntimeSnapshotStore.MarkApplied(snapshot);
            previousCertificatePackage?.Dispose();
        }
        catch
        {
            previousCertificatePackage?.Dispose();
            _loadedCertificatePackage = null;
            throw;
        }
        finally
        {
            preparedPlan.Dispose();
        }
    }

    private bool TryPreparePlan(
        NodeRuntimeSnapshot snapshot,
        out PreparedRuntimePlan preparedPlan,
        out string? error)
    {
        if (!snapshot.RequiresCertificate)
        {
            preparedPlan = new PreparedRuntimePlan(snapshot.CreateRuntimePlan(certificate: null, _xrayRuntimeOptions.UseCone), null);
            error = null;
            return true;
        }

        if (string.IsNullOrWhiteSpace(snapshot.Config.Certificate.PfxPath))
        {
            preparedPlan = default!;
            error = "TLS listeners require a certificate path.";
            return false;
        }

        try
        {
            var certificatePackage = CertificateLoader.LoadPackage(snapshot.Config.Certificate);
            preparedPlan = new PreparedRuntimePlan(
                snapshot.CreateRuntimePlan(
                    certificatePackage.Certificate,
                    certificatePackage.AdditionalCertificates,
                    _xrayRuntimeOptions.UseCone),
                certificatePackage);
            error = null;
            return true;
        }
        catch (Exception ex)
        {
            preparedPlan = default!;
            error = $"Failed to load runtime certificate: {ex.Message}";
            return false;
        }
    }

    private async Task StopRuntimeAsync(CancellationToken cancellationToken)
    {
        var certificatePackage = _loadedCertificatePackage;
        _loadedCertificatePackage = null;

        try
        {
            if (_runtimeStarted || _runtime.State != RuntimeState.Stopped)
            {
                await _runtime.StopAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _runtimeStarted = false;
            certificatePackage?.Dispose();
        }
    }

    private async Task WaitForNextChangeAsync(
        NodeRuntimeSnapshot snapshot,
        bool requiresCertificate,
        CancellationToken cancellationToken)
    {
        var knownRevision = snapshot.Revision;
        var knownAssetVersion = _certificateStateStore.GetSnapshot().AssetVersion;
        var knownFaultVersion = _faultSignal.Version;
        var configChange = _runtimeConfigStore.WaitForChangeAsync(knownRevision, cancellationToken);
        var certificateChange = requiresCertificate
            ? _certificateStateStore.WaitForAssetChangeAsync(knownAssetVersion, cancellationToken)
            : WaitForCancellationAsync(cancellationToken);
        var faultChange = _faultSignal.WaitForChangeAsync(knownFaultVersion, cancellationToken);

        await Task.WhenAny(configChange, certificateChange, faultChange).ConfigureAwait(false);
    }

    private async Task ObserveRuntimeEventsAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var runtimeEvent in _runtime.GetEventsAsync(cancellationToken).ConfigureAwait(false))
            {
                switch (runtimeEvent)
                {
                    case RuntimeListenerStartedEvent listenerStarted:
                        LogListenerStarted(listenerStarted);
                        break;
                    case RuntimeListenerFaultedEvent listenerFaulted:
                        _faultSignal.ReportFault();
                        _logger.LogError(
                            "Runtime listener group {TaskName} faulted at revision {Revision}: {Message}",
                            listenerFaulted.TaskName,
                            listenerFaulted.Revision,
                            listenerFaulted.Message);
                        break;
                    case RuntimeFaultedEvent faulted:
                        _faultSignal.ReportFault();
                        _logger.LogError(
                            faulted.Exception,
                            "Runtime faulted at revision {Revision} on {TaskName}: {Message}",
                            faulted.Revision,
                            faulted.TaskName,
                            faulted.Message);
                        break;
                    case RuntimeStateChangedEvent stateChanged:
                        _logger.LogInformation(
                            "Runtime state changed to {State} at revision {Revision}: {Message}",
                            stateChanged.State,
                            stateChanged.Revision,
                            stateChanged.Message);
                        break;
                    case RuntimeClientHelloRejectedEvent clientHelloRejected:
                        LogClientHelloRejected(clientHelloRejected);
                        break;
                    case RuntimeUnknownServerNameRejectedEvent unknownServerNameRejected:
                        LogUnknownServerNameRejected(unknownServerNameRejected);
                        break;
                    case RuntimeConnectionErrorEvent connectionError:
                        LogConnectionError(connectionError);
                        break;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (ChannelClosedException)
        {
        }
    }

    private void LogListenerStarted(RuntimeListenerStartedEvent runtimeEvent)
    {
        var listener = runtimeEvent.Listener;
        if (listener.Binding.IsUnix)
        {
            _logger.LogInformation(
                "Runtime listener {Protocol}/{Tag} is running on unix:{Address} at revision {Revision}.",
                listener.Protocol,
                listener.Tag,
                listener.Binding.ListenAddress,
                runtimeEvent.Revision);
            return;
        }

        _logger.LogInformation(
            "Runtime listener {Protocol}/{Tag} is running on {Address}:{Port} at revision {Revision}.",
            listener.Protocol,
            listener.Tag,
            listener.Binding.ListenAddress,
            listener.Binding.Port,
            runtimeEvent.Revision);
    }

    private void LogClientHelloRejected(RuntimeClientHelloRejectedEvent runtimeEvent)
    {
        _logger.LogWarning(
            "Rejected {Protocol} inbound connection from {RemoteEndPoint} due to client hello policy '{Reason}' (SNI: {ServerName}, JA3: {Ja3Hash}).",
            FormatInboundProtocol(runtimeEvent.Protocol),
            FormatRemoteEndPoint(runtimeEvent.RemoteEndPoint),
            string.IsNullOrWhiteSpace(runtimeEvent.Reason) ? "unknown" : runtimeEvent.Reason,
            FormatDisplayValue(runtimeEvent.ServerName),
            FormatDisplayValue(runtimeEvent.Ja3Hash));
    }

    private void LogUnknownServerNameRejected(RuntimeUnknownServerNameRejectedEvent runtimeEvent)
    {
        _logger.LogWarning(
            "Rejected {Protocol} inbound connection from {RemoteEndPoint} due to unknown SNI '{ServerName}'.",
            FormatInboundProtocol(runtimeEvent.Protocol),
            FormatRemoteEndPoint(runtimeEvent.RemoteEndPoint),
            FormatDisplayValue(runtimeEvent.RequestedServerName));
    }

    private void LogConnectionError(RuntimeConnectionErrorEvent runtimeEvent)
    {
        if (runtimeEvent.IsProxyInbound)
        {
            _logger.LogDebug(
                runtimeEvent.Exception,
                "{Proxy} connection failed on {InboundTag} from {RemoteEndPoint}.",
                FormatProxyInboundProtocol(runtimeEvent.Protocol),
                string.IsNullOrWhiteSpace(runtimeEvent.Tag) ? "<empty>" : runtimeEvent.Tag,
                FormatRemoteEndPoint(runtimeEvent.RemoteEndPoint));
            return;
        }

        _logger.LogDebug(
            runtimeEvent.Exception,
            "{Protocol} inbound connection failed from {RemoteEndPoint}.",
            FormatInboundProtocol(runtimeEvent.Protocol),
            FormatRemoteEndPoint(runtimeEvent.RemoteEndPoint));
    }

    private static bool HasActiveRuntime(NodeRuntimeSnapshot snapshot)
    {
        return snapshot.ProxyInbounds.HasListeners ||
               snapshot.TrojanPlan.TlsListeners.Count > 0 ||
               snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty).TlsListeners.Count > 0 ||
               snapshot.GetInboundPlanOrDefault(InboundProtocols.Vmess, VmessInboundRuntimePlan.Empty).TlsListeners.Count > 0;
    }

    private static Task WaitForCancellationAsync(CancellationToken cancellationToken)
        => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    private static string FormatInboundProtocol(string protocol)
        => InboundProtocols.Normalize(protocol) switch
        {
            InboundProtocols.Vless => "VLESS",
            InboundProtocols.Vmess => "VMess",
            _ => "Trojan"
        };

    private static string FormatProxyInboundProtocol(string protocol)
        => ProxyInboundProtocols.Normalize(protocol) switch
        {
            ProxyInboundProtocols.Http => "HTTP proxy inbound",
            _ => "SOCKS5 proxy inbound"
        };

    private static string FormatRemoteEndPoint(string? remoteEndPoint)
        => string.IsNullOrWhiteSpace(remoteEndPoint) ? "<unknown>" : remoteEndPoint;

    private static string FormatDisplayValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? "<empty>" : value;

    private sealed class RuntimeFaultSignal
    {
        private readonly object _sync = new();
        private TaskCompletionSource<int> _signal = CreateSignal();
        private int _version;

        public int Version
        {
            get
            {
                lock (_sync)
                {
                    return _version;
                }
            }
        }

        public void ReportFault()
        {
            lock (_sync)
            {
                _version++;
                var completed = _signal;
                _signal = CreateSignal();
                completed.TrySetResult(_version);
            }
        }

        public Task WaitForChangeAsync(int knownVersion, CancellationToken cancellationToken)
        {
            lock (_sync)
            {
                if (_version != knownVersion)
                {
                    return Task.CompletedTask;
                }

                return _signal.Task.WaitAsync(cancellationToken);
            }
        }

        private static TaskCompletionSource<int> CreateSignal()
            => new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed class PreparedRuntimePlan : IDisposable
    {
        private LoadedCertificatePackage? _certificatePackage;

        public PreparedRuntimePlan(RuntimePlan plan, LoadedCertificatePackage? certificatePackage)
        {
            Plan = plan;
            _certificatePackage = certificatePackage;
        }

        public RuntimePlan Plan { get; }

        public LoadedCertificatePackage? DetachCertificatePackage()
        {
            var certificatePackage = _certificatePackage;
            _certificatePackage = null;
            return certificatePackage;
        }

        public void Dispose()
        {
            _certificatePackage?.Dispose();
            _certificatePackage = null;
        }
    }
}

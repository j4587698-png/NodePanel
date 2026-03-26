using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class SocksLocalProxyListenerService : ReloadingInboundHostedServiceBase
{
    private readonly LocalProxyStateStore _localProxyStateStore;
    private readonly ILogger<SocksLocalProxyListenerService> _logger;
    private readonly Socks5LocalProxyServer _server;

    public SocksLocalProxyListenerService(
        RuntimeConfigStore runtimeConfigStore,
        CertificateStateStore certificateStateStore,
        LocalProxyStateStore localProxyStateStore,
        Socks5LocalProxyServer server,
        ILogger<SocksLocalProxyListenerService> logger)
        : base(runtimeConfigStore, certificateStateStore, logger)
    {
        _localProxyStateStore = localProxyStateStore;
        _server = server;
        _logger = logger;
    }

    protected override string HostDisplayName => "SOCKS5 local proxy";

    protected override bool HasActiveRuntime(NodeRuntimeSnapshot snapshot)
        => GetListeners(snapshot, LocalInboundProtocols.Socks).Count > 0;

    protected override bool RequiresCertificate(NodeRuntimeSnapshot snapshot) => false;

    protected override Task RunHostAsync(
        NodeRuntimeSnapshot snapshot,
        System.Security.Cryptography.X509Certificates.X509Certificate2? certificate,
        CancellationToken cancellationToken)
        => _server.RunAsync(
            new Socks5LocalProxyServerOptions
            {
                Listeners = GetListeners(snapshot, LocalInboundProtocols.Socks),
                Limits = CreateLimits(snapshot.Config.Limits),
                Callbacks = new LocalProxyServerCallbacks
                {
                    ListenerStarted = listener => ReportListenerStarted(LocalInboundProtocols.Socks, "socks5", listener, snapshot.Revision),
                    ConnectionError = context => _logger.LogDebug(
                        context.Exception,
                        "SOCKS5 local proxy connection failed on {InboundTag} from {RemoteEndPoint}.",
                        context.InboundTag,
                        context.RemoteEndPoint)
                }
            },
            cancellationToken);

    protected override void OnHostFault(NodeRuntimeSnapshot snapshot, Exception exception)
        => _localProxyStateStore.ReportHostFailure(
            LocalInboundProtocols.Socks,
            GetListeners(snapshot, LocalInboundProtocols.Socks),
            snapshot.Revision,
            exception.Message);

    protected override void OnHostUnexpectedStop(NodeRuntimeSnapshot snapshot)
        => _localProxyStateStore.ReportHostFailure(
            LocalInboundProtocols.Socks,
            GetListeners(snapshot, LocalInboundProtocols.Socks),
            snapshot.Revision,
            "SOCKS5 local proxy stopped unexpectedly.");

    private static IReadOnlyList<LocalProxyListenerDefinition> GetListeners(NodeRuntimeSnapshot snapshot, string protocol)
        => snapshot.Config.LocalInbounds
            .Where(inbound =>
                inbound.Enabled &&
                string.Equals(LocalInboundProtocols.Normalize(inbound.Protocol), protocol, StringComparison.Ordinal))
            .Select(static inbound => new LocalProxyListenerDefinition
            {
                Tag = inbound.Tag,
                Binding = new ListenerBinding(inbound.ListenAddress, inbound.Port),
                HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds
            })
            .ToArray();

    private static LocalProxyServerLimits CreateLimits(TrojanInboundLimits limits)
        => new()
        {
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds
        };

    private void LogListenerStart(string label, LocalProxyListenerDefinition listener, int revision)
    {
        _localProxyStateStore.ReportListenerStarted(LocalInboundProtocols.Socks, listener, revision);

        if (listener.Binding.IsUnix)
        {
            _logger.LogInformation(
                "{Listener} listening on unix:{Address} at revision {Revision}.",
                label,
                listener.Binding.ListenAddress,
                revision);
            return;
        }

        _logger.LogInformation(
            "{Listener} listening on {Address}:{Port} at revision {Revision}.",
            label,
            listener.Binding.ListenAddress,
            listener.Binding.Port,
            revision);
    }

    private void ReportListenerStarted(string protocol, string label, LocalProxyListenerDefinition listener, int revision)
        => LogListenerStart(label, listener, revision);
}

public sealed class HttpLocalProxyListenerService : ReloadingInboundHostedServiceBase
{
    private readonly LocalProxyStateStore _localProxyStateStore;
    private readonly HttpLocalProxyServer _server;
    private readonly ILogger<HttpLocalProxyListenerService> _logger;

    public HttpLocalProxyListenerService(
        RuntimeConfigStore runtimeConfigStore,
        CertificateStateStore certificateStateStore,
        LocalProxyStateStore localProxyStateStore,
        HttpLocalProxyServer server,
        ILogger<HttpLocalProxyListenerService> logger)
        : base(runtimeConfigStore, certificateStateStore, logger)
    {
        _localProxyStateStore = localProxyStateStore;
        _server = server;
        _logger = logger;
    }

    protected override string HostDisplayName => "HTTP local proxy";

    protected override bool HasActiveRuntime(NodeRuntimeSnapshot snapshot)
        => GetListeners(snapshot, LocalInboundProtocols.Http).Count > 0;

    protected override bool RequiresCertificate(NodeRuntimeSnapshot snapshot) => false;

    protected override Task RunHostAsync(
        NodeRuntimeSnapshot snapshot,
        System.Security.Cryptography.X509Certificates.X509Certificate2? certificate,
        CancellationToken cancellationToken)
        => _server.RunAsync(
            new HttpLocalProxyServerOptions
            {
                Listeners = GetListeners(snapshot, LocalInboundProtocols.Http),
                Limits = CreateLimits(snapshot.Config.Limits),
                Callbacks = new LocalProxyServerCallbacks
                {
                    ListenerStarted = listener => ReportListenerStarted(LocalInboundProtocols.Http, "http-proxy", listener, snapshot.Revision),
                    ConnectionError = context => _logger.LogDebug(
                        context.Exception,
                        "HTTP local proxy connection failed on {InboundTag} from {RemoteEndPoint}.",
                        context.InboundTag,
                        context.RemoteEndPoint)
                }
            },
            cancellationToken);

    protected override void OnHostFault(NodeRuntimeSnapshot snapshot, Exception exception)
        => _localProxyStateStore.ReportHostFailure(
            LocalInboundProtocols.Http,
            GetListeners(snapshot, LocalInboundProtocols.Http),
            snapshot.Revision,
            exception.Message);

    protected override void OnHostUnexpectedStop(NodeRuntimeSnapshot snapshot)
        => _localProxyStateStore.ReportHostFailure(
            LocalInboundProtocols.Http,
            GetListeners(snapshot, LocalInboundProtocols.Http),
            snapshot.Revision,
            "HTTP local proxy stopped unexpectedly.");

    private static IReadOnlyList<LocalProxyListenerDefinition> GetListeners(NodeRuntimeSnapshot snapshot, string protocol)
        => snapshot.Config.LocalInbounds
            .Where(inbound =>
                inbound.Enabled &&
                string.Equals(LocalInboundProtocols.Normalize(inbound.Protocol), protocol, StringComparison.Ordinal))
            .Select(static inbound => new LocalProxyListenerDefinition
            {
                Tag = inbound.Tag,
                Binding = new ListenerBinding(inbound.ListenAddress, inbound.Port),
                HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds
            })
            .ToArray();

    private static LocalProxyServerLimits CreateLimits(TrojanInboundLimits limits)
        => new()
        {
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds
        };

    private void LogListenerStart(string label, LocalProxyListenerDefinition listener, int revision)
    {
        _localProxyStateStore.ReportListenerStarted(LocalInboundProtocols.Http, listener, revision);

        if (listener.Binding.IsUnix)
        {
            _logger.LogInformation(
                "{Listener} listening on unix:{Address} at revision {Revision}.",
                label,
                listener.Binding.ListenAddress,
                revision);
            return;
        }

        _logger.LogInformation(
            "{Listener} listening on {Address}:{Port} at revision {Revision}.",
            label,
            listener.Binding.ListenAddress,
            listener.Binding.Port,
            revision);
    }

    private void ReportListenerStarted(string protocol, string label, LocalProxyListenerDefinition listener, int revision)
        => LogListenerStart(label, listener, revision);
}

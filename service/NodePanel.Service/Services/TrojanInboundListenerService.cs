using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class TrojanInboundListenerService : ReloadingInboundHostedServiceBase
{
    private readonly ILogger<TrojanInboundListenerService> _logger;
    private readonly TrojanInboundServer _trojanInboundServer;
    private readonly XrayRuntimeOptions _xrayRuntimeOptions;

    public TrojanInboundListenerService(
        RuntimeConfigStore runtimeConfigStore,
        CertificateStateStore certificateStateStore,
        TrojanInboundServer trojanInboundServer,
        XrayRuntimeOptions xrayRuntimeOptions,
        ILogger<TrojanInboundListenerService> logger)
        : base(runtimeConfigStore, certificateStateStore, logger)
    {
        _trojanInboundServer = trojanInboundServer;
        _xrayRuntimeOptions = xrayRuntimeOptions;
        _logger = logger;
    }

    protected override string HostDisplayName => "Trojan inbound server";

    protected override bool HasActiveRuntime(NodeRuntimeSnapshot snapshot)
        => snapshot.GetInboundPlanOrDefault(InboundProtocols.Trojan, TrojanInboundRuntimePlan.Empty).TlsListeners.Count > 0;

    protected override bool RequiresCertificate(NodeRuntimeSnapshot snapshot)
        => snapshot.GetInboundPlanOrDefault(InboundProtocols.Trojan, TrojanInboundRuntimePlan.Empty).RequiresCertificate;

    protected override Task RunHostAsync(
        NodeRuntimeSnapshot snapshot,
        System.Security.Cryptography.X509Certificates.X509Certificate2? certificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return _trojanInboundServer.RunAsync(CreateServerOptions(snapshot, certificate), cancellationToken);
    }

    private TrojanInboundServerOptions CreateServerOptions(
        NodeRuntimeSnapshot snapshot,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        => new()
        {
            Plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Trojan, TrojanInboundRuntimePlan.Empty),
            Limits = new TrojanInboundServerLimits
            {
                GlobalBytesPerSecond = snapshot.Config.Limits.GlobalBytesPerSecond,
                ConnectTimeoutSeconds = snapshot.Config.Limits.ConnectTimeoutSeconds,
                ConnectionIdleSeconds = snapshot.Config.Limits.ConnectionIdleSeconds,
                UplinkOnlySeconds = snapshot.Config.Limits.UplinkOnlySeconds,
                DownlinkOnlySeconds = snapshot.Config.Limits.DownlinkOnlySeconds
            },
            Tls = new TrojanInboundTlsOptions
            {
                Certificate = certificate,
                ServerNamePolicy = CreateServerNamePolicyOptions(snapshot.Config.Certificate),
                ClientHelloPolicy = CreateClientHelloPolicyOptions(snapshot.Config.Certificate.ClientHelloPolicy)
            },
            UseCone = _xrayRuntimeOptions.UseCone,
            Callbacks = new TrojanInboundServerCallbacks
            {
                ListenerStarted = listener => LogListenerStart(listener, snapshot.Revision),
                ClientHelloRejected = context => _logger.LogWarning(
                    "Rejected trojan inbound connection from {RemoteEndPoint} due to client hello policy '{Reason}' (SNI: {ServerName}, JA3: {Ja3Hash}).",
                    context.RemoteEndPoint,
                    string.IsNullOrWhiteSpace(context.Reason) ? "unknown" : context.Reason,
                    string.IsNullOrWhiteSpace(context.Metadata?.ServerName) ? "<empty>" : context.Metadata?.ServerName,
                    string.IsNullOrWhiteSpace(context.Metadata?.Ja3Hash) ? "<empty>" : context.Metadata?.Ja3Hash),
                UnknownServerNameRejected = context => _logger.LogWarning(
                    "Rejected trojan inbound connection from {RemoteEndPoint} due to unknown SNI '{ServerName}'.",
                    context.RemoteEndPoint,
                    string.IsNullOrWhiteSpace(context.RequestedServerName) ? "<empty>" : context.RequestedServerName),
                ConnectionError = context => _logger.LogDebug(
                    context.Exception,
                    "Trojan inbound connection failed from {RemoteEndPoint}.",
                    context.RemoteEndPoint)
            }
        };

    private static TrojanTlsServerNamePolicyOptions CreateServerNamePolicyOptions(CertificateOptions options)
        => new()
        {
            RejectUnknownServerName = options.RejectUnknownSni,
            ConfiguredServerNames = BuildConfiguredServerNames(options)
        };

    private static TrojanClientHelloPolicyRuntime CreateClientHelloPolicyOptions(TlsClientHelloPolicyConfig options)
        => new()
        {
            Enabled = options.Enabled,
            AllowedServerNames = options.AllowedServerNames,
            BlockedServerNames = options.BlockedServerNames,
            AllowedApplicationProtocols = options.AllowedApplicationProtocols,
            BlockedApplicationProtocols = options.BlockedApplicationProtocols,
            AllowedJa3 = options.AllowedJa3,
            BlockedJa3 = options.BlockedJa3
        };

    private static IReadOnlyList<string> BuildConfiguredServerNames(CertificateOptions options)
        => [.. new[] { options.Domain }.Concat(options.AltNames)];

    private void LogListenerStart(TrojanTlsListenerRuntime listener, int revision)
    {
        var transportLabel = listener.IsShared
            ? "trojan-tls+wss"
            : listener.WebSocketInbound is not null
                ? "trojan-wss"
                : "trojan-tls";

        if (listener.Binding.IsUnix)
        {
            _logger.LogInformation(
                "{Listener} listening on unix:{Address} at revision {Revision}.",
                transportLabel,
                listener.Binding.ListenAddress,
                revision);
            return;
        }

        _logger.LogInformation(
            "{Listener} listening on {Address}:{Port} at revision {Revision}.",
            transportLabel,
            listener.Binding.ListenAddress,
            listener.Binding.Port,
            revision);
    }
}

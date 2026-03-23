using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class VlessInboundListenerService : ReloadingInboundHostedServiceBase
{
    private readonly ILogger<VlessInboundListenerService> _logger;
    private readonly VlessInboundServer _vlessInboundServer;
    private readonly XrayRuntimeOptions _xrayRuntimeOptions;

    public VlessInboundListenerService(
        RuntimeConfigStore runtimeConfigStore,
        CertificateStateStore certificateStateStore,
        VlessInboundServer vlessInboundServer,
        XrayRuntimeOptions xrayRuntimeOptions,
        ILogger<VlessInboundListenerService> logger)
        : base(runtimeConfigStore, certificateStateStore, logger)
    {
        _vlessInboundServer = vlessInboundServer;
        _xrayRuntimeOptions = xrayRuntimeOptions;
        _logger = logger;
    }

    protected override string HostDisplayName => "VLESS inbound server";

    protected override bool HasActiveRuntime(NodeRuntimeSnapshot snapshot)
        => snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty).TlsListeners.Count > 0;

    protected override bool RequiresCertificate(NodeRuntimeSnapshot snapshot)
        => snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty).RequiresCertificate;

    protected override Task RunHostAsync(
        NodeRuntimeSnapshot snapshot,
        System.Security.Cryptography.X509Certificates.X509Certificate2? certificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return _vlessInboundServer.RunAsync(CreateServerOptions(snapshot, certificate), cancellationToken);
    }

    private VlessInboundServerOptions CreateServerOptions(
        NodeRuntimeSnapshot snapshot,
        System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        => new()
        {
            Plan = snapshot.GetInboundPlanOrDefault(InboundProtocols.Vless, VlessInboundRuntimePlan.Empty),
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
            Callbacks = new VlessInboundServerCallbacks
            {
                ListenerStarted = listener => LogListenerStart(listener, snapshot.Revision),
                ClientHelloRejected = context => _logger.LogWarning(
                    "Rejected VLESS inbound connection from {RemoteEndPoint} due to client hello policy '{Reason}' (SNI: {ServerName}, JA3: {Ja3Hash}).",
                    context.RemoteEndPoint,
                    string.IsNullOrWhiteSpace(context.Reason) ? "unknown" : context.Reason,
                    string.IsNullOrWhiteSpace(context.Metadata?.ServerName) ? "<empty>" : context.Metadata?.ServerName,
                    string.IsNullOrWhiteSpace(context.Metadata?.Ja3Hash) ? "<empty>" : context.Metadata?.Ja3Hash),
                UnknownServerNameRejected = context => _logger.LogWarning(
                    "Rejected VLESS inbound connection from {RemoteEndPoint} due to unknown SNI '{ServerName}'.",
                    context.RemoteEndPoint,
                    string.IsNullOrWhiteSpace(context.RequestedServerName) ? "<empty>" : context.RequestedServerName),
                ConnectionError = context => _logger.LogDebug(
                    context.Exception,
                    "VLESS inbound connection failed from {RemoteEndPoint}.",
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

    private void LogListenerStart(VlessTlsListenerRuntime listener, int revision)
    {
        var transportLabel = listener.IsShared
            ? "vless-tls+wss"
            : listener.WebSocketInbound is not null
                ? "vless-wss"
                : "vless-tls";

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

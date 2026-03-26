using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Acme;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;
using NodePanel.Service.Services;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Configuration.AddEnvironmentVariables();

builder.Services
    .AddOptions<NodePanelOptions>()
    .BindConfiguration(NodePanelOptions.SectionName);
builder.Services.AddSingleton(sp => ResolveNodePanelOptions(sp.GetRequiredService<IOptions<NodePanelOptions>>().Value, args));
builder.Services.AddSingleton(XrayRuntimeOptions.FromEnvironment());

builder.Services.AddSingleton<RuntimeConfigStore>();
builder.Services.AddSingleton<CertificateStateStore>();
builder.Services.AddSingleton<HostResourceTelemetryProvider>();
builder.Services.AddSingleton<LocalProxyStateStore>();
builder.Services.AddSingleton<PersistedNodeConfigStore>();
builder.Services.AddSingleton<CertificateRenewalSignal>();
builder.Services.AddSingleton<AcmeHttpChallengeStore>();
builder.Services.AddSingleton<UserStore>();
builder.Services.AddSingleton<RateLimiterRegistry>();
builder.Services.AddSingleton<TrafficRegistry>();
builder.Services.AddSingleton<SessionRegistry>();
builder.Services.AddSingleton<TrojanHandshakeReader>();
builder.Services.AddSingleton<VlessHandshakeReader>();
builder.Services.AddSingleton<VmessHandshakeReader>();
builder.Services.AddSingleton<TrojanUdpPacketReader>();
builder.Services.AddSingleton<TrojanUdpPacketWriter>();
builder.Services.AddSingleton<VlessUdpPacketReader>();
builder.Services.AddSingleton<VlessUdpPacketWriter>();
builder.Services.AddSingleton<TrojanOutboundClient>();
builder.Services.AddSingleton<ITrojanOutboundSettingsProvider>(sp => sp.GetRequiredService<RuntimeConfigStore>());
builder.Services.AddSingleton<IStrategyOutboundSettingsProvider>(sp => sp.GetRequiredService<RuntimeConfigStore>());
builder.Services.AddSingleton<IOutboundCommonSettingsProvider>(sp => sp.GetRequiredService<RuntimeConfigStore>());
builder.Services.AddSingleton<IDnsRuntimeSettingsProvider>(sp => sp.GetRequiredService<RuntimeConfigStore>());
builder.Services.AddSingleton<IDnsResolver>(sp => new RuntimeDnsResolver(sp.GetRequiredService<IDnsRuntimeSettingsProvider>()));
builder.Services.AddSingleton<IOutboundHandler, FreedomOutboundHandler>();
builder.Services.AddSingleton<IOutboundHandler, TrojanOutboundHandler>();
builder.Services.AddSingleton<StrategyOutboundProbeService>();
builder.Services.AddSingleton<IStrategyOutboundProbeService>(sp => sp.GetRequiredService<StrategyOutboundProbeService>());
builder.Services.AddSingleton<IOutboundHandler, SelectorOutboundHandler>();
builder.Services.AddSingleton<IOutboundHandler, UrlTestOutboundHandler>();
builder.Services.AddSingleton<IOutboundHandler, FallbackOutboundHandler>();
builder.Services.AddSingleton<IOutboundHandler, LoadBalanceOutboundHandler>();
builder.Services.AddSingleton<IOutboundRuntimePlanProvider>(sp => sp.GetRequiredService<RuntimeConfigStore>());
builder.Services.AddSingleton<IOutboundRouter, DefaultOutboundRouter>();
builder.Services.AddSingleton<IDispatcher, DefaultDispatcher>();
builder.Services.AddSingleton<RelayService>();
builder.Services.AddSingleton<Socks5LocalProxyServer>();
builder.Services.AddSingleton<HttpLocalProxyServer>();
builder.Services.AddSingleton<TrojanMuxInboundServer>();
builder.Services.AddSingleton<TrojanFallbackRelayService>();
builder.Services.AddSingleton<TrojanUdpAssociateRelay>();
builder.Services.AddSingleton<VlessUdpRelay>();
builder.Services.AddSingleton<VmessUdpRelay>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, TrojanInboundRuntimeCompiler>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, VlessInboundRuntimeCompiler>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, VmessInboundRuntimeCompiler>();
builder.Services.AddSingleton<ConfigOrchestrator>();
builder.Services.AddSingleton<TelemetryDeltaTracker>();
builder.Services.AddSingleton<TrojanInboundConnectionHandler>();
builder.Services.AddSingleton<VlessInboundConnectionHandler>();
builder.Services.AddSingleton<VmessInboundConnectionHandler>();
builder.Services.AddSingleton<TrojanInboundServer>();
builder.Services.AddSingleton<VlessInboundServer>();
builder.Services.AddSingleton<VmessInboundServer>();
builder.Services.AddSingleton<ManagedAcmeCertificateService>();

builder.Services.AddSingleton<ControlPlaneClientService>();
builder.Services.AddSingleton<IControlPlaneConnection>(sp => sp.GetRequiredService<ControlPlaneClientService>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<ControlPlaneClientService>());
builder.Services.AddHostedService<AcmeHttpChallengeListenerService>();
builder.Services.AddHostedService<TrojanInboundListenerService>();
builder.Services.AddHostedService<VlessInboundListenerService>();
builder.Services.AddHostedService<VmessInboundListenerService>();
builder.Services.AddHostedService<SocksLocalProxyListenerService>();
builder.Services.AddHostedService<HttpLocalProxyListenerService>();
builder.Services.AddHostedService<CertificateMaintenanceService>();
builder.Services.AddHostedService<TelemetryFlushService>();

var app = builder.Build();

var options = app.Services.GetRequiredService<NodePanelOptions>();
var persistedNodeConfigStore = app.Services.GetRequiredService<PersistedNodeConfigStore>();
var orchestrator = app.Services.GetRequiredService<ConfigOrchestrator>();
var persistedConfig = persistedNodeConfigStore.TryLoad();
if (persistedConfig is not null)
{
    orchestrator.ApplyBootstrap(persistedConfig.Config, persistedConfig.Revision);
}
else
{
    orchestrator.ApplyBootstrap(options.Bootstrap);
}

app.MapGet("/", () => "NodePanel");
app.MapGet("/healthz", () => "ok");
app.MapGet("/revision", (RuntimeConfigStore store) => store.GetSnapshot().Revision.ToString());
app.MapGet("/control-plane", GetControlPlaneDiagnostics);

app.Run();

static NodePanelOptions ResolveNodePanelOptions(NodePanelOptions options, string[] args)
{
    var panelUrl = FirstNonEmpty(
        GetArgumentValue(args, "--panel-url"),
        GetArgumentValue(args, "--control-plane-url"),
        Environment.GetEnvironmentVariable("NodePanel__PanelUrl"),
        Environment.GetEnvironmentVariable("NodePanel__ControlPlane__Url"),
        options.PanelUrl,
        options.ControlPlane.Url);

    var nodeId = FirstNonEmpty(
        GetArgumentValue(args, "--node-id"),
        Environment.GetEnvironmentVariable("NodePanel__Identity__NodeId"),
        options.Identity.NodeId);

    var accessToken = FirstNonEmpty(
        GetArgumentValue(args, "--panel-access-token"),
        GetArgumentValue(args, "--control-plane-access-token"),
        Environment.GetEnvironmentVariable("NodePanel__ControlPlane__AccessToken"),
        options.ControlPlane.AccessToken);

    var enabled = ResolveBoolean(
        options.ControlPlane.Enabled,
        GetArgumentValue(args, "--control-plane-enabled"),
        Environment.GetEnvironmentVariable("NodePanel__ControlPlane__Enabled"));

    if (!string.IsNullOrWhiteSpace(panelUrl))
    {
        enabled = true;
    }

    return new NodePanelOptions
    {
        PanelUrl = panelUrl,
        CachedConfigPath = FirstNonEmpty(
            Environment.GetEnvironmentVariable("NodePanel__CachedConfigPath"),
            options.CachedConfigPath),
        Identity = new NodeIdentityOptions
        {
            NodeId = nodeId
        },
        ControlPlane = new ControlPlaneOptions
        {
            Enabled = enabled,
            Url = panelUrl,
            AccessToken = accessToken,
            ConnectTimeoutSeconds = options.ControlPlane.ConnectTimeoutSeconds,
            HeartbeatIntervalSeconds = options.ControlPlane.HeartbeatIntervalSeconds,
            ReconnectDelaySeconds = options.ControlPlane.ReconnectDelaySeconds
        },
        Bootstrap = options.Bootstrap
    };
}

static string GetArgumentValue(string[] args, string key)
{
    foreach (var arg in args)
    {
        if (arg.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
        {
            return arg[(key.Length + 1)..];
        }
    }

    return string.Empty;
}

static string FirstNonEmpty(params string?[] values)
    => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

static bool ResolveBoolean(bool fallback, params string?[] values)
{
    foreach (var value in values)
    {
        if (bool.TryParse(value, out var result))
        {
            return result;
        }
    }

    return fallback;
}

static IResult GetControlPlaneDiagnostics(NodePanelOptions options, IControlPlaneConnection connection)
{
    var nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId;
    var json =
        "{" +
        $"\"enabled\":{ToJsonBoolean(options.ControlPlane.Enabled)}," +
        $"\"url\":{ToJsonString(options.ControlPlane.Url)}," +
        $"\"nodeId\":{ToJsonString(nodeId)}," +
        $"\"isConnected\":{ToJsonBoolean(connection.IsConnected)}" +
        "}";

    return Results.Text(json, "application/json");
}

static string ToJsonBoolean(bool value) => value ? "true" : "false";

static string ToJsonString(string? value)
{
    var text = value ?? string.Empty;
    return "\"" + text
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}

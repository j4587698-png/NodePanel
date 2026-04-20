using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Acme;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;
using NodePanel.Service.Services;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Configuration.AddEnvironmentVariables();

var serviceOptions = NodePanelOptionsLoader.Load(builder.Configuration, args);
builder.Services.AddSingleton(serviceOptions);
builder.Services.AddSingleton(XrayRuntimeOptions.FromEnvironment());

builder.Services.AddSingleton<RuntimeConfigStore>();
builder.Services.AddSingleton<AppliedRuntimeSnapshotStore>();
builder.Services.AddSingleton<CertificateStateStore>();
builder.Services.AddSingleton<HostResourceTelemetryProvider>();
builder.Services.AddSingleton<PersistedNodeConfigStore>();
builder.Services.AddSingleton<CertificateRenewalSignal>();
builder.Services.AddSingleton<AcmeHttpChallengeStore>();
builder.Services.AddSingleton<IRuntime, DefaultRuntime>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, DokodemoInboundRuntimeCompiler>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, TrojanInboundRuntimeCompiler>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, ShadowsocksInboundRuntimeCompiler>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, VlessInboundRuntimeCompiler>();
builder.Services.AddSingleton<IInboundProtocolRuntimeCompiler, VmessInboundRuntimeCompiler>();
builder.Services.AddSingleton<IOutboundProtocolRuntimeCompiler, BuiltinOutboundRuntimeCompiler>();
builder.Services.AddSingleton<IOutboundProtocolRuntimeCompiler, TrojanOutboundRuntimeCompiler>();
builder.Services.AddSingleton<IOutboundProtocolRuntimeCompiler, VlessOutboundRuntimeCompiler>();
builder.Services.AddSingleton<IOutboundProtocolRuntimeCompiler, VmessOutboundRuntimeCompiler>();
builder.Services.AddSingleton(
    sp => new ConfigOrchestrator(
        sp.GetRequiredService<RuntimeConfigStore>(),
        RuntimeCapabilities.SupportedOutboundProtocols,
        sp.GetServices<IInboundProtocolRuntimeCompiler>(),
        sp.GetServices<IOutboundProtocolRuntimeCompiler>(),
        sp.GetRequiredService<PersistedNodeConfigStore>(),
        sp.GetRequiredService<ILogger<ConfigOrchestrator>>()));
builder.Services.AddSingleton<TelemetryDeltaTracker>();
builder.Services.AddSingleton<ManagedAcmeCertificateService>();

builder.Services.AddSingleton<ControlPlaneClientService>();
builder.Services.AddSingleton<IControlPlaneConnection>(sp => sp.GetRequiredService<ControlPlaneClientService>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<ControlPlaneClientService>());
builder.Services.AddHostedService<AcmeHttpChallengeListenerService>();
builder.Services.AddHostedService<RuntimeLifecycleService>();
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
app.MapGet("/revision", (AppliedRuntimeSnapshotStore store) => store.GetSnapshot().Revision.ToString());
app.MapGet("/control-plane", GetControlPlaneDiagnostics);

app.Run();

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

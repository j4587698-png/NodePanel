using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;
using Microsoft.AspNetCore.Authentication.Cookies;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Configuration.AddEnvironmentVariables();
builder.WebHost.UseKestrelHttpsConfiguration();

var bootstrapPanelOptions = builder.Configuration.GetSection(PanelOptions.SectionName).Get<PanelOptions>() ?? new PanelOptions();
var panelHttpsRuntime = new PanelHttpsRuntime(bootstrapPanelOptions);
panelHttpsRuntime.LoadSnapshot();

var listenerBindings = PanelListenerBindingRules.Resolve(builder.Configuration);
if (!listenerBindings.HasConfiguredBindings)
{
    builder.WebHost.UseUrls(PanelListenerBindingRules.DefaultUrls);
    listenerBindings = PanelListenerBindingRules.ResolveDefaults();
}

panelHttpsRuntime.MarkListenerConfigured(listenerBindings.HttpsPort);
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.OnAuthenticate = (_, sslOptions) =>
        {
            var authenticationOptions = panelHttpsRuntime.CreateAuthenticationOptions();
            sslOptions.ServerCertificate = authenticationOptions.ServerCertificate;
            sslOptions.EnabledSslProtocols = authenticationOptions.EnabledSslProtocols;
        };
    });
});

builder.Services
    .AddOptions<PanelOptions>()
    .BindConfiguration(PanelOptions.SectionName);
builder.Services.AddSingleton(sp => sp.GetRequiredService<IOptions<PanelOptions>>().Value);

builder.Services.AddControllersWithViews(options =>
{
    options.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true;

    var messageProvider = options.ModelBindingMessageProvider;
    messageProvider.SetAttemptedValueIsInvalidAccessor((value, fieldName) => $"{fieldName} 的值“{value}”无效。");
    messageProvider.SetMissingBindRequiredValueAccessor(fieldName => $"缺少必填字段“{fieldName}”。");
    messageProvider.SetMissingKeyOrValueAccessor(() => "缺少必填项。");
    messageProvider.SetMissingRequestBodyRequiredValueAccessor(() => "请求内容不能为空。");
    messageProvider.SetNonPropertyAttemptedValueIsInvalidAccessor(value => $"值“{value}”无效。");
    messageProvider.SetNonPropertyUnknownValueIsInvalidAccessor(() => "提供的值无效。");
    messageProvider.SetUnknownValueIsInvalidAccessor(fieldName => $"字段“{fieldName}”的值无效。");
    messageProvider.SetValueIsInvalidAccessor(value => $"值“{value}”无效。");
    messageProvider.SetValueMustBeANumberAccessor(fieldName => $"字段“{fieldName}”必须是数字。");
    messageProvider.SetValueMustNotBeNullAccessor(fieldName => $"字段“{fieldName}”不能为空。");
});
builder.Services.AddHttpClient();
builder.Services.AddSingleton(panelHttpsRuntime);
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddSingleton<PanelSnapshotBuilder>();
builder.Services.AddSingleton<NodeConnectionRegistry>();
builder.Services.AddSingleton<ControlPlanePushService>();
builder.Services.AddSingleton<PanelAcmeHttpChallengeStore>();
builder.Services.AddSingleton<PanelMutationService>();
builder.Services.AddSingleton<PanelQueryService>();
builder.Services.AddSingleton<PanelAuthSettingsService>();
builder.Services.AddSingleton<PanelDnsChallengeService>();
builder.Services.AddSingleton<PanelCertificateProgressTracker>();
builder.Services.AddSingleton<PanelCertificateService>();
builder.Services.AddSingleton<PanelPublicUrlBuilder>();
builder.Services.AddSingleton<SubscriptionCatalogService>();
builder.Services.AddSingleton<SubscriptionProfileResolver>();
builder.Services.AddSingleton<SubscriptionRenderer>();
builder.Services.AddSingleton<UserPortalService>();
builder.Services.AddSingleton<EpayService>();
builder.Services.AddSingleton<EmailVerificationService>();
builder.Services.AddSingleton<SmtpEmailService>();

builder.Services.AddSingleton<NetworkAccountingService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<NetworkAccountingService>());
builder.Services.AddSingleton<TrafficResetService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<TrafficResetService>());
builder.Services.AddHostedService<PanelCertificateRenewalService>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/auth/login";
        options.LogoutPath = "/auth/logout";
        options.AccessDeniedPath = "/auth/accessdenied";
    });

var app = builder.Build();

app.Use(async (context, next) =>
{
    var db = context.RequestServices.GetRequiredService<DatabaseService>();
    var path = context.Request.Path;
    var isInstallPath = path.StartsWithSegments("/install");
    var isAcmeChallengePath = path.StartsWithSegments("/.well-known/acme-challenge");
    var isStaticFile = path.Value?.EndsWith(".css") == true || 
                       path.Value?.EndsWith(".js") == true || 
                       path.Value?.EndsWith(".ico") == true || 
                       path.StartsWithSegments("/css") || 
                       path.StartsWithSegments("/js") || 
                       path.StartsWithSegments("/lib") || 
                       path.StartsWithSegments("/webfonts");

    if (!db.IsConfigured && !isInstallPath && !isStaticFile && !isAcmeChallengePath)
    {
        context.Response.Redirect("/install");
        return;
    }

    if (db.IsConfigured && isInstallPath)
    {
        context.Response.Redirect("/");
        return;
    }

    await next();
});

app.Use(async (context, next) =>
{
    if (!context.Request.IsHttps && panelHttpsRuntime.ShouldRedirectHttp(context.Request.Path))
    {
        context.Response.Redirect(panelHttpsRuntime.BuildRedirectUri(context.Request).ToString(), permanent: true);
        return;
    }

    await next();
});

app.UseStaticFiles();
app.UseWebSockets();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => Results.Text("ok"));
app.MapGet("/", () => Results.Redirect("/admin"));
app.MapGet(
    "/.well-known/acme-challenge/{token}",
    (string token, PanelAcmeHttpChallengeStore store) =>
        store.TryGet(token, out var response)
            ? Results.Text(response, "text/plain", Encoding.ASCII)
            : Results.NotFound());

app.MapGet(
    "/api/admin/state",
    async (HttpContext context, PanelOptions options, PanelQueryService panelQueryService, CancellationToken cancellationToken) =>
    {
        if (!IsAdminAuthorized(context, options))
        {
            return Results.Unauthorized();
        }

        return Results.Ok(await panelQueryService.BuildStateViewAsync(cancellationToken));
    });

app.MapPut(
    "/api/admin/nodes/{nodeId}",
    async (
        string nodeId,
        UpsertNodeRequest request,
        HttpContext context,
        PanelOptions options,
        PanelMutationService panelMutationService,
        CancellationToken cancellationToken) =>
    {
        if (!IsAdminAuthorized(context, options))
        {
            return Results.Unauthorized();
        }

        var saved = await panelMutationService.SaveNodeAsync(nodeId, request, cancellationToken).ConfigureAwait(false);
        return Results.Ok(saved);
    });

app.MapPut(
    "/api/admin/users/{userId}",
    async (
        string userId,
        UpsertUserRequest request,
        HttpContext context,
        PanelOptions options,
        PanelMutationService panelMutationService,
        CancellationToken cancellationToken) =>
    {
        if (!IsAdminAuthorized(context, options))
        {
            return Results.Unauthorized();
        }

        var saved = await panelMutationService.SaveUserAsync(userId, request, cancellationToken).ConfigureAwait(false);
        return Results.Ok(saved);
    });

app.MapPost(
    "/api/admin/nodes/{nodeId}/certificate/renew",
    async (
        string nodeId,
        HttpContext context,
        PanelOptions options,
        PanelQueryService panelQueryService,
        PanelMutationService panelMutationService,
        CancellationToken cancellationToken) =>
    {
        if (!IsAdminAuthorized(context, options))
        {
            return Results.Unauthorized();
        }

        var node = await panelQueryService.FindNodeAsync(nodeId, cancellationToken);
        if (node is null)
        {
            return Results.NotFound(new { error = $"Node '{nodeId}' was not found." });
        }

        var certificateMode = CertificateModes.Normalize(node.Config.Certificate.Mode);
        if (certificateMode is not (CertificateModes.AcmeManaged or CertificateModes.AcmeExternal))
        {
            return Results.BadRequest(new { error = $"Node '{nodeId}' is not using an ACME certificate mode." });
        }

        var delivered = await panelMutationService
            .RequestCertificateRenewalAsync(nodeId, "admin-api", cancellationToken)
            .ConfigureAwait(false);

        return Results.Ok(new { nodeId, delivered, offlineAutoRenew = !delivered });
    });

app.MapGet(
    "/client/subscribe",
    async (string? token, string? flag, string? profile, HttpContext context, SubscriptionRenderer subscriptionRenderer, CancellationToken cancellationToken) =>
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Results.BadRequest(new { error = "Missing subscription token." });
        }

        var renderResult = await subscriptionRenderer.TryRenderAsync(token, flag, profile, context.Request.Headers["User-Agent"].ToString(), cancellationToken);
        if (!renderResult.Success)
        {
            return Results.NotFound(new { error = renderResult.Error });
        }

        var document = renderResult.Document;
        foreach (var header in document.Headers)
        {
            context.Response.Headers[header.Key] = header.Value;
        }

        if (!string.IsNullOrWhiteSpace(document.FileName))
        {
            context.Response.Headers.ContentDisposition =
                $"attachment; filename*=UTF-8''{Uri.EscapeDataString(document.FileName)}";
        }

        return Results.Text(document.Content, document.ContentType, Encoding.UTF8);
    });

app.Map(
    "/control/ws",
    async (
        HttpContext context,
        PanelOptions options,
        ILoggerFactory loggerFactory,
        DatabaseService db,
        NodeConnectionRegistry nodeConnectionRegistry,
        ControlPlanePushService controlPlanePushService) =>
    {
        var logger = loggerFactory.CreateLogger("NodeControlPlaneEndpoint");

        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("WebSocket request expected.").ConfigureAwait(false);
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        await using var session = new NodeControlPlaneSession(socket, loggerFactory.CreateLogger<NodeControlPlaneSession>());

        var envelope = await session.ReceiveAsync(context.RequestAborted).ConfigureAwait(false);
        if (envelope is null || !string.Equals(envelope.Type, ControlMessageTypes.NodeHello, StringComparison.Ordinal))
        {
            logger.LogWarning(
                "Rejected control plane WebSocket from {RemoteIp} because the first message was not node.hello.",
                context.Connection.RemoteIpAddress);
            await session.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Expected node.hello as the first message.", context.RequestAborted).ConfigureAwait(false);
            return;
        }

        var hello = JsonSerializer.Deserialize(envelope.Payload.GetRawText(), ControlPlaneJsonSerializerContext.Default.NodeHelloPayload);
        if (hello is null || string.IsNullOrWhiteSpace(hello.NodeId))
        {
            logger.LogWarning(
                "Rejected control plane WebSocket from {RemoteIp} because node.hello was invalid.",
                context.Connection.RemoteIpAddress);
            await session.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Invalid node.hello payload.", context.RequestAborted).ConfigureAwait(false);
            return;
        }

        var nodeId = hello.NodeId.Trim();
        if (!db.IsConfigured)
        {
            logger.LogWarning(
                "Rejected control plane WebSocket for node {NodeId} because the panel database is not configured.",
                nodeId);
            await session.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Backend database not configured.", context.RequestAborted).ConfigureAwait(false);
            return;
        }
        
        var exists = await db.FSql.Select<NodeEntity>().Where(item => item.NodeId == nodeId).AnyAsync(context.RequestAborted);
        if (!exists)
        {
            if (!options.AutoRegisterUnknownNodes)
            {
                logger.LogWarning("Rejected control plane WebSocket for unknown node {NodeId}.", nodeId);
                await session.CloseAsync(WebSocketCloseStatus.PolicyViolation, "Node is not registered.", context.RequestAborted).ConfigureAwait(false);
                return;
            }

            var node = new NodeEntity { NodeId = nodeId };
            await db.FSql.InsertOrUpdate<NodeEntity>().SetSource(node).ExecuteAffrowsAsync(context.RequestAborted);
        }

        var previous = nodeConnectionRegistry.Register(nodeId, session);
        logger.LogInformation(
            "Node {NodeId} connected to control plane from {RemoteIp}. Version={Version}, AppliedRevision={AppliedRevision}.",
            nodeId,
            context.Connection.RemoteIpAddress,
            hello.Version,
            hello.AppliedRevision);
        if (previous is not null && !ReferenceEquals(previous, session))
        {
            logger.LogInformation("Replacing an older control plane session for node {NodeId}.", nodeId);
            await previous.CloseAsync(WebSocketCloseStatus.NormalClosure, "Replaced by a newer session.", context.RequestAborted).ConfigureAwait(false);
            await previous.DisposeAsync().ConfigureAwait(false);
        }

        nodeConnectionRegistry.RecordHello(nodeId, hello.Version, hello.AppliedRevision);
        await controlPlanePushService.PushSnapshotAsync(nodeId, context.RequestAborted).ConfigureAwait(false);

        try
        {
            while (!context.RequestAborted.IsCancellationRequested)
            {
                var message = await session.ReceiveAsync(context.RequestAborted).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }

                switch (message.Type)
                {
                    case ControlMessageTypes.Heartbeat:
                    {
                        var payload = JsonSerializer.Deserialize(
                            message.Payload.GetRawText(),
                            ControlPlaneJsonSerializerContext.Default.HeartbeatPayload);
                        if (payload is not null)
                        {
                            nodeConnectionRegistry.RecordHeartbeat(nodeId, payload.Timestamp);
                        }

                        break;
                    }
                    case ControlMessageTypes.TelemetryBatch:
                    {
                        var payload = JsonSerializer.Deserialize(
                            message.Payload.GetRawText(),
                            ControlPlaneJsonSerializerContext.Default.TelemetryBatchPayload);
                        if (payload is not null)
                        {
                            nodeConnectionRegistry.RecordTelemetry(nodeId, payload);
                            var acc = context.RequestServices.GetRequiredService<NetworkAccountingService>();
                            acc.EnqueueTrafficDelta(nodeId, payload.Traffic);
                        }

                        break;
                    }
                    case ControlMessageTypes.ApplyResult:
                    {
                        var payload = JsonSerializer.Deserialize(
                            message.Payload.GetRawText(),
                            ControlPlaneJsonSerializerContext.Default.ApplyResultPayload);
                        if (payload is not null)
                        {
                            nodeConnectionRegistry.RecordApplyResult(nodeId, payload);
                        }

                        break;
                    }
                }
            }
        }
        catch (WebSocketException ex) when (!context.RequestAborted.IsCancellationRequested)
        {
            logger.LogInformation(ex, "Control plane WebSocket for node {NodeId} was closed unexpectedly.", nodeId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled control plane error for node {NodeId}.", nodeId);
            throw;
        }
        finally
        {
            nodeConnectionRegistry.Unregister(nodeId, session);
            logger.LogInformation("Node {NodeId} disconnected from control plane.", nodeId);
        }
    });

app.MapControllers();

await panelHttpsRuntime.RefreshAsync();
app.Run();

static bool IsAdminAuthorized(HttpContext context, PanelOptions options)
{
    if (string.IsNullOrWhiteSpace(options.AdminToken))
    {
        return true;
    }

    if (context.Request.Headers.TryGetValue("X-Panel-Token", out var headerToken) &&
        string.Equals(headerToken.ToString(), options.AdminToken, StringComparison.Ordinal))
    {
        return true;
    }

    if (context.Request.Query.TryGetValue("token", out var queryToken) &&
        string.Equals(queryToken.ToString(), options.AdminToken, StringComparison.Ordinal))
    {
        return true;
    }

    return false;
}

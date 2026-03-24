using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Panel.Controllers;

[Authorize(Roles = "Admin")]
[Route("admin")]
public sealed class DashboardController : Controller
{
    private readonly PanelCertificateService _panelCertificateService;
    private readonly PanelMutationService _panelMutationService;
    private readonly PanelProcessControl _panelProcessControl;
    private readonly PanelPublicUrlBuilder _publicUrlBuilder;
    private readonly PanelQueryService _panelQueryService;

    public DashboardController(
        PanelQueryService panelQueryService,
        PanelMutationService panelMutationService,
        PanelPublicUrlBuilder publicUrlBuilder,
        PanelCertificateService panelCertificateService,
        PanelProcessControl panelProcessControl)
    {
        _panelQueryService = panelQueryService;
        _panelMutationService = panelMutationService;
        _publicUrlBuilder = publicUrlBuilder;
        _panelCertificateService = panelCertificateService;
        _panelProcessControl = panelProcessControl;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
        => View(
            new DashboardPageViewModel
            {
                State = await _panelQueryService.BuildStateViewAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("orders")]
    public async Task<IActionResult> Orders(CancellationToken cancellationToken)
        => View(
            new DashboardPageViewModel
            {
                State = await _panelQueryService.BuildStateViewAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("users")]
    public async Task<IActionResult> Users(CancellationToken cancellationToken)
        => View(
            new DashboardPageViewModel
            {
                State = await _panelQueryService.BuildStateViewAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("nodes")]
    public async Task<IActionResult> Nodes(CancellationToken cancellationToken)
        => View(
            new DashboardPageViewModel
            {
                State = await _panelQueryService.BuildStateViewAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("plans")]
    public async Task<IActionResult> Plans(CancellationToken cancellationToken)
        => View(
            new DashboardPageViewModel
            {
                State = await _panelQueryService.BuildStateViewAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("settings")]
    public async Task<IActionResult> Settings(CancellationToken cancellationToken)
        => View(
            new DashboardPageViewModel
            {
                State = await _panelQueryService.BuildStateViewAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("certificates")]
    public async Task<IActionResult> Certificates(CancellationToken cancellationToken)
        => View(
            new CertificateListPageViewModel
            {
                Certificates = await _panelQueryService.GetCertificateViewsAsync(cancellationToken),
                PanelHttps = await _panelQueryService.GetPanelHttpsSettingsAsync(cancellationToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("certificates/new")]
    public IActionResult NewCertificate()
        => View(
            "Certificate",
            new CertificateEditorViewModel
            {
                Form = new PanelCertificateFormInput(),
                IsEditMode = false,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });

    [HttpGet("certificates/{certificateId}")]
    public async Task<IActionResult> Certificate(string certificateId, CancellationToken cancellationToken)
    {
        var certificate = await _panelQueryService.FindCertificateAsync(certificateId, cancellationToken);
        if (certificate is null)
        {
            TempData["StatusMessage"] = $"证书 {certificateId} 不存在。";
            return RedirectToAction(nameof(Certificates));
        }

        return View(
            new CertificateEditorViewModel
            {
                Form = PanelCertificateFormInput.FromRecord(certificate),
                IsEditMode = true,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
            });
    }

    [HttpPost("certificates/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveCertificate(PanelCertificateFormInput form, CancellationToken cancellationToken)
    {
        var requestValid = form.TryToRequest(out var request, out var configError);
        if (!ModelState.IsValid || !requestValid)
        {
            if (!string.IsNullOrWhiteSpace(configError))
            {
                ModelState.AddModelError(string.Empty, configError);
            }

            return View(
                "Certificate",
                new CertificateEditorViewModel
                {
                    Form = form,
                    IsEditMode = true,
                    StatusMessage = BuildValidationStatusMessage("证书配置校验失败", configError)
                });
        }

        var certificateId = NodeFormValueCodec.TrimOrEmpty(form.CertificateId);
        await _panelMutationService.SaveCertificateAsync(certificateId, request, cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = $"证书 {certificateId} 配置已保存。";
        return RedirectToAction(nameof(Certificate), new { certificateId });
    }

    [HttpPost("certificates/{certificateId}/renew")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RenewCertificate(string certificateId, string? returnUrl, CancellationToken cancellationToken)
    {
        var normalizedCertificateId = certificateId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedCertificateId))
        {
            TempData["StatusMessage"] = "证书 ID 不能为空。";
            return RedirectToLocalOrDefault(returnUrl, nameof(Certificates));
        }

        try
        {
            var record = await _panelCertificateService
                .RenewAsync(normalizedCertificateId, ignoreSchedule: true, cancellationToken)
                .ConfigureAwait(false);

            TempData["StatusMessage"] = record is null
                ? $"证书 {normalizedCertificateId} 不存在。"
                : $"证书 {normalizedCertificateId} 已签发/续签完成，并已向绑定节点重新下发。";
        }
        catch (Exception ex)
        {
            TempData["StatusMessage"] = $"证书 {normalizedCertificateId} 签发失败: {ex.Message}";
        }

        return RedirectToLocalOrDefault(returnUrl, nameof(Certificate), new { certificateId = normalizedCertificateId });
    }

    [HttpPost("certificates/panel-https/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SavePanelHttpsSettings(PanelHttpsSettingsFormInput panelHttps, CancellationToken cancellationToken)
    {
        var normalizedPanelHttps = panelHttps.Normalize();
        if (normalizedPanelHttps.Enabled)
        {
            if (string.IsNullOrWhiteSpace(normalizedPanelHttps.CertificateId))
            {
                ModelState.AddModelError(nameof(panelHttps.CertificateId), "启用 Panel HTTPS 时必须选择一张证书。");
            }
            else
            {
                var certificate = await _panelQueryService
                    .FindCertificateAsync(normalizedPanelHttps.CertificateId, cancellationToken)
                    .ConfigureAwait(false);

                if (certificate is null)
                {
                    ModelState.AddModelError(
                        nameof(panelHttps.CertificateId),
                        $"证书 {normalizedPanelHttps.CertificateId} 不存在。");
                }
                else if (string.IsNullOrWhiteSpace(certificate.PfxBase64))
                {
                    ModelState.AddModelError(
                        nameof(panelHttps.CertificateId),
                        $"证书 {normalizedPanelHttps.CertificateId} 还没有可用的 PFX 资产，请先完成签发/续签。");
                }
            }
        }

        if (!ModelState.IsValid)
        {
            return View(
                "Certificates",
                new CertificateListPageViewModel
                {
                    Certificates = await _panelQueryService.GetCertificateViewsAsync(cancellationToken),
                    PanelHttps = normalizedPanelHttps,
                    StatusMessage = BuildValidationStatusMessage("Panel HTTPS 设置校验失败")
                });
        }

        var currentSettings = await _panelQueryService.GetPanelHttpsSettingsAsync(cancellationToken).ConfigureAwait(false);
        var requiresRestart = normalizedPanelHttps.RequiresProcessRestart(currentSettings);

        await _panelMutationService.SavePanelHttpsSettingsAsync(normalizedPanelHttps, cancellationToken).ConfigureAwait(false);
        if (requiresRestart &&
            _panelProcessControl.TryScheduleRestart("Panel HTTPS listener configuration changed."))
        {
            return View(
                "Restarting",
                new PanelRestartingViewModel
                {
                    Title = "正在重启面板",
                    Message = "Panel HTTPS 监听配置已保存，面板进程正在重启以应用 80/443 直连监听。几秒后会自动返回证书页面。",
                    RedirectUrl = Url.Action(nameof(Certificates)) ?? "/admin/certificates"
                });
        }
        TempData["StatusMessage"] = requiresRestart
            ? "Panel HTTPS 设置已保存。首次启用或修改监听地址/端口需要重启面板进程。"
            : "Panel HTTPS 设置已保存。证书切换和 HTTP 跳转规则已立即生效。";
        return RedirectToAction(nameof(Certificates));
    }

    [HttpPost("settings/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveSettings([FromForm] Dictionary<string, string> settings, CancellationToken cancellationToken)
    {
        // 过滤空键
        var validSettings = settings
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Key))
            .ToDictionary(kv => kv.Key, kv => kv.Value ?? string.Empty);

        await _panelMutationService.SaveSettingsAsync(validSettings, cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = "系统设置已保存。";
        return RedirectToAction(nameof(Settings));
    }

    [HttpGet("nodes/new")]
    public async Task<IActionResult> NewNode(CancellationToken cancellationToken)
    {
        var certificates = await _panelQueryService.GetCertificatesAsync(cancellationToken);
        var form = new NodeFormInput
        {
            CertificateMode = certificates.Count > 0 ? CertificateModes.PanelDistributed : CertificateModes.AcmeManaged,
            PanelCertificateId = certificates.Count > 0 ? certificates[0].CertificateId : string.Empty,
            CertificateDomain = certificates.Count > 0 ? certificates[0].Domain : string.Empty
        };
        form.PrepareForEditView();

        return View(
            "Node",
            new NodeEditorViewModel
            {
                Form = form,
                IsEditMode = false,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty,
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken),
                AvailableCertificates = certificates
            });
    }

    [HttpGet("nodes/{nodeId}")]
    public async Task<IActionResult> Node(string nodeId, CancellationToken cancellationToken)
    {
        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
        var node = state.Nodes.FirstOrDefault(item => string.Equals(item.Definition.NodeId, nodeId, StringComparison.Ordinal));
        if (node is null)
        {
            TempData["StatusMessage"] = $"节点 {nodeId} 不存在。";
            return RedirectToAction(nameof(Index));
        }

        var form = NodeFormInput.FromRecord(node.Definition);
        form.PrepareForEditView();

        return View(
            new NodeEditorViewModel
            {
                Form = form,
                IsEditMode = true,
                Runtime = node.Runtime,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty,
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken),
                AvailableCertificates = await _panelQueryService.GetCertificatesAsync(cancellationToken)
            });
    }

    [HttpPost("nodes/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveNode(NodeFormInput form, CancellationToken cancellationToken)
    {
        var requestValid = form.TryToRequest(out var request, out var configError);
        if (!ModelState.IsValid || !requestValid)
        {
            form.PrepareForEditView();

            if (!string.IsNullOrWhiteSpace(configError))
            {
                ModelState.AddModelError(string.Empty, configError);
            }

            return View(
                "Node",
                new NodeEditorViewModel
                {
                    Form = form,
                    IsEditMode = true,
                    StatusMessage = BuildValidationStatusMessage("节点配置校验失败", configError),
                    AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken),
                    AvailableCertificates = await _panelQueryService.GetCertificatesAsync(cancellationToken)
                });
        }

        var nodeId = NodeFormValueCodec.TrimOrEmpty(form.NodeId);
        await _panelMutationService.SaveNodeAsync(nodeId, request, cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = $"节点 {nodeId} 已保存。";
        return RedirectToAction(nameof(Node), new { nodeId });
    }

    [HttpPost("nodes/{nodeId}/certificate/renew")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RenewNodeCertificate(string nodeId, string? returnUrl, CancellationToken cancellationToken)
    {
        var normalizedNodeId = nodeId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedNodeId))
        {
            TempData["StatusMessage"] = "节点 ID 不能为空。";
            return RedirectToLocalOrDefault(returnUrl, nameof(Index));
        }

        var node = await _panelQueryService.FindNodeAsync(normalizedNodeId, cancellationToken);
        if (node is null)
        {
            TempData["StatusMessage"] = $"节点 {normalizedNodeId} 不存在。";
            return RedirectToLocalOrDefault(returnUrl, nameof(Index));
        }

        var certificateMode = CertificateModes.Normalize(node.Config.Certificate.Mode);
        if (certificateMode is not (CertificateModes.AcmeManaged or CertificateModes.AcmeExternal))
        {
            TempData["StatusMessage"] = $"节点 {normalizedNodeId} 当前不是 ACME 证书模式，无法触发续签。";
            return RedirectToLocalOrDefault(returnUrl, nameof(Node), new { nodeId = normalizedNodeId });
        }

        var requestedBy = string.IsNullOrWhiteSpace(User.Identity?.Name) ? "panel-ui" : User.Identity!.Name!;
        var delivered = await _panelMutationService
            .RequestCertificateRenewalAsync(normalizedNodeId, requestedBy, cancellationToken)
            .ConfigureAwait(false);

        TempData["StatusMessage"] = delivered
            ? $"节点 {normalizedNodeId} 已下发立即续签请求。"
            : $"节点 {normalizedNodeId} 当前离线，无法立即下发续签；后端仍会按本地缓存配置自动续签。";

        return RedirectToLocalOrDefault(returnUrl, nameof(Node), new { nodeId = normalizedNodeId });
    }

    [HttpGet("users/new")]
    public async Task<IActionResult> NewUser(CancellationToken cancellationToken)
    {
        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
        return View(
            "User",
            new UserEditorViewModel
            {
                Form = new UserFormInput(),
                IsEditMode = false,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty,
                Plans = state.Plans,
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken)
            });
    }

    [HttpGet("users/{userId}")]
    public async Task<IActionResult> UserEditor(string userId, CancellationToken cancellationToken)
    {
        var user = await _panelQueryService.FindUserAsync(userId, cancellationToken);
        if (user is null)
        {
            TempData["StatusMessage"] = $"用户 {userId} 不存在。";
            return RedirectToAction(nameof(Index));
        }

        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);

        return View(
            new UserEditorViewModel
            {
                Form = UserFormInput.FromRecord(user),
                IsEditMode = true,
                PortalUrl = BuildPortalUrl(user.SubscriptionToken),
                SubscriptionUrl = BuildSubscriptionUrl(user.SubscriptionToken),
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty,
                Plans = state.Plans,
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken)
            });
    }

    [HttpPost("users/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveUser(UserFormInput form, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
            return View(
                "User",
                new UserEditorViewModel
                {
                    Form = form,
                    IsEditMode = true,
                    PortalUrl = BuildPortalUrl(form.SubscriptionToken),
                    SubscriptionUrl = BuildSubscriptionUrl(form.SubscriptionToken),
                    StatusMessage = BuildValidationStatusMessage("用户配置校验失败"),
                    Plans = state.Plans,
                    AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken)
                });
        }

        var userId = NodeFormValueCodec.TrimOrEmpty(form.UserId);
        var saved = await _panelMutationService.SaveUserAsync(userId, form.ToRequest(), cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = $"用户 {userId} 已保存。";
        return RedirectToAction(nameof(UserEditor), new { userId = saved.UserId });
    }

    [HttpPost("users/{userId}/apply-plan")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ApplyPlanToUser(string userId, string planId, string cycle, CancellationToken cancellationToken)
    {
        var normalizedUserId = userId?.Trim() ?? string.Empty;
        var normalizedPlanId = planId?.Trim() ?? string.Empty;

        var user = await _panelQueryService.FindUserAsync(normalizedUserId, cancellationToken);
        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
        var plan = state.Plans.FirstOrDefault(p => string.Equals(p.PlanId, normalizedPlanId, StringComparison.Ordinal));

        if (user is null || plan is null)
        {
            TempData["StatusMessage"] = "用户或套餐不存在。";
            return RedirectToAction(nameof(UserEditor), new { userId = normalizedUserId });
        }

        DateTimeOffset? targetExpiresAt = cycle switch
        {
            "month" => DateTimeOffset.UtcNow.AddDays(31),
            "quarter" => DateTimeOffset.UtcNow.AddDays(90),
            "half_year" => DateTimeOffset.UtcNow.AddDays(180),
            "year" => DateTimeOffset.UtcNow.AddDays(365),
            "one_time" => null,
            _ => DateTimeOffset.UtcNow.AddDays(31)
        };

        decimal amount = cycle switch
        {
            "month" => plan.MonthPrice ?? 0,
            "quarter" => plan.QuarterPrice ?? 0,
            "half_year" => plan.HalfYearPrice ?? 0,
            "year" => plan.YearPrice ?? 0,
            "one_time" => plan.OneTimePrice ?? 0,
            _ => 0
        };

        var request = new UpsertUserRequest
        {
            DisplayName = user.DisplayName,
            SubscriptionToken = user.SubscriptionToken,
            TrojanPassword = user.TrojanPassword,
            V2rayUuid = user.V2rayUuid,
            GroupId = plan.GroupId,
            Enabled = true,
            BytesPerSecond = user.BytesPerSecond,
            DeviceLimit = user.DeviceLimit,
            NodeIds = user.NodeIds,
            Subscription = user.Subscription with
            {
                PlanName = plan.Name,
                TransferEnableBytes = plan.TransferEnableBytes,
                ExpiresAt = targetExpiresAt
            }
        };

        await _panelMutationService.SaveUserAsync(normalizedUserId, request, cancellationToken).ConfigureAwait(false);
        await _panelMutationService.CreateOrderAsync(normalizedUserId, normalizedPlanId, cycle, amount, cancellationToken: cancellationToken).ConfigureAwait(false);

        TempData["StatusMessage"] = $"已成功为用户 {normalizedUserId} 应用套餐 {plan.PlanId} 并生成了对应订单。";
        return RedirectToAction(nameof(UserEditor), new { userId = normalizedUserId });
    }

    [HttpPost("users/{userId}/reset-traffic")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetUserTraffic(string userId, CancellationToken cancellationToken)
    {
        var normalizedUserId = userId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedUserId))
        {
            return RedirectToAction(nameof(Index));
        }

        await _panelMutationService.ResetUserTrafficAsync(normalizedUserId, cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = $"已重置用户 {normalizedUserId} 的流量。";
        return RedirectToAction(nameof(UserEditor), new { userId = normalizedUserId });
    }

    [HttpGet("plans/new")]
    public async Task<IActionResult> NewPlan(CancellationToken cancellationToken)
        => View(
            "Plan",
            new PlanEditorViewModel
            {
                Form = new PlanFormInput(),
                IsEditMode = false,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty,
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken)
            });

    [HttpGet("plans/{planId}")]
    public async Task<IActionResult> Plan(string planId, CancellationToken cancellationToken)
    {
        var state = await _panelQueryService.BuildStateViewAsync(cancellationToken);
        var plan = state.Plans.FirstOrDefault(item => string.Equals(item.PlanId, planId, StringComparison.Ordinal));
        if (plan is null)
        {
            TempData["StatusMessage"] = $"套餐 {planId} 不存在。";
            return RedirectToAction(nameof(Index));
        }

        return View(
            new PlanEditorViewModel
            {
                Form = PlanFormInput.FromRecord(plan),
                IsEditMode = true,
                StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty,
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken)
            });
    }

    [HttpPost("plans/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SavePlan(PlanFormInput form, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return View("Plan", new PlanEditorViewModel 
            { 
                Form = form, 
                IsEditMode = true, 
                StatusMessage = BuildValidationStatusMessage("套餐配置校验失败"), 
                AvailableGroups = await _panelQueryService.GetServerGroupsAsync(cancellationToken) 
            });
        }

        var planId = NodeFormValueCodec.TrimOrEmpty(form.PlanId);
        await _panelMutationService.SavePlanAsync(planId, form.ToRequest(), cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = $"套餐 {planId} 已保存。";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost("plans/{planId}/delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeletePlan(string planId, CancellationToken cancellationToken)
    {
        await _panelMutationService.DeletePlanAsync(NodeFormValueCodec.TrimOrEmpty(planId), cancellationToken).ConfigureAwait(false);
        TempData["StatusMessage"] = $"套餐 {planId} 已删除。";
        return RedirectToAction(nameof(Index));
    }

    private string BuildPortalUrl(string token)
        => string.IsNullOrWhiteSpace(token) ? string.Empty : _publicUrlBuilder.BuildPortalUrl(token, Request);

    private string BuildSubscriptionUrl(string token)
        => string.IsNullOrWhiteSpace(token) ? string.Empty : _publicUrlBuilder.BuildSubscriptionUrl(token, null, Request);

    private IActionResult RedirectToLocalOrDefault(string? returnUrl, string actionName, object? routeValues = null)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return LocalRedirect(returnUrl);
        }

        return RedirectToAction(actionName, routeValues)!;
    }

    private string BuildValidationStatusMessage(string title, string? configError = null)
    {
        if (!string.IsNullOrWhiteSpace(configError))
        {
            return $"{title}: {configError}";
        }

        var modelError = ModelState.Values
            .SelectMany(static entry => entry.Errors)
            .Select(static error => string.IsNullOrWhiteSpace(error.ErrorMessage) ? error.Exception?.Message : error.ErrorMessage)
            .FirstOrDefault(static message => !string.IsNullOrWhiteSpace(message));

        return string.IsNullOrWhiteSpace(modelError)
            ? $"{title}，请检查输入。"
            : $"{title}: {modelError}";
    }

    [HttpGet("tickets")]
    public async Task<IActionResult> Tickets(CancellationToken cancellationToken)
    {
        var model = await _panelQueryService.GetTicketsAsync(cancellationToken);
        return View(model);
    }
    
    [HttpGet("commissions")]
    public async Task<IActionResult> Commissions(CancellationToken cancellationToken)
    {
        var model = await _panelQueryService.GetCommissionLogsAsync(cancellationToken);
        return View(model);
    }

    [HttpGet("groups")]
    public async Task<IActionResult> ServerGroups(CancellationToken cancellationToken)
        => View(new ServerGroupsPageViewModel
        {
            Groups = await _panelQueryService.GetServerGroupsAsync(cancellationToken),
            StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty
        });

    [HttpGet("groups/new")]
    public IActionResult NewServerGroup()
        => View("ServerGroup", new ServerGroupEditorViewModel
        {
            Form = new ServerGroupFormInput(),
            IsEditMode = false
        });

    [HttpGet("groups/{groupId:int}")]
    public async Task<IActionResult> ServerGroup(int groupId, CancellationToken cancellationToken)
    {
        var groups = await _panelQueryService.GetServerGroupsAsync(cancellationToken);
        var group = groups.FirstOrDefault(g => g.GroupId == groupId);
        if (group == null)
        {
            TempData["StatusMessage"] = $"权限组 {groupId} 不存在。";
            return RedirectToAction(nameof(ServerGroups));
        }

        return View("ServerGroup", new ServerGroupEditorViewModel
        {
            Form = new ServerGroupFormInput { GroupId = group.GroupId, Name = group.Name },
            IsEditMode = true
        });
    }

    [HttpPost("groups/save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveServerGroup(ServerGroupFormInput form, CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
            return View("ServerGroup", new ServerGroupEditorViewModel { Form = form, IsEditMode = true, StatusMessage = "填写有误" });

        await _panelMutationService.SaveServerGroupAsync(form.GroupId, NodeFormValueCodec.TrimOrEmpty(form.Name), cancellationToken);
        TempData["StatusMessage"] = "权限组已保存。";
        return RedirectToAction(nameof(ServerGroups));
    }

    [HttpPost("groups/{groupId:int}/delete")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> DeleteServerGroup(int groupId, CancellationToken cancellationToken)
    {
        try 
        {
            await _panelMutationService.DeleteServerGroupAsync(groupId, cancellationToken);
            TempData["StatusMessage"] = "权限组已删除。";
        }
        catch (InvalidOperationException ex)
        {
            TempData["StatusMessage"] = ex.Message;
        }
        return RedirectToAction(nameof(ServerGroups));
    }
}

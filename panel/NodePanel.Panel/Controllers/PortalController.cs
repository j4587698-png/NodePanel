using Microsoft.AspNetCore.Mvc;
using NodePanel.Panel.Services;

namespace NodePanel.Panel.Controllers;

[Route("portal")]
public sealed class PortalController : Controller
{
    private readonly PanelMutationService _panelMutationService;
    private readonly PanelQueryService _panelQueryService;
    private readonly UserPortalService _userPortalService;

    public PortalController(
        UserPortalService userPortalService,
        PanelQueryService panelQueryService,
        PanelMutationService panelMutationService)
    {
        _userPortalService = userPortalService;
        _panelQueryService = panelQueryService;
        _panelMutationService = panelMutationService;
    }

    [HttpGet("")]
    [HttpGet("{token}")]
    public async Task<IActionResult> Index(string? token, CancellationToken cancellationToken)
    {
        var resolvedToken = string.IsNullOrWhiteSpace(token)
            ? Request.Query["token"].ToString()
            : token;

        if (string.IsNullOrWhiteSpace(resolvedToken))
        {
            var emptyModel = _userPortalService.BuildEmpty();
            emptyModel.StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty;
            return View(emptyModel);
        }

        var result = await _userPortalService.TryBuildAsync(resolvedToken, Request, cancellationToken);
        result.Model.StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty;
        return View(result.Model);
    }

    [HttpPost("reset-subscription-token")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ResetSubscriptionToken(string token, string returnTarget, CancellationToken cancellationToken)
    {
        var normalizedToken = token?.Trim() ?? string.Empty;
        var normalizedReturnTarget = returnTarget?.Trim() ?? string.Empty;

        if (string.IsNullOrWhiteSpace(normalizedToken))
        {
            TempData["StatusMessage"] = "订阅令牌不存在或已失效。";
            return string.Equals(normalizedReturnTarget, "user", StringComparison.OrdinalIgnoreCase)
                ? Redirect("/user")
                : RedirectToAction(nameof(Index));
        }

        var user = await _panelQueryService.FindUserBySubscriptionTokenAsync(normalizedToken, cancellationToken);
        if (user is null)
        {
            TempData["StatusMessage"] = "订阅令牌不存在或已失效。";
            return string.Equals(normalizedReturnTarget, "user", StringComparison.OrdinalIgnoreCase)
                ? Redirect("/user")
                : RedirectToAction(nameof(Index));
        }

        var updated = await _panelMutationService.ResetUserSubscriptionTokenAsync(user.UserId, cancellationToken);
        TempData["StatusMessage"] = "订阅令牌已重置，旧链接立即失效。";

        return string.Equals(normalizedReturnTarget, "user", StringComparison.OrdinalIgnoreCase)
            ? Redirect("/user")
            : RedirectToAction(nameof(Index), new { token = updated.SubscriptionToken });
    }
}

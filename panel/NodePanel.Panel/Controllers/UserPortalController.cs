using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Panel.Controllers;

[Authorize]
[Route("user")]
public sealed class UserPortalController : Controller
{
    private readonly UserPortalService _userPortalService;
    private readonly PanelMutationService _panelMutationService;

    public UserPortalController(UserPortalService userPortalService, PanelMutationService panelMutationService)
    {
        _userPortalService = userPortalService;
        _panelMutationService = panelMutationService;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken cancellationToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Redirect("/auth/login");
        }

        var result = await _userPortalService.TryBuildByUserIdAsync(userId, Request, cancellationToken);
        if (!result.Success)
        {
            return View("~/Views/Portal/Index.cshtml", _userPortalService.BuildEmpty());
        }

        return View("~/Views/Portal/Index.cshtml", result.Model);
    }

    [HttpGet("store")]
    public async Task<IActionResult> Store(CancellationToken cancellationToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Redirect("/auth/login");
        }

        var model = await _userPortalService.BuildStoreAsync(userId, cancellationToken);
        model.StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty;
        return View("~/Views/Portal/Store.cshtml", model);
    }

    [HttpPost("checkout")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Checkout(string planId, string cycle, CancellationToken cancellationToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Redirect("/auth/login");
        }

        var store = await _userPortalService.BuildStoreAsync(userId, cancellationToken);
        var plan = store.Plans.FirstOrDefault(p => string.Equals(p.PlanId, planId, StringComparison.Ordinal));
        if (plan is null)
        {
            TempData["StatusMessage"] = "套餐不存在。";
            return RedirectToAction(nameof(Store));
        }

        var price = PlanPresentation.GetCyclePrice(plan, cycle);
        if (!price.HasValue)
        {
            TempData["StatusMessage"] = "该周期选项无效。";
            return RedirectToAction(nameof(Store));
        }

        var amount = price.Value;
        var order = await _panelMutationService.CreateOrderAsync(userId, planId, cycle, amount, 0, cancellationToken);
        if (amount == 0m)
        {
            await _panelMutationService.CompleteOrderAsync(order.OrderId, cancellationToken);
            TempData["StatusMessage"] = string.Equals(cycle, "reset_price", StringComparison.Ordinal)
                ? "0 元流量重置包已立即生效。"
                : "0 元套餐已直接开通成功。";
            return RedirectToAction(nameof(Orders));
        }

        TempData["StatusMessage"] = "订单已创建，状态为待支付。请完成支付后生效。";
        return RedirectToAction(nameof(Orders));
    }

    [HttpGet("orders")]
    public async Task<IActionResult> Orders(CancellationToken cancellationToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Redirect("/auth/login");
        }

        var model = await _userPortalService.BuildOrdersAsync(userId, cancellationToken);
        model.StatusMessage = TempData["StatusMessage"]?.ToString() ?? string.Empty;
        return View("~/Views/Portal/Orders.cshtml", model);
    }

    [HttpPost("pay/{orderId}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Pay(string orderId, [FromServices] EpayService epayService, CancellationToken cancellationToken)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Redirect("/auth/login");
        }

        var model = await _userPortalService.BuildOrdersAsync(userId, cancellationToken);
        var order = model.Orders.FirstOrDefault(o => string.Equals(o.OrderId, orderId, StringComparison.Ordinal));

        if (order is null || order.Status == 1)
        {
            TempData["StatusMessage"] = order?.Status == 1 ? "订单已支付过。" : "无效的订单。";
            return RedirectToAction(nameof(Orders));
        }

        if (order.TotalAmount <= 0)
        {
            await _panelMutationService.CompleteOrderAsync(order.OrderId, cancellationToken);
            TempData["StatusMessage"] = "0 元订单已自动完成。";
            return RedirectToAction(nameof(Orders));
        }

        try
        {
            var returnUrl = Url.Action(nameof(Orders), "UserPortal", null, Request.Scheme) ?? string.Empty;
            var notifyUrl = Url.Action("EpayNotify", "Payment", null, Request.Scheme) ?? string.Empty;

            var paymentUrl = await epayService.GeneratePaymentUrlAsync(order.OrderId, order.TotalAmount, notifyUrl, returnUrl, cancellationToken);
            return Redirect(paymentUrl);
        }
        catch (InvalidOperationException)
        {
            TempData["StatusMessage"] = "支付网关未配置，请联系管理员。";
            return RedirectToAction(nameof(Orders));
        }
    }
}

using Microsoft.AspNetCore.Mvc;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Panel.Controllers;

[ApiController]
[Route("payment")]
public sealed class PaymentController : ControllerBase
{
    private readonly EpayService _epayService;
    private readonly PanelMutationService _mutation;

    public PaymentController(EpayService epayService, PanelMutationService mutation)
    {
        _epayService = epayService;
        _mutation = mutation;
    }

    [HttpGet("epay/notify")]
    [HttpPost("epay/notify")]
    public async Task<IActionResult> EpayNotify(CancellationToken cancellationToken)
    {
        IFormCollection form;
        if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType)
        {
            form = await Request.ReadFormAsync(cancellationToken);
        }
        else
        {
            var dict = Request.Query.ToDictionary(k => k.Key, v => new Microsoft.Extensions.Primitives.StringValues(v.Value.ToArray()));
            form = new FormCollection(dict);
        }
        
        if (!await _epayService.VerifySignatureAsync(form, cancellationToken))
        {
            return BadRequest("Invalid Signature");
        }

        var tradeStatus = form["trade_status"].ToString();
        // Some gateways omit trade_status on success, but if present it should be success
        if (tradeStatus == "TRADE_SUCCESS" || string.IsNullOrWhiteSpace(tradeStatus))
        {
            var orderId = form["out_trade_no"].ToString();
            if (!string.IsNullOrWhiteSpace(orderId))
            {
                await _mutation.CompleteOrderAsync(orderId, cancellationToken);
                return Content("success");
            }
        }

        return BadRequest("Trade not successful");
    }
}

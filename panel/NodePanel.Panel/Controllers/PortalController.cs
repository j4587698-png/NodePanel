using Microsoft.AspNetCore.Mvc;
using NodePanel.Panel.Services;

namespace NodePanel.Panel.Controllers;

[Route("portal")]
public sealed class PortalController : Controller
{
    private readonly UserPortalService _userPortalService;

    public PortalController(UserPortalService userPortalService)
    {
        _userPortalService = userPortalService;
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
            return View(_userPortalService.BuildEmpty());
        }

        var result = await _userPortalService.TryBuildAsync(resolvedToken, Request, cancellationToken);
        return View(result.Model);
    }
}

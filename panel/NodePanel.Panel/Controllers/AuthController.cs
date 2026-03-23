using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Panel.Controllers;

[Route("auth")]
public sealed class AuthController : Controller
{
    private readonly DatabaseService _db;

    public AuthController(DatabaseService db)
    {
        _db = db;
    }

    [HttpGet("login")]
    public IActionResult Login() => View(new LoginRequest());

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromForm] LoginRequest request)
    {
        if (!ModelState.IsValid) return View(request);

        var user = await _db.FSql.Select<UserEntity>().Where(u => u.Email == request.Email).FirstAsync();
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(request);
        }

        var hasher = new PasswordHasher<UserEntity>();
        var result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        if (result == PasswordVerificationResult.Failed)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View(request);
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.UserId),
            new Claim(ClaimTypes.Name, user.Email),
            new Claim("DisplayName", user.DisplayName)
        };

        if (user.IsAdmin)
        {
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
        }

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties
        {
            IsPersistent = request.RememberMe
        });

        if (user.IsAdmin)
            return Redirect("/admin");
            
        return Redirect("/user");
    }

    [HttpGet("register")]
    public IActionResult Register() => View(new RegisterRequest());

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromForm] RegisterRequest request)
    {
        if (!ModelState.IsValid) return View(request);

        var exists = await _db.FSql.Select<UserEntity>().Where(u => u.Email == request.Email).AnyAsync();
        if (exists)
        {
            ModelState.AddModelError(string.Empty, "Email already in use.");
            return View(request);
        }

        var user = new UserEntity
        {
            UserId = Guid.NewGuid().ToString("N"),
            Email = request.Email,
            DisplayName = request.Email.Split('@')[0],
            TrojanPassword = Guid.NewGuid().ToString("N"),
            V2rayUuid = Guid.NewGuid().ToString("D"),
            SubscriptionToken = Guid.NewGuid().ToString("N"),
            IsAdmin = false
        };

        if (!string.IsNullOrWhiteSpace(request.InviteCode))
        {
            var inviteCode = await _db.FSql.Select<InviteCodeEntity>().Where(c => c.Code == request.InviteCode).FirstAsync();
            if (inviteCode != null)
            {
                user.InviteUserId = inviteCode.UserId;
            }
        }

        var hasher = new PasswordHasher<UserEntity>();
        user.PasswordHash = hasher.HashPassword(user, request.Password);

        await _db.FSql.Insert(user).ExecuteAffrowsAsync();

        await _db.FSql.Insert(new InviteCodeEntity
        {
            Code = Guid.NewGuid().ToString("N").Substring(0, 8),
            UserId = user.UserId,
            CreatedAt = DateTimeOffset.UtcNow
        }).ExecuteAffrowsAsync();

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.UserId),
            new Claim(ClaimTypes.Name, user.Email),
            new Claim("DisplayName", user.DisplayName)
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        return Redirect("/user");
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}

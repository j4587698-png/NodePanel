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
    private const string InvalidLoginMessage = "登录失败，邮箱或密码错误。";
    private const string EmailAlreadyInUseMessage = "该邮箱已被注册。";
    private const string DisplayNameRequiredMessage = "用户名不能为空。";
    private const string RegistrationDisabledMessage = "当前未开放注册。";
    private const string PasswordResetDisabledMessage = "当前未开放密码重置。";

    private const string InviteCodeRequiredMessage = "当前注册需要邀请码。";
    private const string InviteCodeInvalidMessage = "邀请码无效或不存在。";

    private readonly DatabaseService _db;
    private readonly EmailVerificationService _emailVerificationService;
    private readonly PanelMutationService _panelMutationService;
    private readonly PanelAuthSettingsService _panelAuthSettingsService;
    private readonly SmtpEmailService _smtpEmailService;

    public AuthController(
        DatabaseService db,
        PanelAuthSettingsService panelAuthSettingsService,
        EmailVerificationService emailVerificationService,
        PanelMutationService panelMutationService,
        SmtpEmailService smtpEmailService)
    {
        _db = db;
        _panelAuthSettingsService = panelAuthSettingsService;
        _emailVerificationService = emailVerificationService;
        _panelMutationService = panelMutationService;
        _smtpEmailService = smtpEmailService;
    }

    [HttpGet("login")]
    public async Task<IActionResult> Login(CancellationToken cancellationToken)
        => View(await BuildLoginViewModelAsync(new LoginRequest(), cancellationToken).ConfigureAwait(false));

    [HttpPost("login")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login([FromForm] LoginRequest request, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        ApplyLoginViewModel(request, settings);
        if (!ModelState.IsValid) return View(request);

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(request.Email);
        var user = await _db.FSql.Select<UserEntity>().Where(u => u.Email == normalizedEmail).FirstAsync();
        if (user == null)
        {
            ModelState.AddModelError(string.Empty, InvalidLoginMessage);
            return View(request);
        }

        var hasher = new PasswordHasher<UserEntity>();
        var result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
        if (result == PasswordVerificationResult.Failed)
        {
            ModelState.AddModelError(string.Empty, InvalidLoginMessage);
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
    public async Task<IActionResult> Register(CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!settings.AllowRegistration)
        {
            TempData["StatusMessage"] = RegistrationDisabledMessage;
            return RedirectToAction(nameof(Login));
        }

        return View(await BuildRegisterViewModelAsync(new RegisterRequest(), settings, cancellationToken).ConfigureAwait(false));
    }

    [HttpPost("register/send-code")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendRegisterCode([FromForm] RegisterEmailCodeRequest request, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!settings.AllowRegistration)
        {
            TempData["StatusMessage"] = RegistrationDisabledMessage;
            return RedirectToAction(nameof(Login));
        }

        var model = await BuildRegisterViewModelAsync(
                new RegisterRequest
                {
                    DisplayName = request.DisplayName,
                    Email = request.Email,
                    InviteCode = request.InviteCode
                },
                settings,
                cancellationToken)
            .ConfigureAwait(false);

        if (!settings.IsRegistrationVerificationAvailable)
        {
            ModelState.AddModelError(string.Empty, "当前未启用注册邮箱验证码。");
            return View("Register", model);
        }

        if (!TryValidateModel(request))
        {
            return View("Register", model);
        }

        var inviteCodeValidation = await ResolveInviteCodeAsync(request.InviteCode, settings, cancellationToken).ConfigureAwait(false);
        if (!inviteCodeValidation.Success)
        {
            ModelState.AddModelError(nameof(request.InviteCode), inviteCodeValidation.ErrorMessage);
            return View("Register", model);
        }

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(request.Email);
        var exists = await _db.FSql.Select<UserEntity>().Where(u => u.Email == normalizedEmail).AnyAsync(cancellationToken);
        if (exists)
        {
            ModelState.AddModelError(nameof(request.Email), EmailAlreadyInUseMessage);
            return View("Register", model);
        }

        try
        {
            var code = await _emailVerificationService
                .IssueCodeAsync(normalizedEmail, EmailVerificationPurposes.Register, cancellationToken)
                .ConfigureAwait(false);

            await _smtpEmailService.SendAsync(
                    settings,
                    normalizedEmail,
                    string.Empty,
                    $"{settings.SiteName} 注册验证码",
                    $"您的注册验证码是：{code}\n\n验证码 10 分钟内有效，请勿泄露给他人。",
                    cancellationToken)
                .ConfigureAwait(false);

            model.StatusMessage = "验证码已发送，请检查邮箱。";
        }
        catch (Exception ex)
        {
            ModelState.AddModelError(string.Empty, $"验证码发送失败：{ex.Message}");
        }

        return View("Register", model);
    }

    [HttpPost("register")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Register([FromForm] RegisterRequest request, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!settings.AllowRegistration)
        {
            TempData["StatusMessage"] = RegistrationDisabledMessage;
            return RedirectToAction(nameof(Login));
        }

        ApplyRegisterViewModel(request, settings);
        if (!ModelState.IsValid) return View(request);

        var normalizedDisplayName = NodeFormValueCodec.TrimOrEmpty(request.DisplayName);
        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(request.Email);
        if (string.IsNullOrWhiteSpace(normalizedDisplayName))
        {
            ModelState.AddModelError(nameof(request.DisplayName), DisplayNameRequiredMessage);
            return View(request);
        }

        var inviteCodeValidation = await ResolveInviteCodeAsync(request.InviteCode, settings, cancellationToken).ConfigureAwait(false);
        if (!inviteCodeValidation.Success)
        {
            ModelState.AddModelError(nameof(request.InviteCode), inviteCodeValidation.ErrorMessage);
            return View(request);
        }

        if (settings.IsRegistrationVerificationAvailable)
        {
            var verified = await _emailVerificationService
                .VerifyCodeAsync(normalizedEmail, EmailVerificationPurposes.Register, request.VerificationCode, cancellationToken)
                .ConfigureAwait(false);
            if (!verified)
            {
                ModelState.AddModelError(nameof(request.VerificationCode), "验证码无效或已过期。");
                return View(request);
            }
        }

        var exists = await _db.FSql.Select<UserEntity>().Where(u => u.Email == normalizedEmail).AnyAsync();
        if (exists)
        {
            ModelState.AddModelError(string.Empty, EmailAlreadyInUseMessage);
            return View(request);
        }

        var user = new UserEntity
        {
            UserId = Guid.NewGuid().ToString("N"),
            Email = normalizedEmail,
            DisplayName = normalizedDisplayName,
            TrojanPassword = Guid.NewGuid().ToString("N"),
            V2rayUuid = Guid.NewGuid().ToString("D"),
            SubscriptionToken = Guid.NewGuid().ToString("N"),
            IsAdmin = false
        };

        if (inviteCodeValidation.InviteCode is not null)
        {
            user.InviteUserId = inviteCodeValidation.InviteCode.UserId;
            user.AppliedInviteCode = inviteCodeValidation.InviteCode.Code;
        }

        var hasher = new PasswordHasher<UserEntity>();
        user.PasswordHash = hasher.HashPassword(user, request.Password);

        await _db.FSql.Insert(user).ExecuteAffrowsAsync();
        await _panelMutationService.CreateInviteCodeAsync(user.UserId, settings.MaxInviteCodesPerUser, cancellationToken).ConfigureAwait(false);

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

    [HttpGet("forgot-password")]
    public async Task<IActionResult> ForgotPassword(CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!settings.IsPasswordResetAvailable)
        {
            TempData["StatusMessage"] = PasswordResetDisabledMessage;
            return RedirectToAction(nameof(Login));
        }

        return View(await BuildForgotPasswordViewModelAsync(new ForgotPasswordRequest(), cancellationToken).ConfigureAwait(false));
    }

    [HttpPost("forgot-password/send-code")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendForgotPasswordCode([FromForm] ForgotPasswordEmailCodeRequest request, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!settings.IsPasswordResetAvailable)
        {
            TempData["StatusMessage"] = PasswordResetDisabledMessage;
            return RedirectToAction(nameof(Login));
        }

        var model = await BuildForgotPasswordViewModelAsync(
                new ForgotPasswordRequest
                {
                    Email = request.Email
                },
                cancellationToken)
            .ConfigureAwait(false);

        if (!TryValidateModel(request))
        {
            return View("ForgotPassword", model);
        }

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(request.Email);
        var user = await _db.FSql.Select<UserEntity>().Where(item => item.Email == normalizedEmail).FirstAsync(cancellationToken);

        try
        {
            if (user is not null)
            {
                var code = await _emailVerificationService
                    .IssueCodeAsync(normalizedEmail, EmailVerificationPurposes.PasswordReset, cancellationToken)
                    .ConfigureAwait(false);

                await _smtpEmailService.SendAsync(
                        settings,
                        normalizedEmail,
                        user.DisplayName,
                        $"{settings.SiteName} 密码重置验证码",
                        $"您的密码重置验证码是：{code}\n\n验证码 10 分钟内有效，请勿泄露给他人。",
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            model.StatusMessage = "如果该邮箱已注册，验证码已发送，请检查邮箱。";
        }
        catch (Exception ex)
        {
            ModelState.AddModelError(string.Empty, $"验证码发送失败：{ex.Message}");
        }

        return View("ForgotPassword", model);
    }

    [HttpPost("forgot-password")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ForgotPassword([FromForm] ForgotPasswordRequest request, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        if (!settings.IsPasswordResetAvailable)
        {
            TempData["StatusMessage"] = PasswordResetDisabledMessage;
            return RedirectToAction(nameof(Login));
        }

        if (!ModelState.IsValid)
        {
            return View(await BuildForgotPasswordViewModelAsync(request, cancellationToken).ConfigureAwait(false));
        }

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(request.Email);
        var user = await _db.FSql.Select<UserEntity>().Where(item => item.Email == normalizedEmail).FirstAsync(cancellationToken);
        if (user is null)
        {
            ModelState.AddModelError(nameof(request.VerificationCode), "验证码无效或已过期。");
            return View(await BuildForgotPasswordViewModelAsync(request, cancellationToken).ConfigureAwait(false));
        }

        var verified = await _emailVerificationService
            .VerifyCodeAsync(normalizedEmail, EmailVerificationPurposes.PasswordReset, request.VerificationCode, cancellationToken)
            .ConfigureAwait(false);
        if (!verified)
        {
            ModelState.AddModelError(nameof(request.VerificationCode), "验证码无效或已过期。");
            return View(await BuildForgotPasswordViewModelAsync(request, cancellationToken).ConfigureAwait(false));
        }

        var hasher = new PasswordHasher<UserEntity>();
        user.PasswordHash = hasher.HashPassword(user, NodeFormValueCodec.TrimOrEmpty(request.Password));
        await _db.FSql.InsertOrUpdate<UserEntity>().SetSource(user).ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);

        TempData["StatusMessage"] = "密码已重置，请使用新密码登录。";
        return RedirectToAction(nameof(Login));
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    private async Task<LoginRequest> BuildLoginViewModelAsync(LoginRequest model, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        ApplyLoginViewModel(model, settings);
        return model;
    }

    private async Task<RegisterRequest> BuildRegisterViewModelAsync(RegisterRequest model, PanelAuthSettings settings, CancellationToken cancellationToken)
    {
        await Task.CompletedTask;
        ApplyRegisterViewModel(model, settings);
        return model;
    }

    private async Task<ForgotPasswordRequest> BuildForgotPasswordViewModelAsync(ForgotPasswordRequest model, CancellationToken cancellationToken)
    {
        var settings = await _panelAuthSettingsService.GetAsync(cancellationToken).ConfigureAwait(false);
        model.StatusMessage = string.IsNullOrWhiteSpace(model.StatusMessage)
            ? TempData["StatusMessage"]?.ToString() ?? string.Empty
            : model.StatusMessage;
        if (!settings.IsPasswordResetAvailable && string.IsNullOrWhiteSpace(model.StatusMessage))
        {
            model.StatusMessage = PasswordResetDisabledMessage;
        }

        return model;
    }

    private async Task<(bool Success, InviteCodeEntity? InviteCode, string ErrorMessage)> ResolveInviteCodeAsync(
        string? inviteCode,
        PanelAuthSettings settings,
        CancellationToken cancellationToken)
    {
        var normalizedInviteCode = NormalizeInviteCode(inviteCode);
        if (string.IsNullOrWhiteSpace(normalizedInviteCode))
        {
            return settings.RequireInviteCodeForRegistration
                ? (false, null, InviteCodeRequiredMessage)
                : (true, null, string.Empty);
        }

        var entity = await _db.FSql.Select<InviteCodeEntity>().Where(c => c.Code == normalizedInviteCode).FirstAsync(cancellationToken);
        return entity is null
            ? (false, null, InviteCodeInvalidMessage)
            : (true, entity, string.Empty);
    }

    private static string NormalizeInviteCode(string? inviteCode)
        => NodeFormValueCodec.TrimOrEmpty(inviteCode).ToLowerInvariant();

    private void ApplyLoginViewModel(LoginRequest model, PanelAuthSettings settings)
    {
        model.AllowRegistration = settings.AllowRegistration;
        model.AllowPasswordReset = settings.IsPasswordResetAvailable;
        model.StatusMessage = string.IsNullOrWhiteSpace(model.StatusMessage)
            ? TempData["StatusMessage"]?.ToString() ?? string.Empty
            : model.StatusMessage;
    }

    private void ApplyRegisterViewModel(RegisterRequest model, PanelAuthSettings settings)
    {
        model.RequireInviteCode = settings.RequireInviteCodeForRegistration;
        model.RequireEmailVerification = settings.IsRegistrationVerificationAvailable;
        model.StatusMessage = string.IsNullOrWhiteSpace(model.StatusMessage)
            ? TempData["StatusMessage"]?.ToString() ?? string.Empty
            : model.StatusMessage;
    }
}

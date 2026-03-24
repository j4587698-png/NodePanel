using System.ComponentModel.DataAnnotations;

namespace NodePanel.Panel.Models;

public sealed class LoginRequest
{
    [Required(ErrorMessage = "邮箱不能为空。")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确。")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "密码不能为空。")]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}

public sealed class RegisterRequest
{
    [Required(ErrorMessage = "邮箱不能为空。")]
    [EmailAddress(ErrorMessage = "邮箱格式不正确。")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "密码不能为空。")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "确认密码不能为空。")]
    [Compare(nameof(Password), ErrorMessage = "两次输入的密码不一致。")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public string InviteCode { get; set; } = string.Empty;
}

using System.ComponentModel.DataAnnotations;

namespace NodePanel.Panel.Models;

public sealed class InstallRequest
{
    [Required(ErrorMessage = "数据库类型不能为空。")]
    public string DbType { get; set; } = "sqlite";

    public string? DbHost { get; set; } = "127.0.0.1";
    public string? DbPort { get; set; } = "3306";
    
    [Required(ErrorMessage = "数据库名称不能为空。")]
    public string DbName { get; set; } = "server.db";
    
    public string? DbUser { get; set; } = "root";
    public string? DbPassword { get; set; } = "";

    [Required(ErrorMessage = "管理员用户名不能为空。")]
    public string AdminDisplayName { get; set; } = string.Empty;

    [Required(ErrorMessage = "管理员邮箱不能为空。")]
    public string AdminEmail { get; set; } = string.Empty;

    [Required(ErrorMessage = "管理员密码不能为空。")]
    public string AdminPassword { get; set; } = string.Empty;
}

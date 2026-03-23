using System.ComponentModel.DataAnnotations;

namespace NodePanel.Panel.Models;

public sealed class InstallRequest
{
    [Required]
    public string DbType { get; set; } = "sqlite";

    public string? DbHost { get; set; } = "127.0.0.1";
    public string? DbPort { get; set; } = "3306";
    
    [Required]
    public string DbName { get; set; } = "server.db";
    
    public string? DbUser { get; set; } = "root";
    public string? DbPassword { get; set; } = "";

    [Required]
    public string AdminEmail { get; set; } = string.Empty;

    [Required]
    public string AdminPassword { get; set; } = string.Empty;
}

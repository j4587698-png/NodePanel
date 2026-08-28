using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;
using FreeSql;
using Microsoft.AspNetCore.Identity;

namespace NodePanel.Panel.Controllers;

[Route("install")]
public class InstallController : Controller
{
    private readonly DatabaseService _db;
    private readonly ILogger<InstallController> _logger;
    private readonly IWebHostEnvironment _env;
    private readonly string _dataDirectory;

    public InstallController(DatabaseService db, ILogger<InstallController> logger, IWebHostEnvironment env, IConfiguration configuration)
    {
        _db = db;
        _logger = logger;
        _env = env;
        _dataDirectory = ResolveDataDirectory(configuration["Panel:DataFilePath"]);
    }

    [HttpGet]
    public IActionResult Index()
    {
        if (_db.IsConfigured)
        {
            return Redirect("/");
        }

        return View(new InstallRequest());
    }

    private static string ResolveDataDirectory(string? dataFilePath)
    {
        if (!string.IsNullOrWhiteSpace(dataFilePath) && Path.IsPathRooted(dataFilePath))
        {
            return Path.GetDirectoryName(dataFilePath) ?? AppContext.BaseDirectory;
        }

        return AppContext.BaseDirectory;
    }

    [HttpPost]
    public async Task<IActionResult> Index([FromForm] InstallRequest request)
    {
        if (_db.IsConfigured)
        {
            return Redirect("/");
        }

        if (!ModelState.IsValid)
        {
            return View(request);
        }

        try
        {
            // 1. Test connection
            var normalizedDbType = NodeFormValueCodec.TrimOrEmpty(request.DbType);
            var normalizedDbName = NodeFormValueCodec.TrimOrEmpty(request.DbName);
            var normalizedAdminDisplayName = NodeFormValueCodec.TrimOrEmpty(request.AdminDisplayName);
            var normalizedAdminEmail = NodeFormValueCodec.TrimOrEmpty(request.AdminEmail);
            if (string.IsNullOrWhiteSpace(normalizedAdminDisplayName))
            {
                ModelState.AddModelError(nameof(request.AdminDisplayName), "管理员用户名不能为空。");
                return View(request);
            }

            var dataType = DataType.Sqlite;
            var connectionString = $"Data Source={Path.Combine(_dataDirectory, normalizedDbName)}";

            if (string.Equals(normalizedDbType, "mysql", StringComparison.OrdinalIgnoreCase))
            {
                dataType = DataType.MySql;
                connectionString = $"Server={NodeFormValueCodec.TrimOrEmpty(request.DbHost)};Port={NodeFormValueCodec.TrimOrEmpty(request.DbPort)};Database={normalizedDbName};Uid={NodeFormValueCodec.TrimOrEmpty(request.DbUser)};Pwd={NodeFormValueCodec.TrimOrEmpty(request.DbPassword)};";
            }
            else if (string.Equals(normalizedDbType, "postgresql", StringComparison.OrdinalIgnoreCase))
            {
                dataType = DataType.PostgreSQL;
                connectionString = $"Host={NodeFormValueCodec.TrimOrEmpty(request.DbHost)};Port={NodeFormValueCodec.TrimOrEmpty(request.DbPort)};Database={normalizedDbName};Username={NodeFormValueCodec.TrimOrEmpty(request.DbUser)};Password={NodeFormValueCodec.TrimOrEmpty(request.DbPassword)};";
            }

            using var testFsql = new FreeSqlBuilder()
                .UseConnectionString(dataType, connectionString)
                .UseAutoSyncStructure(true)
                .Build();

            // 2. Sync structure
            testFsql.CodeFirst.SyncStructure<UserEntity>();
            testFsql.CodeFirst.SyncStructure<NodeEntity>();
            testFsql.CodeFirst.SyncStructure<PlanEntity>();
            testFsql.CodeFirst.SyncStructure<TrafficRecordEntity>();
            testFsql.CodeFirst.SyncStructure<EmailVerificationCodeEntity>();

            // 3. Insert temp admin if not exists
            var adminExists = await testFsql.Select<UserEntity>().Where(u => u.Email == normalizedAdminEmail).AnyAsync();
            if (!adminExists)
            {
                var hasher = new PasswordHasher<UserEntity>();
                var admin = new UserEntity
                {
                    UserId = Guid.NewGuid().ToString("N"),
                    Email = normalizedAdminEmail,
                    IsAdmin = true,
                    DisplayName = normalizedAdminDisplayName,
                    TrojanPassword = Guid.NewGuid().ToString("N"),
                    V2rayUuid = Guid.NewGuid().ToString("D"),
                    ShadowsocksCipher = ShadowsocksCipherTypes.ChaCha20Poly1305,
                    ShadowsocksPassword = Guid.NewGuid().ToString("N"),
                    SubscriptionToken = Guid.NewGuid().ToString("N")
                };
                
                admin.PasswordHash = hasher.HashPassword(admin, NodeFormValueCodec.TrimOrEmpty(request.AdminPassword));
                
                await testFsql.Insert(admin).ExecuteAffrowsAsync();
            }

            // 4. Save runtime configuration to the mounted data volume so it
            //    survives container restarts, instead of the immutable image appsettings.json.
            var appSettingsPath = Path.Combine(_dataDirectory, "panel.settings.json");
            var raw = System.IO.File.Exists(appSettingsPath) ? await System.IO.File.ReadAllTextAsync(appSettingsPath) : string.Empty;
            if (string.IsNullOrWhiteSpace(raw))
            {
                raw = "{}";
            }

            var json = raw;
            
            var jsonObj = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }) as JsonObject ?? new JsonObject();
            if (jsonObj["Panel"] == null) jsonObj["Panel"] = new JsonObject();
            
            jsonObj["Panel"]!["DbType"] = normalizedDbType;
            jsonObj["Panel"]!["DbConnectionString"] = connectionString;

            var options = new JsonSerializerOptions { WriteIndented = true };
            await System.IO.File.WriteAllTextAsync(appSettingsPath, jsonObj.ToJsonString(options));

            // Give the appsettings reload token a moment to take effect
            await Task.Delay(1000);

            return RedirectToAction("Index", "Dashboard"); // Temporarily go to Dashboard, auth logic added later
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Installation failed.");
            ModelState.AddModelError("", $"Installation failed: {ex.Message}");
            return View(request);
        }
    }
}

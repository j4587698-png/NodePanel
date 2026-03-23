using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
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

    public InstallController(DatabaseService db, ILogger<InstallController> logger, IWebHostEnvironment env)
    {
        _db = db;
        _logger = logger;
        _env = env;
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
            var dataType = DataType.Sqlite;
            var connectionString = $"Data Source={request.DbName}";

            if (request.DbType.Equals("mysql", StringComparison.OrdinalIgnoreCase))
            {
                dataType = DataType.MySql;
                connectionString = $"Server={request.DbHost};Port={request.DbPort};Database={request.DbName};Uid={request.DbUser};Pwd={request.DbPassword};";
            }
            else if (request.DbType.Equals("postgresql", StringComparison.OrdinalIgnoreCase))
            {
                dataType = DataType.PostgreSQL;
                connectionString = $"Host={request.DbHost};Port={request.DbPort};Database={request.DbName};Username={request.DbUser};Password={request.DbPassword};";
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

            // 3. Insert temp admin if not exists
            var adminExists = await testFsql.Select<UserEntity>().Where(u => u.Email == request.AdminEmail).AnyAsync();
            if (!adminExists)
            {
                var hasher = new PasswordHasher<UserEntity>();
                var admin = new UserEntity
                {
                    UserId = Guid.NewGuid().ToString("N"),
                    Email = request.AdminEmail,
                    IsAdmin = true,
                    DisplayName = "Administrator",
                    TrojanPassword = Guid.NewGuid().ToString("N"),
                    V2rayUuid = Guid.NewGuid().ToString("D"),
                    SubscriptionToken = Guid.NewGuid().ToString("N")
                };
                
                admin.PasswordHash = hasher.HashPassword(admin, request.AdminPassword);
                
                await testFsql.Insert(admin).ExecuteAffrowsAsync();
            }

            // 4. Save to appsettings.json
            var appSettingsPath = Path.Combine(_env.ContentRootPath, "appsettings.json");
            var json = System.IO.File.Exists(appSettingsPath) ? await System.IO.File.ReadAllTextAsync(appSettingsPath) : "{}";
            
            var jsonObj = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }) as JsonObject ?? new JsonObject();
            if (jsonObj["Panel"] == null) jsonObj["Panel"] = new JsonObject();
            
            jsonObj["Panel"]!["DbType"] = request.DbType;
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

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class AuthSettingsTests
{
    [Fact]
    public void PanelAuthSettings_from_settings_uses_expected_defaults()
    {
        var settings = PanelAuthSettings.FromSettings(new Dictionary<string, string>(StringComparer.Ordinal));

        Assert.Equal("NodePanel", settings.SiteName);
        Assert.True(settings.AllowRegistration);
        Assert.False(settings.RequireInviteCodeForRegistration);
        Assert.Equal(1, settings.MaxInviteCodesPerUser);
        Assert.False(settings.RequireRegisterEmailVerification);
        Assert.False(settings.AllowPasswordResetByEmail);
        Assert.False(settings.HasSmtpConfiguration);
        Assert.False(settings.IsRegistrationVerificationAvailable);
        Assert.False(settings.IsPasswordResetAvailable);
    }

    [Fact]
    public void PanelAuthSettings_from_settings_exposes_email_features_when_smtp_is_complete()
    {
        var settings = PanelAuthSettings.FromSettings(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [PanelAuthSettingKeys.AllowRegistration] = "true",
                [PanelAuthSettingKeys.RequireInviteCodeForRegistration] = "true",
                [PanelAuthSettingKeys.MaxInviteCodesPerUser] = "5",
                [PanelAuthSettingKeys.RequireRegisterEmailVerification] = "true",
                [PanelAuthSettingKeys.AllowPasswordResetByEmail] = "true",
                [PanelAuthSettingKeys.SmtpHost] = "smtp.example.com",
                [PanelAuthSettingKeys.SmtpPort] = "465",
                [PanelAuthSettingKeys.SmtpUsername] = "mailer@example.com",
                [PanelAuthSettingKeys.SmtpPassword] = "secret",
                [PanelAuthSettingKeys.SmtpFromAddress] = "mailer@example.com",
                [PanelAuthSettingKeys.SmtpFromName] = "NodePanel",
                [PanelAuthSettingKeys.SmtpEnableSsl] = "true"
            });

        Assert.True(settings.RequireInviteCodeForRegistration);
        Assert.Equal(5, settings.MaxInviteCodesPerUser);
        Assert.True(settings.HasSmtpConfiguration);
        Assert.True(settings.IsRegistrationVerificationAvailable);
        Assert.True(settings.IsPasswordResetAvailable);
    }

    [Fact]
    public void PanelAuthSettings_validate_requires_smtp_before_enabling_email_flows()
    {
        var errors = PanelAuthSettings.Validate(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [PanelAuthSettingKeys.AllowRegistration] = "true",
                [PanelAuthSettingKeys.RequireRegisterEmailVerification] = "true",
                [PanelAuthSettingKeys.AllowPasswordResetByEmail] = "true"
            });

        Assert.Equal(2, errors.Count);
    }

    [Fact]
    public void PanelAuthSettings_validate_rejects_negative_invite_code_limit()
    {
        var errors = PanelAuthSettings.Validate(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [PanelAuthSettingKeys.MaxInviteCodesPerUser] = "-1"
            });

        Assert.Single(errors);
    }

    [Fact]
    public async Task EmailVerificationService_issue_and_verify_code_once()
    {
        using var harness = new EmailVerificationHarness();
        var service = new EmailVerificationService(harness.DatabaseService);

        var code = await service.IssueCodeAsync("user@example.com", EmailVerificationPurposes.Register, CancellationToken.None);

        Assert.True(await service.VerifyCodeAsync("user@example.com", EmailVerificationPurposes.Register, code, CancellationToken.None));
        Assert.False(await service.VerifyCodeAsync("user@example.com", EmailVerificationPurposes.Register, code, CancellationToken.None));
    }

    [Fact]
    public async Task EmailVerificationService_new_code_replaces_previous_one()
    {
        using var harness = new EmailVerificationHarness();
        var service = new EmailVerificationService(harness.DatabaseService);

        var firstCode = await service.IssueCodeAsync("user@example.com", EmailVerificationPurposes.PasswordReset, CancellationToken.None);
        var secondCode = await service.IssueCodeAsync("user@example.com", EmailVerificationPurposes.PasswordReset, CancellationToken.None);

        Assert.NotEqual(firstCode, secondCode);
        Assert.False(await service.VerifyCodeAsync("user@example.com", EmailVerificationPurposes.PasswordReset, firstCode, CancellationToken.None));
        Assert.True(await service.VerifyCodeAsync("user@example.com", EmailVerificationPurposes.PasswordReset, secondCode, CancellationToken.None));
    }

    [Fact]
    public async Task Password_reset_updates_only_the_selected_users_password()
    {
        using var harness = new EmailVerificationHarness();
        var db = harness.DatabaseService.FSql;
        var user = new UserEntity { UserId = "admin", Email = "admin@example.com", IsAdmin = true, DisplayName = "Admin", PasswordHash = "old" };
        var other = new UserEntity { UserId = "other", Email = "other@example.com", PasswordHash = "other-hash" };
        await db.Insert(user).ExecuteAffrowsAsync();
        await db.Insert(other).ExecuteAffrowsAsync();
        var passwords = new Queue<string>(["new password", "new password"]);
        using var output = new StringWriter();
        using var error = new StringWriter();

        var result = await PanelPasswordResetCommand.RunAsync(
            db, new StringReader(" admin@example.com "), output, error, passwords.Dequeue);

        var updated = await db.Select<UserEntity>().Where(item => item.UserId == user.UserId).FirstAsync();
        var unchanged = await db.Select<UserEntity>().Where(item => item.UserId == other.UserId).FirstAsync();
        Assert.Equal(0, result);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<UserEntity>().VerifyHashedPassword(updated, updated.PasswordHash, "new password"));
        Assert.True(updated.IsAdmin);
        Assert.Equal("Admin", updated.DisplayName);
        Assert.Equal("other-hash", unchanged.PasswordHash);
        Assert.DoesNotContain("new password", output.ToString());
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public async Task Password_reset_rejects_mismatched_passwords_without_updating()
    {
        using var harness = new EmailVerificationHarness();
        var db = harness.DatabaseService.FSql;
        await db.Insert(new UserEntity { UserId = "admin", Email = "admin@example.com", PasswordHash = "old" }).ExecuteAffrowsAsync();
        var passwords = new Queue<string>(["first", "second"]);

        var result = await PanelPasswordResetCommand.RunAsync(
            db, new StringReader("admin@example.com"), TextWriter.Null, TextWriter.Null, passwords.Dequeue);

        Assert.Equal(1, result);
        Assert.Equal("old", (await db.Select<UserEntity>().Where(item => item.UserId == "admin").FirstAsync()).PasswordHash);
    }

    [Fact]
    public async Task Password_reset_rejects_missing_or_ambiguous_email_without_prompting_for_password()
    {
        using var harness = new EmailVerificationHarness();
        var db = harness.DatabaseService.FSql;
        await db.Insert(new UserEntity { UserId = "one", Email = "duplicate@example.com", PasswordHash = "one" }).ExecuteAffrowsAsync();
        await db.Insert(new UserEntity { UserId = "two", Email = "duplicate@example.com", PasswordHash = "two" }).ExecuteAffrowsAsync();
        static string UnexpectedPasswordPrompt() => throw new InvalidOperationException("Password should not be requested.");

        Assert.Equal(1, await PanelPasswordResetCommand.RunAsync(
            db, new StringReader("missing@example.com"), TextWriter.Null, TextWriter.Null, UnexpectedPasswordPrompt));
        Assert.Equal(1, await PanelPasswordResetCommand.RunAsync(
            db, new StringReader("duplicate@example.com"), TextWriter.Null, TextWriter.Null, UnexpectedPasswordPrompt));
    }

    [Fact]
    public async Task Password_reset_uses_configured_sqlite_database()
    {
        using var harness = new EmailVerificationHarness();
        await harness.DatabaseService.FSql.Insert(
            new UserEntity { UserId = "admin", Email = "admin@example.com", PasswordHash = "old" }).ExecuteAffrowsAsync();
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Panel:DbType"] = "sqlite",
            ["Panel:DbConnectionString"] = $"Data Source={harness.DatabasePath}"
        }).Build();
        var passwords = new Queue<string>(["new password", "new password"]);

        var result = await PanelPasswordResetCommand.RunConfiguredAsync(
            config, new StringReader("admin@example.com"), TextWriter.Null, TextWriter.Null, passwords.Dequeue);

        var updated = await harness.DatabaseService.FSql.Select<UserEntity>().Where(item => item.UserId == "admin").FirstAsync();
        Assert.Equal(0, result);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<UserEntity>().VerifyHashedPassword(updated, updated.PasswordHash, "new password"));
    }

    [Fact]
    public async Task Password_reset_does_not_create_missing_sqlite_database()
    {
        using var harness = new EmailVerificationHarness();
        var missingPath = Path.Combine(Path.GetDirectoryName(harness.DatabasePath)!, "missing.db");
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Panel:DbType"] = "sqlite",
            ["Panel:DbConnectionString"] = $"Data Source={missingPath}"
        }).Build();

        await Assert.ThrowsAnyAsync<Exception>(() => PanelPasswordResetCommand.RunConfiguredAsync(
            config, new StringReader("admin@example.com"), TextWriter.Null, TextWriter.Null, () => "unused"));
        Assert.False(File.Exists(missingPath));
    }

    private sealed class EmailVerificationHarness : IDisposable
    {
        private readonly string _rootPath;

        public EmailVerificationHarness()
        {
            _rootPath = Path.Combine(Path.GetTempPath(), "np-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_rootPath);

            DatabasePath = Path.Combine(_rootPath, "panel.db");
            DatabaseService = new DatabaseService(
                new StaticOptionsMonitor<PanelOptions>(
                    new PanelOptions
                    {
                        DbType = "sqlite",
                        DbConnectionString = $"Data Source={DatabasePath}"
                    }));
        }

        public DatabaseService DatabaseService { get; }
        public string DatabasePath { get; }

        public void Dispose()
        {
            DatabaseService.Dispose();
            if (Directory.Exists(_rootPath))
            {
                Directory.Delete(_rootPath, recursive: true);
            }
        }
    }

    private sealed class StaticOptionsMonitor<TOptions> : IOptionsMonitor<TOptions>
    {
        public StaticOptionsMonitor(TOptions currentValue)
        {
            CurrentValue = currentValue;
        }

        public TOptions CurrentValue { get; }

        public TOptions Get(string? name) => CurrentValue;

        public IDisposable OnChange(Action<TOptions, string?> listener) => NoopDisposable.Instance;
    }

    private sealed class NoopDisposable : IDisposable
    {
        public static NoopDisposable Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}

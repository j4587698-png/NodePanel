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

    private sealed class EmailVerificationHarness : IDisposable
    {
        private readonly string _rootPath;

        public EmailVerificationHarness()
        {
            _rootPath = Path.Combine(Path.GetTempPath(), "np-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_rootPath);

            var dbPath = Path.Combine(_rootPath, "panel.db");
            DatabaseService = new DatabaseService(
                new StaticOptionsMonitor<PanelOptions>(
                    new PanelOptions
                    {
                        DbType = "sqlite",
                        DbConnectionString = $"Data Source={dbPath}"
                    }));
        }

        public DatabaseService DatabaseService { get; }

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

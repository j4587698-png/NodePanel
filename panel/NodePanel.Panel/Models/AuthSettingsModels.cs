namespace NodePanel.Panel.Models;

public static class PanelAuthSettingKeys
{
    public const string AllowRegistration = "auth_allow_registration";
    public const string RequireInviteCodeForRegistration = "auth_require_invite_code_for_registration";
    public const string MaxInviteCodesPerUser = "auth_max_invite_codes_per_user";
    public const string RequireRegisterEmailVerification = "auth_require_register_email_verification";
    public const string AllowPasswordResetByEmail = "auth_allow_password_reset_by_email";
    public const string SmtpHost = "smtp_host";
    public const string SmtpPort = "smtp_port";
    public const string SmtpUsername = "smtp_username";
    public const string SmtpPassword = "smtp_password";
    public const string SmtpFromAddress = "smtp_from_address";
    public const string SmtpFromName = "smtp_from_name";
    public const string SmtpEnableSsl = "smtp_enable_ssl";
    public const string PopHost = "pop_host";
    public const string PopPort = "pop_port";
    public const string PopUsername = "pop_username";
    public const string PopPassword = "pop_password";
    public const string PopEnableSsl = "pop_enable_ssl";
}

public sealed record PanelAuthSettings
{
    public string SiteName { get; init; } = "NodePanel";

    public bool AllowRegistration { get; init; } = true;

    public bool RequireInviteCodeForRegistration { get; init; }

    public int MaxInviteCodesPerUser { get; init; } = 1;

    public bool RequireRegisterEmailVerification { get; init; }

    public bool AllowPasswordResetByEmail { get; init; }

    public string SmtpHost { get; init; } = string.Empty;

    public int SmtpPort { get; init; } = 465;

    public string SmtpUsername { get; init; } = string.Empty;

    public string SmtpPassword { get; init; } = string.Empty;

    public string SmtpFromAddress { get; init; } = string.Empty;

    public string SmtpFromName { get; init; } = string.Empty;

    public bool SmtpEnableSsl { get; init; } = true;

    public string PopHost { get; init; } = string.Empty;

    public int PopPort { get; init; } = 995;

    public string PopUsername { get; init; } = string.Empty;

    public string PopPassword { get; init; } = string.Empty;

    public bool PopEnableSsl { get; init; } = true;

    public string EffectiveSmtpFromAddress
        => !string.IsNullOrWhiteSpace(SmtpFromAddress)
            ? SmtpFromAddress.Trim()
            : SmtpUsername.Trim();

    public bool HasSmtpConfiguration
        => !string.IsNullOrWhiteSpace(SmtpHost) &&
           SmtpPort is > 0 and <= 65535 &&
           !string.IsNullOrWhiteSpace(EffectiveSmtpFromAddress);

    public bool IsRegistrationVerificationAvailable
        => AllowRegistration &&
           RequireRegisterEmailVerification &&
           HasSmtpConfiguration;

    public bool IsPasswordResetAvailable
        => AllowPasswordResetByEmail &&
           HasSmtpConfiguration;

    public static PanelAuthSettings FromSettings(IReadOnlyDictionary<string, string>? settings)
    {
        var source = settings ?? new Dictionary<string, string>(StringComparer.Ordinal);

        return new PanelAuthSettings
        {
            SiteName = NormalizeOrDefault(source.GetValueOrDefault("site_name"), "NodePanel"),
            AllowRegistration = ParseBool(source.GetValueOrDefault(PanelAuthSettingKeys.AllowRegistration), defaultValue: true),
            RequireInviteCodeForRegistration = ParseBool(source.GetValueOrDefault(PanelAuthSettingKeys.RequireInviteCodeForRegistration)),
            MaxInviteCodesPerUser = ParseNonNegativeInt(source.GetValueOrDefault(PanelAuthSettingKeys.MaxInviteCodesPerUser), 1),
            RequireRegisterEmailVerification = ParseBool(source.GetValueOrDefault(PanelAuthSettingKeys.RequireRegisterEmailVerification)),
            AllowPasswordResetByEmail = ParseBool(source.GetValueOrDefault(PanelAuthSettingKeys.AllowPasswordResetByEmail)),
            SmtpHost = NormalizeOrDefault(source.GetValueOrDefault(PanelAuthSettingKeys.SmtpHost), string.Empty),
            SmtpPort = ParsePort(source.GetValueOrDefault(PanelAuthSettingKeys.SmtpPort), 465),
            SmtpUsername = NormalizeOrDefault(source.GetValueOrDefault(PanelAuthSettingKeys.SmtpUsername), string.Empty),
            SmtpPassword = source.GetValueOrDefault(PanelAuthSettingKeys.SmtpPassword) ?? string.Empty,
            SmtpFromAddress = NormalizeOrDefault(source.GetValueOrDefault(PanelAuthSettingKeys.SmtpFromAddress), string.Empty),
            SmtpFromName = NormalizeOrDefault(source.GetValueOrDefault(PanelAuthSettingKeys.SmtpFromName), string.Empty),
            SmtpEnableSsl = ParseBool(source.GetValueOrDefault(PanelAuthSettingKeys.SmtpEnableSsl), defaultValue: true),
            PopHost = NormalizeOrDefault(source.GetValueOrDefault(PanelAuthSettingKeys.PopHost), string.Empty),
            PopPort = ParsePort(source.GetValueOrDefault(PanelAuthSettingKeys.PopPort), 995),
            PopUsername = NormalizeOrDefault(source.GetValueOrDefault(PanelAuthSettingKeys.PopUsername), string.Empty),
            PopPassword = source.GetValueOrDefault(PanelAuthSettingKeys.PopPassword) ?? string.Empty,
            PopEnableSsl = ParseBool(source.GetValueOrDefault(PanelAuthSettingKeys.PopEnableSsl), defaultValue: true)
        };
    }

    public static IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var parsed = FromSettings(settings);
        var errors = new List<string>();
        if (!TryParseNonNegativeInt(settings.GetValueOrDefault(PanelAuthSettingKeys.MaxInviteCodesPerUser), 1, out _))
        {
            errors.Add("每个用户的邀请码数量上限必须是大于等于 0 的整数。");
        }

        if (parsed.RequireRegisterEmailVerification && !parsed.HasSmtpConfiguration)
        {
            errors.Add("启用注册验证码前，请先完整配置 SMTP 发信信息。");
        }

        if (parsed.AllowPasswordResetByEmail && !parsed.HasSmtpConfiguration)
        {
            errors.Add("启用忘记密码验证码重置前，请先完整配置 SMTP 发信信息。");
        }

        return errors;
    }

    private static bool ParseBool(string? value, bool defaultValue = false)
        => bool.TryParse(value, out var parsed) ? parsed : defaultValue;

    private static int ParsePort(string? value, int defaultValue)
        => int.TryParse(value, out var parsed) && parsed is > 0 and <= 65535 ? parsed : defaultValue;

    private static int ParseNonNegativeInt(string? value, int defaultValue)
        => TryParseNonNegativeInt(value, defaultValue, out var parsed) ? parsed : defaultValue;

    private static bool TryParseNonNegativeInt(string? value, int defaultValue, out int parsed)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            parsed = defaultValue;
            return true;
        }

        if (int.TryParse(value, out parsed) && parsed >= 0)
        {
            return true;
        }

        parsed = defaultValue;
        return false;
    }

    private static string NormalizeOrDefault(string? value, string defaultValue)
    {
        var normalized = NodeFormValueCodec.TrimOrEmpty(value);
        return string.IsNullOrWhiteSpace(normalized) ? defaultValue : normalized;
    }
}

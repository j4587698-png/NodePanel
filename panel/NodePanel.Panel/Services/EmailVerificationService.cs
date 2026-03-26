using System.Security.Cryptography;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public static class EmailVerificationPurposes
{
    public const string Register = "register";
    public const string PasswordReset = "password_reset";
}

public sealed class EmailVerificationService
{
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(10);

    private readonly DatabaseService _db;

    public EmailVerificationService(DatabaseService db)
    {
        _db = db;
    }

    public async Task<string> IssueCodeAsync(string email, string purpose, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) throw new InvalidOperationException("Not configured");

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(email);
        var normalizedPurpose = NodeFormValueCodec.TrimOrEmpty(purpose);
        if (string.IsNullOrWhiteSpace(normalizedEmail) || string.IsNullOrWhiteSpace(normalizedPurpose))
        {
            throw new InvalidOperationException("邮箱和验证码用途不能为空。");
        }

        await _db.FSql.Delete<EmailVerificationCodeEntity>()
            .Where(item => item.Email == normalizedEmail && item.Purpose == normalizedPurpose)
            .ExecuteAffrowsAsync(cancellationToken)
            .ConfigureAwait(false);

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var entity = new EmailVerificationCodeEntity
        {
            VerificationId = Guid.NewGuid().ToString("N"),
            Email = normalizedEmail,
            Purpose = normalizedPurpose,
            Code = code,
            ExpiresAt = DateTimeOffset.UtcNow.Add(DefaultLifetime),
            CreatedAt = DateTimeOffset.UtcNow
        };

        await _db.FSql.Insert(entity).ExecuteAffrowsAsync(cancellationToken).ConfigureAwait(false);
        return code;
    }

    public async Task<bool> VerifyCodeAsync(string email, string purpose, string code, CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured) return false;

        var normalizedEmail = NodeFormValueCodec.TrimOrEmpty(email);
        var normalizedPurpose = NodeFormValueCodec.TrimOrEmpty(purpose);
        var normalizedCode = NodeFormValueCodec.TrimOrEmpty(code);
        if (string.IsNullOrWhiteSpace(normalizedEmail) ||
            string.IsNullOrWhiteSpace(normalizedPurpose) ||
            string.IsNullOrWhiteSpace(normalizedCode))
        {
            return false;
        }

        var entity = await _db.FSql.Select<EmailVerificationCodeEntity>()
            .Where(item =>
                item.Email == normalizedEmail &&
                item.Purpose == normalizedPurpose &&
                item.Code == normalizedCode)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            return false;
        }

        if (entity.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            await _db.FSql.Delete<EmailVerificationCodeEntity>()
                .Where(item => item.VerificationId == entity.VerificationId)
                .ExecuteAffrowsAsync(cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        var consumed = await _db.FSql.Delete<EmailVerificationCodeEntity>()
            .Where(item => item.VerificationId == entity.VerificationId)
            .ExecuteAffrowsAsync(cancellationToken)
            .ConfigureAwait(false);
        if (consumed == 0)
        {
            return false;
        }

        await _db.FSql.Delete<EmailVerificationCodeEntity>()
            .Where(item => item.Email == normalizedEmail && item.Purpose == normalizedPurpose)
            .ExecuteAffrowsAsync(cancellationToken)
            .ConfigureAwait(false);

        return true;
    }
}

using System.Net;
using System.Net.Mail;
using System.Text;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class SmtpEmailService
{
    public async Task SendAsync(
        PanelAuthSettings settings,
        string recipientEmail,
        string recipientName,
        string subject,
        string body,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var normalizedRecipientEmail = NodeFormValueCodec.TrimOrEmpty(recipientEmail);
        var normalizedRecipientName = NodeFormValueCodec.TrimOrEmpty(recipientName);
        var normalizedSubject = NodeFormValueCodec.TrimOrEmpty(subject);
        var normalizedBody = body ?? string.Empty;

        if (!settings.HasSmtpConfiguration)
        {
            throw new InvalidOperationException("请先在系统设置中完整配置 SMTP 发信信息。");
        }

        if (string.IsNullOrWhiteSpace(normalizedRecipientEmail))
        {
            throw new InvalidOperationException("收件邮箱不能为空。");
        }

        var fromAddress = settings.EffectiveSmtpFromAddress;
        using var message = new MailMessage
        {
            From = string.IsNullOrWhiteSpace(settings.SmtpFromName)
                ? new MailAddress(fromAddress)
                : new MailAddress(fromAddress, settings.SmtpFromName, Encoding.UTF8),
            Subject = normalizedSubject,
            Body = normalizedBody,
            IsBodyHtml = false,
            BodyEncoding = Encoding.UTF8,
            SubjectEncoding = Encoding.UTF8
        };

        message.To.Add(
            string.IsNullOrWhiteSpace(normalizedRecipientName)
                ? new MailAddress(normalizedRecipientEmail)
                : new MailAddress(normalizedRecipientEmail, normalizedRecipientName, Encoding.UTF8));

        using var client = new SmtpClient(settings.SmtpHost, settings.SmtpPort)
        {
            DeliveryMethod = SmtpDeliveryMethod.Network,
            EnableSsl = settings.SmtpEnableSsl
        };

        if (!string.IsNullOrWhiteSpace(settings.SmtpUsername))
        {
            client.UseDefaultCredentials = false;
            client.Credentials = new NetworkCredential(settings.SmtpUsername, settings.SmtpPassword);
        }
        else
        {
            client.UseDefaultCredentials = true;
        }

        cancellationToken.ThrowIfCancellationRequested();
        await client.SendMailAsync(message).ConfigureAwait(false);
    }
}

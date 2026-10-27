using System.Net;
using System.Net.Mail;

namespace SSLense.Core.Notifications;

internal sealed class SmtpEmailSender : IEmailSender
{
    public async Task SendAsync(
        SmtpDeliverySettings settings,
        NotificationMessage message,
        CancellationToken cancellationToken)
    {
        using var mail = new MailMessage(settings.From, settings.To, message.Subject, message.Body);
        using var client = new SmtpClient(settings.Host, settings.Port)
        {
            EnableSsl = settings.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = string.IsNullOrWhiteSpace(settings.Username)
        };
        if (!string.IsNullOrWhiteSpace(settings.Username))
        {
            client.Credentials = new NetworkCredential(settings.Username, settings.Password);
        }

        try
        {
            await client.SendMailAsync(mail, cancellationToken).ConfigureAwait(false);
        }
        catch (SmtpException exception)
        {
            throw new InvalidOperationException(
                $"SMTP notification failed via '{settings.Host}:{settings.Port}'. Check the server, TLS, credentials, and firewall settings.",
                exception);
        }
    }
}

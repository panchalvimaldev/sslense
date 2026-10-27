using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

internal sealed class NotificationSettingsService(
    IConfigStore configStore,
    ISecretProtector secretProtector) : INotificationSettingsService
{
    public async Task ConfigureAsync(
        NotificationSettingsRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var smtp = request.Smtp is null ? null : CreateSmtpConfig(
            request.Smtp,
            request.PreserveExistingSmtpPassword ? config.Notifications.Smtp?.ProtectedPassword : null);
        WebhookNotificationConfig? webhook = null;
        if (!string.IsNullOrWhiteSpace(request.WebhookUrl))
        {
            if (!Uri.TryCreate(request.WebhookUrl, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                throw new ArgumentException("The webhook URL must be an absolute HTTP or HTTPS URL.");
            }

            webhook = new WebhookNotificationConfig(Protect(uri.AbsoluteUri));
        }
        else if (request.PreserveExistingWebhook)
        {
            webhook = config.Notifications.Webhook;
        }

        if (smtp is null && webhook is null)
        {
            throw new ArgumentException("Configure at least one SMTP or webhook notification channel.");
        }

        await configStore.SaveAsync(
                config with
                {
                    Notifications = new NotificationConfig
                    {
                        Smtp = smtp,
                        Webhook = webhook,
                        NotifyOnSuccess = request.NotifyOnSuccess
                    }
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task ClearAsync(CancellationToken cancellationToken = default)
    {
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(
                config with { Notifications = new NotificationConfig() },
                cancellationToken)
            .ConfigureAwait(false);
    }

    private SmtpNotificationConfig CreateSmtpConfig(SmtpSettingsRequest smtp, string? existingProtectedPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(smtp.Host);
        if (smtp.Port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(smtp), "SMTP port must be between 1 and 65535.");
        }

        ValidateEmail(smtp.From, "SMTP from address");
        ValidateEmail(smtp.To, "SMTP recipient address");
        if (!string.IsNullOrWhiteSpace(smtp.Username) && smtp.Password is null && existingProtectedPassword is null)
        {
            throw new ArgumentException("An SMTP password is required when a username is configured.");
        }

        return new SmtpNotificationConfig(
            smtp.Host.Trim(),
            smtp.Port,
            smtp.EnableSsl,
            smtp.Username?.Trim(),
            smtp.Password is null ? existingProtectedPassword : Protect(smtp.Password),
            smtp.From.Trim(),
            smtp.To.Trim());
    }

    private string Protect(string value)
    {
        var plaintext = Encoding.UTF8.GetBytes(value);
        try
        {
            return Convert.ToBase64String(secretProtector.Protect(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void ValidateEmail(string value, string label)
    {
        try
        {
            _ = new MailAddress(value);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            throw new ArgumentException($"{label} is invalid.", exception);
        }
    }
}

using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Notifications;

internal sealed class Notifier(
    IConfigStore configStore,
    ISecretProtector secretProtector,
    IEmailSender emailSender,
    IWebhookSender webhookSender) : INotifier
{
    public async Task NotifyAsync(
        NotificationMessage message,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (message.Kind == NotificationKind.RenewalSuccess && !config.Notifications.NotifyOnSuccess)
        {
            return;
        }

        if (message.Kind == NotificationKind.Test &&
            config.Notifications.Smtp is null &&
            config.Notifications.Webhook is null)
        {
            throw new InvalidOperationException("No notification channels are configured.");
        }

        var failures = new List<Exception>();
        if (config.Notifications.Smtp is { } smtp)
        {
            try
            {
                var password = string.IsNullOrWhiteSpace(smtp.ProtectedPassword)
                    ? null
                    : Unprotect(smtp.ProtectedPassword);
                await emailSender.SendAsync(
                        new SmtpDeliverySettings(
                            smtp.Host,
                            smtp.Port,
                            smtp.EnableSsl,
                            smtp.Username,
                            password,
                            smtp.From,
                            smtp.To),
                        message,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                failures.Add(exception);
            }
        }

        if (config.Notifications.Webhook is { } webhook)
        {
            try
            {
                var url = new Uri(Unprotect(webhook.ProtectedUrl), UriKind.Absolute);
                await webhookSender.SendAsync(url, message, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                failures.Add(exception);
            }
        }

        if (failures.Count > 0)
        {
            throw new AggregateException("One or more notification channels failed.", failures);
        }
    }

    private string Unprotect(string encoded)
    {
        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(encoded);
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("A protected notification secret is not valid base64 data.", exception);
        }

        var plaintext = secretProtector.Unprotect(protectedBytes);
        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

namespace SSLense.Core.Notifications;

public interface IWebhookSender
{
    Task SendAsync(
        Uri url,
        NotificationMessage message,
        CancellationToken cancellationToken);
}

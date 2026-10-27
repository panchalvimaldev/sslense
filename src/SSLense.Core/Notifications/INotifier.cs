namespace SSLense.Core.Notifications;

public interface INotifier
{
    Task NotifyAsync(
        NotificationMessage message,
        CancellationToken cancellationToken = default);
}

namespace SSLense.Core.Notifications;

public interface INotificationSettingsService
{
    Task ConfigureAsync(
        NotificationSettingsRequest request,
        CancellationToken cancellationToken = default);

    Task ClearAsync(CancellationToken cancellationToken = default);
}

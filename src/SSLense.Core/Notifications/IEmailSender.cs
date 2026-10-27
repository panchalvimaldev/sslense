namespace SSLense.Core.Notifications;

public interface IEmailSender
{
    Task SendAsync(
        SmtpDeliverySettings settings,
        NotificationMessage message,
        CancellationToken cancellationToken);
}

public sealed record SmtpDeliverySettings(
    string Host,
    int Port,
    bool EnableSsl,
    string? Username,
    string? Password,
    string From,
    string To);

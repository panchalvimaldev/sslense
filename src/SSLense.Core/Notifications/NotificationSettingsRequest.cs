namespace SSLense.Core.Notifications;

public sealed record NotificationSettingsRequest(
    SmtpSettingsRequest? Smtp,
    string? WebhookUrl,
    bool NotifyOnSuccess);

public sealed record SmtpSettingsRequest(
    string Host,
    int Port,
    bool EnableSsl,
    string? Username,
    string? Password,
    string From,
    string To);

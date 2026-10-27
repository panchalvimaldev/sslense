namespace SSLense.Core.Config;

public sealed record NotificationConfig
{
    public SmtpNotificationConfig? Smtp { get; init; }

    public WebhookNotificationConfig? Webhook { get; init; }

    public bool NotifyOnSuccess { get; init; }
}

public sealed record SmtpNotificationConfig(
    string Host,
    int Port,
    bool EnableSsl,
    string? Username,
    string? ProtectedPassword,
    string From,
    string To);

public sealed record WebhookNotificationConfig(string ProtectedUrl);

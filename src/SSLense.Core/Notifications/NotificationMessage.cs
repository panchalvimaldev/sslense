namespace SSLense.Core.Notifications;

public enum NotificationKind
{
    Test,
    RenewalFailure,
    RenewalSuccess,
    ExpiryWarning
}

public sealed record NotificationMessage(
    NotificationKind Kind,
    string Subject,
    string Body);

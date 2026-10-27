namespace SSLense.Core.Config;

public sealed record AppConfig
{
    public string? DefaultEmail { get; init; }

    public bool UseStaging { get; init; } = true;

    public int RenewalThresholdDays { get; init; } = 30;

    public NotificationConfig Notifications { get; init; } = new();
}

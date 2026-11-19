namespace SSLense.Core.Config;

public interface ISettingsService
{
    Task<AppConfig> GetAsync(CancellationToken cancellationToken = default);

    Task SaveGeneralAsync(
        string? defaultEmail,
        int renewalThresholdDays,
        CancellationToken cancellationToken = default);

    /// <summary>Sets when automatic renewals may run, or null to let them run at any time.</summary>
    Task SaveMaintenanceWindowAsync(MaintenanceWindow? window, CancellationToken cancellationToken = default);

    /// <summary>Turns the new-version notice on or off.</summary>
    Task SaveCheckForUpdatesAsync(bool enabled, CancellationToken cancellationToken = default);
}

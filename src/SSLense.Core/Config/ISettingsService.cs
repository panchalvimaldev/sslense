namespace SSLense.Core.Config;

public interface ISettingsService
{
    Task<AppConfig> GetAsync(CancellationToken cancellationToken = default);

    Task SaveGeneralAsync(
        string? defaultEmail,
        int renewalThresholdDays,
        CancellationToken cancellationToken = default);
}

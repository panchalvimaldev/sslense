using System.Net.Mail;

namespace SSLense.Core.Config;

internal sealed class SettingsService(IConfigStore configStore) : ISettingsService
{
    public Task<AppConfig> GetAsync(CancellationToken cancellationToken = default) =>
        configStore.LoadAsync(cancellationToken);

    public async Task SaveGeneralAsync(
        string? defaultEmail,
        int renewalThresholdDays,
        CancellationToken cancellationToken = default)
    {
        if (renewalThresholdDays is < 1 or > 89)
        {
            throw new ArgumentOutOfRangeException(
                nameof(renewalThresholdDays),
                "Renewal threshold must be between 1 and 89 days.");
        }

        if (!string.IsNullOrWhiteSpace(defaultEmail))
        {
            try
            {
                _ = new MailAddress(defaultEmail);
            }
            catch (FormatException exception)
            {
                throw new ArgumentException("The default ACME email address is invalid.", nameof(defaultEmail), exception);
            }
        }

        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(
                config with
                {
                    DefaultEmail = string.IsNullOrWhiteSpace(defaultEmail) ? null : defaultEmail.Trim(),
                    RenewalThresholdDays = renewalThresholdDays,
                    UseStaging = true
                },
                cancellationToken)
            .ConfigureAwait(false);
    }
}

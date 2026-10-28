using SSLense.Core;
using SSLense.Core.Certificates;
using SSLense.Core.Renewal;

namespace SSLense.Service;

internal sealed class RenewalWorker(
    IRenewalService renewalService,
    IExpiryMonitor expiryMonitor,
    ICertificateRecoveryService recoveryService,
    ILogger<RenewalWorker> logger) : BackgroundService
{
    // Hourly checks are cheap: certificates that are not due and retries still backing off
    // are skipped from saved state, and ARI responses are cached by the provider.
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RecoverAsync(stoppingToken).ConfigureAwait(false);
        await RunCycleAsync(stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(CheckInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await RunCycleAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task RunCycleAsync(CancellationToken cancellationToken)
    {
        // Expiry monitoring runs first and separately so it still alerts when renewal itself is broken.
        await CheckExpiryAsync(cancellationToken).ConfigureAwait(false);
        await RunRenewalAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task RecoverAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (var result in await recoveryService.RecoverAsync(cancellationToken).ConfigureAwait(false))
            {
                if (result.Succeeded)
                {
                    logger.LogInformation("{RecoveryMessage}", result.Message);
                }
                else
                {
                    logger.LogWarning("{RecoveryMessage}", result.Message);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Certificate operation recovery failed; continuing with renewal");
        }
    }

    private async Task CheckExpiryAsync(CancellationToken cancellationToken)
    {
        try
        {
            foreach (var message in await expiryMonitor.CheckAsync(cancellationToken).ConfigureAwait(false))
            {
                logger.LogWarning("{ExpiryMessage}", message);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Certificate expiry check failed");
        }
    }

    private async Task RunRenewalAsync(CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Starting scheduled certificate renewal check");
            var progress = new Progress<ProgressEvent>(value =>
                logger.LogInformation("[{Step}] {Message}", value.Step, value.Message));
            var results = await renewalService.RenewAsync(
                    new RenewalRequest(All: true, Scheduled: true),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);

            foreach (var result in results)
            {
                if (result.Succeeded)
                {
                    logger.LogInformation(
                        "Scheduled renewal result for {SiteName}: {Message}",
                        result.SiteName,
                        result.Message);
                }
                else if (result.Attempted)
                {
                    logger.LogError(
                        "Scheduled renewal failed for {SiteName}: {Message}",
                        result.SiteName,
                        result.Message);
                }
                else
                {
                    logger.LogWarning(
                        "Scheduled renewal for {SiteName} is backing off: {Message}",
                        result.SiteName,
                        result.Message);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Scheduled certificate renewal check failed");
        }
    }
}

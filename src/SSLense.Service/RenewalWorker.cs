using SSLense.Core;
using SSLense.Core.Renewal;

namespace SSLense.Service;

internal sealed class RenewalWorker(
    IRenewalService renewalService,
    ILogger<RenewalWorker> logger) : BackgroundService
{
    private static readonly TimeSpan DailyInterval = TimeSpan.FromDays(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RunRenewalAsync(stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(DailyInterval);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await RunRenewalAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task RunRenewalAsync(CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Starting scheduled staging certificate renewal check");
            var progress = new Progress<ProgressEvent>(value =>
                logger.LogInformation("[{Step}] {Message}", value.Step, value.Message));
            var results = await renewalService.RenewAsync(
                    new RenewalRequest(All: true, RetryFailures: true),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);

            foreach (var result in results)
            {
                if (!result.Succeeded)
                {
                    logger.LogError(
                        "Scheduled renewal failed for {SiteName}: {Message}",
                        result.SiteName,
                        result.Message);
                }
                else
                {
                    logger.LogInformation(
                        "Scheduled renewal result for {SiteName}: {Message}",
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
            logger.LogError(exception, "Scheduled staging certificate renewal check failed");
        }
    }
}

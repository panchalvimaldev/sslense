using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using System.Diagnostics;
using SSLense.Core.Notifications;

namespace SSLense.Core.Renewal;

internal sealed class RenewalService : IRenewalService
{
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(2)
    ];

    private readonly IManagedCertificateStore _managedStore;
    private readonly IConfigStore _configStore;
    private readonly IAcmeService _acmeService;
    private readonly IIisService _iisService;
    private readonly ICertificateStore _certificateStore;
    private readonly IRenewalDelay _delay;
    private readonly INotifier _notifier;

    public RenewalService(
        IManagedCertificateStore managedStore,
        IConfigStore configStore,
        IAcmeService acmeService,
        IIisService iisService,
        ICertificateStore certificateStore,
        IRenewalDelay delay,
        INotifier notifier)
    {
        _managedStore = managedStore;
        _configStore = configStore;
        _acmeService = acmeService;
        _iisService = iisService;
        _certificateStore = certificateStore;
        _delay = delay;
        _notifier = notifier;
    }

    public async Task<IReadOnlyList<ManagedCertificateStatus>> GetStatusAsync(
        CancellationToken cancellationToken = default)
    {
        var now = DateTimeOffset.UtcNow;
        var records = await _managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return records
            .OrderBy(value => value.NotAfter)
            .Select(value => new ManagedCertificateStatus(
                value.SiteName,
                value.Hosts,
                value.NotBefore,
                value.NotAfter,
                (int)Math.Floor((value.NotAfter - now).TotalDays),
                value.Thumbprint,
                value.LastRenewalAttempt,
                value.LastRenewalSucceeded,
                value.LastRenewalMessage))
            .ToArray();
    }

    public async Task<IReadOnlyList<RenewalResult>> RenewAsync(
        RenewalRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        var records = await _managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var selected = request.All
            ? records
            : records.Where(value => string.Equals(
                value.SiteName,
                request.SiteName,
                StringComparison.OrdinalIgnoreCase)).ToArray();
        if (!request.All && selected.Count == 0)
        {
            throw new InvalidOperationException(
                $"No managed certificate was found for IIS site '{request.SiteName}'.");
        }

        var config = await _configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (config.RenewalThresholdDays < 0)
        {
            throw new InvalidDataException("RenewalThresholdDays cannot be negative.");
        }

        var dueAt = DateTimeOffset.UtcNow.AddDays(config.RenewalThresholdDays);
        var results = new List<RenewalResult>();
        foreach (var certificate in selected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (certificate.NotAfter <= DateTimeOffset.UtcNow.AddDays(14))
            {
                await TryNotifyAsync(
                        new NotificationMessage(
                            NotificationKind.ExpiryWarning,
                            $"SSLense certificate expires soon: {certificate.SiteName}",
                            $"The staging certificate for {certificate.SiteName} ({string.Join(", ", certificate.Hosts)}) " +
                            $"expires at {certificate.NotAfter:O}."),
                        progress,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!request.Force && certificate.NotAfter > dueAt)
            {
                results.Add(new RenewalResult(
                    certificate.SiteName,
                    false,
                    true,
                    $"Skipped: certificate is not due until {certificate.NotAfter:yyyy-MM-dd}.",
                    certificate.Thumbprint));
                continue;
            }

            results.Add(await RenewOneAsync(certificate, request, progress, cancellationToken)
                .ConfigureAwait(false));
        }

        return results;
    }

    private async Task<RenewalResult> RenewOneAsync(
        ManagedCertificate certificate,
        RenewalRequest request,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        var attempts = request.RetryFailures ? 3 : 1;
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            try
            {
                progress?.Report(new ProgressEvent(
                    "renewal",
                    $"Renewing {certificate.SiteName} (attempt {attempt} of {attempts})."));
                var issued = await _acmeService.IssueAsync(
                        new AcmeIssueRequest(
                            certificate.SiteName,
                            certificate.Hosts,
                            certificate.Email,
                            certificate.OutputDirectory,
                            true),
                        progress,
                        cancellationToken)
                    .ConfigureAwait(false);
                var newThumbprint = issued.CertificateThumbprint
                    ?? throw new InvalidOperationException("The renewed certificate has no thumbprint.");

                var cleanupMessage = await RemoveOldCertificateIfUnusedAsync(
                        certificate.Thumbprint,
                        newThumbprint,
                        cancellationToken)
                    .ConfigureAwait(false);
                await TryNotifyAsync(
                        new NotificationMessage(
                            NotificationKind.RenewalSuccess,
                            $"SSLense renewal succeeded: {certificate.SiteName}",
                            $"The staging certificate for {certificate.SiteName} ({string.Join(", ", certificate.Hosts)}) " +
                            $"was renewed successfully. New thumbprint: {newThumbprint}."),
                        progress,
                        cancellationToken)
                    .ConfigureAwait(false);
                return new RenewalResult(
                    certificate.SiteName,
                    true,
                    true,
                    cleanupMessage ?? "Renewed and rebound successfully.",
                    certificate.Thumbprint,
                    newThumbprint);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                await _managedStore.RecordRenewalFailureAsync(
                        certificate.SiteName,
                        DateTimeOffset.UtcNow,
                        exception.Message,
                        CancellationToken.None)
                    .ConfigureAwait(false);

                if (attempt == attempts)
                {
                    await TryNotifyAsync(
                            new NotificationMessage(
                                NotificationKind.RenewalFailure,
                                $"SSLense renewal failed: {certificate.SiteName}",
                                $"The staging certificate renewal for {certificate.SiteName} " +
                                $"({string.Join(", ", certificate.Hosts)}) failed after {attempts} attempt(s). " +
                                $"The existing IIS binding was retained. Error: {exception.Message}"),
                            progress,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                    return new RenewalResult(
                        certificate.SiteName,
                        true,
                        false,
                        exception.Message,
                        certificate.Thumbprint);
                }

                var retryDelay = RetryDelays[attempt - 1];
                progress?.Report(new ProgressEvent(
                    "retry",
                    $"Renewal failed for {certificate.SiteName}; retrying in {retryDelay.TotalHours:0} hour(s)."));
                await _delay.WaitAsync(retryDelay, cancellationToken).ConfigureAwait(false);
            }
        }

        throw new UnreachableException();
    }

    private async Task TryNotifyAsync(
        NotificationMessage message,
        IProgress<ProgressEvent>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            await _notifier.NotifyAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            progress?.Report(new ProgressEvent(
                "notification",
                $"Notification could not be sent: {exception.Message}"));
        }
    }

    private async Task<string?> RemoveOldCertificateIfUnusedAsync(
        string oldThumbprint,
        string newThumbprint,
        CancellationToken cancellationToken)
    {
        if (string.Equals(oldThumbprint, newThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var sites = await _iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var stillUsed = sites.SelectMany(value => value.Bindings).Any(binding =>
            string.Equals(binding.CertificateThumbprint, oldThumbprint, StringComparison.OrdinalIgnoreCase));
        if (stillUsed)
        {
            return "Renewed successfully; the old certificate was retained because another IIS binding uses it.";
        }

        try
        {
            await _certificateStore.RemoveAsync(oldThumbprint, cancellationToken).ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return $"Renewed successfully, but the unused old certificate could not be removed: {exception.Message}";
        }
    }

    private static void ValidateRequest(RenewalRequest request)
    {
        var hasSite = !string.IsNullOrWhiteSpace(request.SiteName);
        if (request.All == hasSite)
        {
            throw new ArgumentException("Specify exactly one of --all or --site.", nameof(request));
        }
    }
}

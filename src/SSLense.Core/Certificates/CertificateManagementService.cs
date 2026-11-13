using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Logs;
using SSLense.Core.Reminders;

namespace SSLense.Core.Certificates;

internal sealed class CertificateManagementService(
    IManagedCertificateStore managedStore,
    ICertificateStore certificateStore,
    IIisService iisService,
    ILogService logService,
    ICertificateAuthorityRegistry? authorities = null,
    IServedCertificateCheck? servedCheck = null,
    ICertificateOperationLock? operationLock = null) : ICertificateManagementService
{
    private readonly ICertificateAuthorityRegistry _authorities = authorities ?? CertificateAuthorityRegistry.BuiltInOnly;
    private readonly ICertificateOperationLock _operationLock = operationLock ?? new NoOpCertificateOperationLock();

    public async Task<CertificateDetails> GetDetailsAsync(
        string siteName,
        CancellationToken cancellationToken = default)
    {
        var record = await FindRecordAsync(siteName, cancellationToken).ConfigureAwait(false);
        var installed = await certificateStore.FindByThumbprintAsync(record.Thumbprint, cancellationToken)
            .ConfigureAwait(false);
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var boundSites = sites.Where(site => site.Bindings.Any(binding =>
                string.Equals(binding.CertificateThumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase)))
            .Select(site => site.Name)
            .ToArray();
        var logs = await logService.ReadCurrentAsync("All", 10, cancellationToken).ConfigureAwait(false);
        var authority = await _authorities.DescribeAsync(record, cancellationToken).ConfigureAwait(false);
        return new CertificateDetails(
            record.SiteName,
            record.Hosts,
            record.Thumbprint,
            installed?.Issuer ?? "Unknown",
            installed?.NotBefore ?? record.NotBefore,
            installed?.NotAfter ?? record.NotAfter,
            boundSites,
            logs.Lines,
            record.AuthorityId,
            authority.Name,
            authority.IsTest,
            record.Source,
            record.AdditionalTargets,
            record.SitePendingSince);
    }

    public async Task RemoveAsync(string siteName, CancellationToken cancellationToken = default)
    {
        var record = await FindRecordAsync(siteName, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(record.SiteName, siteName.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"IIS site '{siteName}' shares the certificate managed for '{record.SiteName}'. To stop managing only this site and keep its binding, use " +
                $"'SSLense.Cli share remove --site \"{siteName}\"'. To remove the certificate from every site, use 'SSLense.Cli remove --site \"{record.SiteName}\"'.");
        }

        // Services outside IIS may still use a certificate with no site, and SSLense cannot tell which, so it stays installed.
        if (record.NoSite)
        {
            await managedStore.RemoveAsync(record.SiteName, cancellationToken).ConfigureAwait(false);
            return;
        }

        var existingSites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        foreach (var target in record.AllTargets())
        {
            // A site left on an older certificate keeps that binding, and a deleted site has none to remove.
            if (record.IsShared() && (target.PendingSince is not null ||
                existingSites.FindSite(target.SiteName) is null))
            {
                continue;
            }

            await iisService.RemoveHttpsBindingsAsync(
                    target.SiteName,
                    target.Hosts,
                    record.Thumbprint,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var stillUsed = sites.SelectMany(site => site.Bindings).Any(binding =>
            string.Equals(binding.CertificateThumbprint, record.Thumbprint, StringComparison.OrdinalIgnoreCase));
        // Only certificates SSLense obtained itself are deleted; an imported one may be used outside IIS.
        if (!stillUsed && record.Source == CertificateSource.Acme)
        {
            await certificateStore.RemoveAsync(record.Thumbprint, cancellationToken).ConfigureAwait(false);
        }

        await managedStore.RemoveAsync(record.SiteName, cancellationToken).ConfigureAwait(false);
    }

    public async Task<string> StopManagingAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var before = await FindRecordAsync(name, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(before.SiteName, name.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"IIS site '{name.Trim()}' shares the certificate managed for '{before.SiteName}'. To stop managing only this site, use " +
                $"'SSLense.Cli share remove --site \"{name.Trim()}\"'. To stop managing the certificate on every site, use " +
                $"'SSLense.Cli unmanage --site \"{before.SiteName}\"'.");
        }

        // A renewal running now would write the record back, so this waits for it.
        await using var siteLocks = await _operationLock
            .AcquireAllAsync(before.AllSiteNames(), cancellationToken)
            .ConfigureAwait(false);
        var record = await FindRecordAsync(before.SiteName, cancellationToken).ConfigureAwait(false);

        // Only SSLense's record goes: IIS bindings, the certificate in the store and its deployment results stay as they are.
        await managedStore.RemoveAsync(record.SiteName, CancellationToken.None).ConfigureAwait(false);

        if (record.NoSite)
        {
            return $"SSLense no longer manages '{record.SiteName}'. The certificate stays in LocalMachine\\My for the services that use it " +
                   $"and expires on {record.NotAfter:yyyy-MM-dd}.";
        }

        var sites = record.AllTargets()
            .Select(target => $"'{ManagedCertificateNames.IisSiteOf(target.SiteName)}'")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return $"SSLense no longer manages the certificate for {string.Join(", ", record.Hosts)}. Its HTTPS bindings on IIS " +
               $"{(sites.Length == 1 ? "site" : "sites")} {string.Join(", ", sites)} were not changed, so visitors are served it until it expires on " +
               $"{record.NotAfter:yyyy-MM-dd}. Renew or replace it yourself before then.";
    }

    public async Task<CertificateCheckResult> CheckServedAsync(string name, CancellationToken cancellationToken = default)
    {
        var check = servedCheck ?? throw new InvalidOperationException("The served-certificate check is not available.");
        var record = await FindRecordAsync(name, cancellationToken).ConfigureAwait(false);
        if (record.NoSite)
        {
            return new CertificateCheckResult(true, "This certificate is not on an IIS site, so there is no binding to check. Its deployment steps hand it to its services.");
        }

        // The certificate's first site, then each site sharing it, with its own host names.
        CertificateTarget[] targets = [new(record.SiteName, record.Hosts), .. record.AdditionalTargets ?? []];
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var problems = new List<string>();
        foreach (var target in targets)
        {
            var site = sites.FindSite(target.SiteName);
            if (site is null)
            {
                problems.Add($"IIS site '{ManagedCertificateNames.IisSiteOf(target.SiteName)}' was not found.");
                continue;
            }

            if (site.State != ServedCertificateCheck.StartedState)
            {
                problems.Add($"IIS site '{site.Name}' is stopped, so it cannot be checked.");
                continue;
            }

            var single = record with { SiteName = target.SiteName, Hosts = target.Hosts, AdditionalTargets = null };
            if (await check.CheckAsync(single, site, cancellationToken).ConfigureAwait(false) is { } problem)
            {
                problems.Add(problem);
            }
        }

        var hosts = targets.SelectMany(target => target.Hosts).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return problems.Count == 0
            ? new CertificateCheckResult(true, hosts.Length == 1
                ? $"https://{hosts[0]} serves the expected certificate."
                : $"All {hosts.Length} host names serve the expected certificate: {string.Join(", ", hosts)}.")
            : new CertificateCheckResult(false, string.Join(" ", problems));
    }

    private async Task<ManagedCertificate> FindRecordAsync(
        string siteName,
        CancellationToken cancellationToken)
    {
        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return records.FirstOrDefault(value => value.ManagesSite(siteName))
            ?? throw ManagedCertificateNotFound.Create(siteName, records);
    }
}

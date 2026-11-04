using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Reminders;

namespace SSLense.Core.Certificates;

internal sealed class CertificateSharingService(
    IManagedCertificateStore managedStore,
    ICertificateStore certificateStore,
    IIisService iisService,
    ICertificateOperationLock operationLock,
    ICertificateTransactionJournal journal) : ICertificateSharingService
{
    public async Task<IReadOnlyList<string>> AddSiteAsync(
        string fromSite,
        string toSite,
        IReadOnlyList<string> hosts,
        bool replaceExisting = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fromSite);
        ArgumentException.ThrowIfNullOrWhiteSpace(toSite);
        ArgumentNullException.ThrowIfNull(hosts);

        var before = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var ownerBefore = FindOwner(before, fromSite);
        await using var siteLocks = await operationLock
            .AcquireAllAsync([.. ownerBefore.AllSiteNames(), toSite], cancellationToken)
            .ConfigureAwait(false);

        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var owner = FindOwner(records, fromSite);
        if (!owner.AllSiteNames().ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(ownerBefore.AllSiteNames()))
        {
            throw new CertificateStateChangedException(
                $"The sites sharing the certificate for IIS site '{fromSite}' changed while the operation was waiting. " +
                "Refresh status before trying again.");
        }

        ThrowIfCannotShare(owner);
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.FirstOrDefault(value => string.Equals(value.Name, toSite.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"IIS site '{toSite}' was not found. Run 'list-sites' to see the site names.");
        var existing = FindExistingRecordToReplace(records, owner, site.Name, replaceExisting);
        var targetHosts = ResolveHosts(owner, site, sites, hosts);
        var installed = await certificateStore.FindByThumbprintAsync(owner.Thumbprint, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException(
                $"Certificate {owner.Thumbprint} is not in LocalMachine\\My. Renew it first with 'SSLense.Cli renew --site \"{owner.SiteName}\" --force'.");
        if (!installed.HasPrivateKey)
        {
            throw new InvalidOperationException($"Certificate {owner.Thumbprint} has no usable private key, so no site can use it.");
        }

        var updated = owner.WithTargets([.. owner.AllTargets(), new CertificateTarget(site.Name, targetHosts)]);
        var transaction = await journal.BeginAsync(updated, owner.Thumbprint, CancellationToken.None).ConfigureAwait(false);
        await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.CertificateImported, CancellationToken.None)
            .ConfigureAwait(false);
        try
        {
            progress?.Report(new ProgressEvent("binding", $"Binding IIS site '{site.Name}' to certificate {owner.Thumbprint}, then confirming over HTTPS."));
            await iisService.ConfigureHttpsBindingsAsync(site.Name, targetHosts, owner.Thumbprint, "My", cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IisBindingException exception) when (exception.PreviousBindingsRestored)
        {
            await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
            throw;
        }

        await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.BindingsUpdated, CancellationToken.None)
            .ConfigureAwait(false);
        progress?.Report(new ProgressEvent("state", "Saving the managed certificate record."));
        await managedStore.UpsertAsync(updated, CancellationToken.None).ConfigureAwait(false);
        if (existing is not null)
        {
            await managedStore.RemoveAsync(existing.SiteName, CancellationToken.None).ConfigureAwait(false);
        }

        await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.StateSaved, CancellationToken.None)
            .ConfigureAwait(false);
        await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);

        // Only a certificate SSLense obtained is removed; one from another provider may have cost money or be used elsewhere.
        if (existing is { Source: CertificateSource.Acme })
        {
            try
            {
                if (await ReplacedCertificateCleanup
                        .RemoveIfUnusedAsync(iisService, certificateStore, existing.Thumbprint, owner.Thumbprint, CancellationToken.None)
                        .ConfigureAwait(false) is { } message)
                {
                    progress?.Report(new ProgressEvent("cleanup", $"The site is shared, but {message}"));
                }
            }
            catch (Exception exception)
            {
                progress?.Report(new ProgressEvent("cleanup", $"The site is shared, but its old certificate could not be checked for removal: {exception.Message}"));
            }
        }

        return targetHosts;
    }

    public async Task<string> RemoveSiteAsync(string siteName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        var before = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var ownerBefore = FindOwner(before, siteName);
        await using var siteLocks = await operationLock
            .AcquireAllAsync(ownerBefore.AllSiteNames(), cancellationToken)
            .ConfigureAwait(false);

        var owner = FindOwner(await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false), siteName);
        if (!owner.IsShared())
        {
            throw new InvalidOperationException(
                $"The certificate for IIS site '{owner.SiteName}' is not shared. To stop managing it and remove its HTTPS bindings, " +
                $"use 'SSLense.Cli remove --site \"{owner.SiteName}\"'.");
        }

        var remaining = owner.AllTargets()
            .Where(target => !string.Equals(target.SiteName, siteName.Trim(), StringComparison.OrdinalIgnoreCase))
            .ToArray();
        await managedStore.ReplaceAsync(owner.SiteName, owner.WithTargets(remaining), CancellationToken.None).ConfigureAwait(false);
        return $"SSLense no longer manages IIS site '{siteName.Trim()}'. Its HTTPS binding was not changed, so the site keeps working until " +
               $"certificate {owner.Thumbprint} expires on {owner.NotAfter:yyyy-MM-dd}. Give the site its own certificate before then.";
    }

    public async Task<IReadOnlyList<string>> CatchUpAsync(
        string siteName,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        var before = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(record => record.ManagesSite(siteName));
        if (before is null || !before.HasPendingSites())
        {
            return [];
        }

        // An operation in progress changes bindings; these sites are looked at again at the next check.
        await using var siteLocks = operationLock.TryAcquireAll(before.AllSiteNames());
        if (siteLocks is null)
        {
            return [];
        }

        var record = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(value => value.ManagesSite(siteName));
        if (record is null || !record.HasPendingSites() ||
            !record.AllSiteNames().ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(before.AllSiteNames()))
        {
            return [];
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var moved = new List<string>();
        var targets = new List<CertificateTarget>();
        foreach (var target in record.AllTargets())
        {
            targets.Add(target);
            if (target.PendingSince is null ||
                sites.FirstOrDefault(site => string.Equals(site.Name, target.SiteName, StringComparison.OrdinalIgnoreCase)) is not { } site ||
                !target.Hosts.All(host => HasWebBinding(site, host)))
            {
                continue;
            }

            try
            {
                progress?.Report(new ProgressEvent("binding", $"Moving IIS site '{target.SiteName}', which was left behind, to certificate {record.Thumbprint}."));
                await iisService.ConfigureHttpsBindingsAsync(target.SiteName, target.Hosts, record.Thumbprint, "My", cancellationToken)
                    .ConfigureAwait(false);
                targets[^1] = target with { PendingSince = null };
                moved.Add(target.SiteName);
            }
            catch (IisBindingException exception)
            {
                progress?.Report(new ProgressEvent("binding", $"IIS site '{target.SiteName}' stays on its previous certificate for now: {exception.Message}"));
            }
        }

        if (moved.Count > 0)
        {
            await managedStore.UpsertAsync(record.WithTargets(targets), CancellationToken.None).ConfigureAwait(false);
        }

        return moved;
    }

    private static ManagedCertificate FindOwner(IReadOnlyList<ManagedCertificate> records, string siteName) =>
        records.FirstOrDefault(record => record.ManagesSite(siteName)) ?? throw ManagedCertificateNotFound.Create(siteName, records);

    private static void ThrowIfCannotShare(ManagedCertificate owner)
    {
        if (owner.Source != CertificateSource.Acme)
        {
            throw new InvalidOperationException(
                $"The certificate for IIS site '{owner.SiteName}' came from another provider. Only certificates SSLense obtains can be shared for now.");
        }

        if (owner.ValidationMethod == ValidationMethod.Http01)
        {
            throw new InvalidOperationException(
                $"The certificate for IIS site '{owner.SiteName}' uses HTTP validation. Sharing needs DNS validation, because HTTP validation would have to reach every site. " +
                "Issue the certificate again with --validation dns.");
        }
    }

    private static ManagedCertificate? FindExistingRecordToReplace(
        IReadOnlyList<ManagedCertificate> records,
        ManagedCertificate owner,
        string siteName,
        bool replaceExisting)
    {
        if (owner.ManagesSite(siteName))
        {
            throw new InvalidOperationException($"IIS site '{siteName}' already uses this certificate.");
        }

        ManagedCertificateTargets.ThrowIfAdditionalSite(records, siteName);
        var existing = records.FirstOrDefault(record => string.Equals(record.SiteName, siteName, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            return null;
        }

        if (existing.IsShared())
        {
            throw new InvalidOperationException(
                $"IIS site '{siteName}' has its own certificate, shared with other sites. Stop sharing that one first with 'SSLense.Cli share remove'.");
        }

        return replaceExisting
            ? existing
            : throw new InvalidOperationException(
                $"IIS site '{siteName}' has its own certificate ({existing.Thumbprint}). To replace it with the shared one, add --replace-existing.");
    }

    private static string[] ResolveHosts(
        ManagedCertificate owner,
        IisSite site,
        IReadOnlyList<IisSite> sites,
        IReadOnlyList<string> requested)
    {
        var names = owner.CertificateNames ?? owner.Hosts;
        var hosts = (requested.Count > 0
                ? requested
                : site.Bindings.Where(IsWebBinding).Select(binding => binding.HostName)
                    .Where(host => host.Length > 0 && !host.Contains('*') && CertificateInspector.Covers(names, host)))
            .Select(NormalizeHost)
            .Where(host => host.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (hosts.Length == 0)
        {
            throw new InvalidOperationException(
                $"IIS site '{site.Name}' has no named bindings that the certificate covers ({string.Join(", ", names)}). Add a binding, or list the hosts with --hosts.");
        }

        foreach (var host in hosts)
        {
            if (host.Contains('*') || Uri.CheckHostName(host) != UriHostNameType.Dns)
            {
                throw new ArgumentException($"'{host}' cannot be used as a host name, because SSLense manages IIS bindings for real host names only.", nameof(requested));
            }

            if (!CertificateInspector.Covers(names, host))
            {
                throw new InvalidOperationException($"The certificate does not cover host name '{host}'. It covers {string.Join(", ", names)}.");
            }

            if (!HasWebBinding(site, host))
            {
                throw new InvalidOperationException($"Host name '{host}' does not have an HTTP or HTTPS binding for IIS site '{site.Name}'.");
            }

            if (sites.FirstOrDefault(other =>
                    !string.Equals(other.Name, site.Name, StringComparison.OrdinalIgnoreCase) &&
                    other.Bindings.Any(binding =>
                        string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
                        binding.Port == 443 &&
                        string.Equals(NormalizeHost(binding.HostName), host, StringComparison.OrdinalIgnoreCase))) is { } conflict)
            {
                throw new InvalidOperationException($"Host name '{host}' is already bound to HTTPS on IIS site '{conflict.Name}'.");
            }
        }

        return hosts;
    }

    private static bool HasWebBinding(IisSite site, string host) =>
        site.Bindings.Any(binding => IsWebBinding(binding) &&
            string.Equals(NormalizeHost(binding.HostName), NormalizeHost(host), StringComparison.OrdinalIgnoreCase));

    private static bool IsWebBinding(IisBinding binding) =>
        string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase);

    private static string NormalizeHost(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();
}

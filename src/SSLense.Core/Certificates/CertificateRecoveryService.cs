using SSLense.Core.Validation;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

internal sealed class CertificateRecoveryService(
    ICertificateTransactionJournal journal,
    ICertificateOperationLock operationLock,
    ICertificateStore certificateStore,
    IManagedCertificateStore managedStore,
    IIisService iisService,
    IChallengeHandler? challengeHandler = null,
    IDnsChallengeService? dnsChallenges = null) : ICertificateRecoveryService
{
    public async Task<IReadOnlyList<CertificateRecoveryResult>> RecoverAsync(
        CancellationToken cancellationToken = default)
    {
        var results = new List<CertificateRecoveryResult>();
        if (challengeHandler is not null)
        {
            try
            {
                results.AddRange(
                    (await challengeHandler.CleanUpAbandonedAsync(cancellationToken).ConfigureAwait(false))
                    .Select(message => new CertificateRecoveryResult(true, message)));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new CertificateRecoveryResult(
                    false,
                    $"Leftover HTTP-01 challenge files could not be cleaned up: {exception.Message} " +
                    "It will be retried on the next start."));
            }
        }

        try
        {
            await iisService.RemoveCertificateTrialAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Harmless, so not worth reporting: nothing uses that host name, and it is deleted again before the next trial.
        }

        if (dnsChallenges is not null)
        {
            try
            {
                results.AddRange(
                    (await dnsChallenges.CleanUpAbandonedAsync(cancellationToken).ConfigureAwait(false))
                    .Select(message => new CertificateRecoveryResult(true, message)));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new CertificateRecoveryResult(
                    false,
                    $"Leftover DNS challenge records could not be cleaned up: {exception.Message} " +
                    "It will be retried on the next start."));
            }
        }

        IReadOnlyList<CertificateTransaction> pending;
        try
        {
            pending = await journal.GetPendingAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            results.Add(new CertificateRecoveryResult(
                false,
                $"Interrupted certificate operations could not be read: {exception.Message}"));
            return results;
        }

        foreach (var snapshot in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var siteName = snapshot.Certificate.SiteName;

            // A held lock means a live GUI, CLI, or service process still owns this transaction.
            await using var siteLock = operationLock.TryAcquireAll(snapshot.Certificate.AllSiteNames());
            if (siteLock is null)
            {
                continue;
            }

            try
            {
                var transaction = await journal.GetAsync(snapshot.Id, cancellationToken).ConfigureAwait(false);
                if (transaction is null)
                {
                    continue;
                }

                // Leave the entry untouched so the newer version that wrote it can finish it.
                StateSchema.EnsureSupported(
                    transaction.SchemaVersion,
                    StateSchema.Transactions,
                    $"certificate transaction {transaction.Id:N}");
                results.Add(await RecoverOneAsync(transaction, cancellationToken).ConfigureAwait(false));
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                results.Add(new CertificateRecoveryResult(
                    false,
                    $"Could not recover certificate transaction {snapshot.Id:N} for '{siteName}': " +
                    $"{exception.Message} It will be retried on the next start."));
            }
        }

        return results;
    }

    private async Task<CertificateRecoveryResult> RecoverOneAsync(
        CertificateTransaction transaction,
        CancellationToken cancellationToken)
    {
        var recovered = new CertificateRecoveryResult(
            true,
            $"Recovered certificate transaction {transaction.Id:N} for '{transaction.Certificate.SiteName}'.");
        if (transaction.Stage == CertificateTransactionStage.StateSaved)
        {
            await journal.CompleteAsync(transaction.Id, cancellationToken).ConfigureAwait(false);
            return recovered;
        }

        var certificate = transaction.Certificate;
        var installed = await certificateStore
            .FindByThumbprintAsync(certificate.Thumbprint, cancellationToken)
            .ConfigureAwait(false);
        if (installed is null)
        {
            await journal.CompleteAsync(transaction.Id, cancellationToken).ConfigureAwait(false);
            return recovered;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        if (certificate.IsShared())
        {
            return await RecoverSharedAsync(transaction, sites, recovered, cancellationToken).ConfigureAwait(false);
        }

        var site = sites.SingleOrDefault(value => string.Equals(
            value.Name,
            certificate.SiteName,
            StringComparison.OrdinalIgnoreCase));
        if (site is null)
        {
            // Nothing can be bound any more; retrying on every start would never succeed.
            await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
            return new CertificateRecoveryResult(
                false,
                $"Abandoned certificate transaction {transaction.Id:N} because IIS site " +
                $"'{certificate.SiteName}' no longer exists. Certificate {certificate.Thumbprint} " +
                "was left in LocalMachine\\My for manual review.");
        }
        if (!AllBindingsActive(site, certificate.Hosts, certificate.Thumbprint))
        {
            await iisService.ConfigureHttpsBindingsAsync(
                    certificate.SiteName,
                    certificate.Hosts,
                    certificate.Thumbprint,
                    "My",
                    cancellationToken)
                .ConfigureAwait(false);
        }

        await FinishAsync(transaction, certificate).ConfigureAwait(false);
        return recovered;
    }

    /// <summary>
    /// Finishes the sites one at a time, as the interrupted operation did. A site left out of the operation, or deleted since,
    /// is marked as left behind. Any other failure keeps the entry, and the old certificate, for the next start.
    /// </summary>
    private async Task<CertificateRecoveryResult> RecoverSharedAsync(
        CertificateTransaction transaction,
        IReadOnlyList<IisSite> sites,
        CertificateRecoveryResult recovered,
        CancellationToken cancellationToken)
    {
        var certificate = transaction.Certificate;
        var targets = new List<CertificateTarget>();
        foreach (var target in certificate.AllTargets())
        {
            var site = sites.FirstOrDefault(value => string.Equals(value.Name, target.SiteName, StringComparison.OrdinalIgnoreCase));
            if (target.PendingSince is not null || site is null)
            {
                targets.Add(target with { PendingSince = target.PendingSince ?? transaction.StartedAt });
                continue;
            }

            if (!AllBindingsActive(site, target.Hosts, certificate.Thumbprint))
            {
                await iisService.ConfigureHttpsBindingsAsync(target.SiteName, target.Hosts, certificate.Thumbprint, "My", cancellationToken)
                    .ConfigureAwait(false);
            }

            targets.Add(target);
        }

        await FinishAsync(transaction, certificate.WithTargets(targets)).ConfigureAwait(false);
        return recovered;
    }

    private async Task FinishAsync(CertificateTransaction transaction, ManagedCertificate certificate)
    {
        await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.BindingsUpdated,
                CancellationToken.None)
            .ConfigureAwait(false);
        await managedStore.UpsertAsync(certificate, CancellationToken.None).ConfigureAwait(false);

        // 'share add --replace-existing' may have stopped before removing the site's old record.
        foreach (var target in certificate.AdditionalTargets ?? [])
        {
            await managedStore.RemoveAsync(target.SiteName, CancellationToken.None).ConfigureAwait(false);
        }

        await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.StateSaved,
                CancellationToken.None)
            .ConfigureAwait(false);
        await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
    }

    private static bool AllBindingsActive(IisSite site, IReadOnlyList<string> hosts, string thumbprint) =>
        hosts.All(host => site.Bindings.Any(binding =>
            string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
            binding.Port == 443 &&
            string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                NormalizeThumbprint(binding.CertificateThumbprint),
                NormalizeThumbprint(thumbprint),
                StringComparison.Ordinal)));

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(Uri.IsHexDigit)).ToUpperInvariant();
}

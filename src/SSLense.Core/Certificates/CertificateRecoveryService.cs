using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

internal sealed class CertificateRecoveryService(
    ICertificateTransactionJournal journal,
    ICertificateOperationLock operationLock,
    ICertificateStore certificateStore,
    IManagedCertificateStore managedStore,
    IIisService iisService) : ICertificateRecoveryService
{
    public async Task<IReadOnlyList<string>> RecoverAsync(
        CancellationToken cancellationToken = default)
    {
        var recovered = new List<string>();
        var pending = await journal.GetPendingAsync(cancellationToken).ConfigureAwait(false);
        foreach (var snapshot in pending)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using var siteLock = await operationLock
                .AcquireAsync(snapshot.Certificate.SiteName, cancellationToken)
                .ConfigureAwait(false);
            var transaction = await journal.GetAsync(snapshot.Id, cancellationToken).ConfigureAwait(false);
            if (transaction is null)
            {
                continue;
            }

            await RecoverOneAsync(transaction, cancellationToken).ConfigureAwait(false);
            recovered.Add(
                $"Recovered certificate transaction {transaction.Id:N} for " +
                $"'{transaction.Certificate.SiteName}'.");
        }

        return recovered;
    }

    private async Task RecoverOneAsync(
        CertificateTransaction transaction,
        CancellationToken cancellationToken)
    {
        if (transaction.Stage == CertificateTransactionStage.StateSaved)
        {
            await journal.CompleteAsync(transaction.Id, cancellationToken).ConfigureAwait(false);
            return;
        }

        var certificate = transaction.Certificate;
        var installed = await certificateStore
            .FindByThumbprintAsync(certificate.Thumbprint, cancellationToken)
            .ConfigureAwait(false);
        if (installed is null)
        {
            await journal.CompleteAsync(transaction.Id, cancellationToken).ConfigureAwait(false);
            return;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var site = sites.SingleOrDefault(value => string.Equals(
            value.Name,
            certificate.SiteName,
            StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"Cannot recover certificate transaction '{transaction.Id:N}' because IIS site " +
                $"'{certificate.SiteName}' no longer exists.");
        var allBindingsActive = certificate.Hosts.All(host => site.Bindings.Any(binding =>
            string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) &&
            binding.Port == 443 &&
            string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                NormalizeThumbprint(binding.CertificateThumbprint),
                NormalizeThumbprint(certificate.Thumbprint),
                StringComparison.Ordinal)));
        if (!allBindingsActive)
        {
            await iisService.ConfigureHttpsBindingsAsync(
                    certificate.SiteName,
                    certificate.Hosts,
                    certificate.Thumbprint,
                    "My",
                    cancellationToken)
                .ConfigureAwait(false);
        }

        await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.BindingsUpdated,
                CancellationToken.None)
            .ConfigureAwait(false);
        await managedStore.UpsertAsync(certificate, CancellationToken.None).ConfigureAwait(false);
        await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.StateSaved,
                CancellationToken.None)
            .ConfigureAwait(false);
        await journal.CompleteAsync(transaction.Id, CancellationToken.None).ConfigureAwait(false);
    }

    private static string NormalizeThumbprint(string? thumbprint) =>
        string.Concat((thumbprint ?? string.Empty).Where(Uri.IsHexDigit)).ToUpperInvariant();
}

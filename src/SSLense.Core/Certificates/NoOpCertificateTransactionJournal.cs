using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

internal sealed class NoOpCertificateTransactionJournal : ICertificateTransactionJournal
{
    public Task<CertificateTransaction> BeginAsync(
        ManagedCertificate certificate,
        string? previousThumbprint,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(new CertificateTransaction(
            Guid.NewGuid(), certificate, previousThumbprint,
            CertificateTransactionStage.Prepared, DateTimeOffset.UtcNow));

    public Task UpdateStageAsync(
        Guid id,
        CertificateTransactionStage stage,
        CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<CertificateTransaction?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<CertificateTransaction?>(null);

    public Task<IReadOnlyList<CertificateTransaction>> GetPendingAsync(
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<CertificateTransaction>>([]);

    public Task CompleteAsync(Guid id, CancellationToken cancellationToken = default) =>
        Task.CompletedTask;
}

using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

public interface ICertificateTransactionJournal
{
    Task<CertificateTransaction> BeginAsync(
        ManagedCertificate certificate,
        string? previousThumbprint,
        CancellationToken cancellationToken = default);

    Task UpdateStageAsync(
        Guid id,
        CertificateTransactionStage stage,
        CancellationToken cancellationToken = default);

    Task<CertificateTransaction?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CertificateTransaction>> GetPendingAsync(
        CancellationToken cancellationToken = default);

    Task CompleteAsync(Guid id, CancellationToken cancellationToken = default);
}

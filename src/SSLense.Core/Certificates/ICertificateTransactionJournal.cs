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

    /// <summary>Replaces the certificate record the entry will save, such as when a site is left out partway through.</summary>
    Task UpdateCertificateAsync(
        Guid id,
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default);

    Task<CertificateTransaction?> GetAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CertificateTransaction>> GetPendingAsync(
        CancellationToken cancellationToken = default);

    Task CompleteAsync(Guid id, CancellationToken cancellationToken = default);
}

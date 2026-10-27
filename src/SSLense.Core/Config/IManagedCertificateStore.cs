namespace SSLense.Core.Config;

public interface IManagedCertificateStore
{
    Task<IReadOnlyList<ManagedCertificate>> GetAllAsync(
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default);

    Task RecordRenewalFailureAsync(
        string siteName,
        DateTimeOffset attemptedAt,
        string message,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string siteName, CancellationToken cancellationToken = default);
}

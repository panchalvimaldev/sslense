namespace SSLense.Core.Config;

public interface IManagedCertificateStore
{
    Task<IReadOnlyList<ManagedCertificate>> GetAllAsync(
        CancellationToken cancellationToken = default);

    /// <summary>Replaces the site's record. An empty <see cref="ManagedCertificate.Id"/> keeps the site's existing ID.</summary>
    Task UpsertAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a failed attempt, increments the consecutive-failure count, and stores the next retry time.
    /// Returns the updated record, or null when the site is no longer managed.
    /// </summary>
    Task<ManagedCertificate?> RecordRenewalFailureAsync(
        string siteName,
        DateTimeOffset attemptedAt,
        string message,
        DateTimeOffset nextRetryAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Records that an expiry notification was sent. Ignored when the site's certificate has since changed
    /// or a higher level was already recorded.
    /// </summary>
    Task RecordExpiryWarningAsync(
        string siteName,
        string thumbprint,
        ExpiryWarningLevel level,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string siteName, CancellationToken cancellationToken = default);
}

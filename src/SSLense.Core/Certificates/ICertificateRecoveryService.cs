namespace SSLense.Core.Certificates;

public interface ICertificateRecoveryService
{
    /// <summary>
    /// Completes or abandons interrupted certificate operations. Never throws for an individual
    /// transaction; failures are reported in the results so callers can keep starting up.
    /// </summary>
    Task<IReadOnlyList<CertificateRecoveryResult>> RecoverAsync(CancellationToken cancellationToken = default);
}

public sealed record CertificateRecoveryResult(bool Succeeded, string Message);

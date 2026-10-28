namespace SSLense.Core.Certificates;

public interface ICertificateRecoveryService
{
    Task<IReadOnlyList<string>> RecoverAsync(CancellationToken cancellationToken = default);
}

namespace SSLense.Core.Certificates;

public interface ICertificateManagementService
{
    Task<CertificateDetails> GetDetailsAsync(
        string siteName,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string siteName, CancellationToken cancellationToken = default);
}

namespace SSLense.Core.Certificates;

public interface ICertificateStore
{
    Task<InstalledCertificate?> FindByThumbprintAsync(
        string thumbprint,
        CancellationToken cancellationToken = default);

    Task<InstalledCertificate> ImportPfxAsync(
        byte[] pfxBytes,
        string password,
        string friendlyName,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string thumbprint, CancellationToken cancellationToken = default);
}

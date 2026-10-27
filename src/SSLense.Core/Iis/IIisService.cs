namespace SSLense.Core.Iis;

public interface IIisService
{
    Task<IReadOnlyList<IisSite>> GetSitesAsync(CancellationToken cancellationToken = default);

    Task ConfigureHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default);

    Task RemoveHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string expectedCertificateThumbprint,
        CancellationToken cancellationToken = default);
}

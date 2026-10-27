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
}

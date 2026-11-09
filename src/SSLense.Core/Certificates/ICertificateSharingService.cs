namespace SSLense.Core.Certificates;

/// <summary>Lets several IIS sites use one certificate (docs/design/shared-certificates.md).</summary>
public interface ICertificateSharingService
{
    /// <summary>
    /// Binds a site to the certificate another site already uses and records it. Never contacts the certificate authority.
    /// </summary>
    /// <param name="fromSite">Any site using the certificate.</param>
    /// <param name="toSite">The site to add.</param>
    /// <param name="hosts">The hosts to bind, or none for every named binding on the site that the certificate covers.</param>
    /// <param name="replaceExisting">Take over a site that has its own certificate, and remove that site's old record.</param>
    /// <returns>The hosts now bound on the site.</returns>
    Task<IReadOnlyList<string>> AddSiteAsync(
        string fromSite,
        string toSite,
        IReadOnlyList<string> hosts,
        bool replaceExisting = false,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops managing a site. Its binding stays as it is, so the site keeps working until the certificate expires.
    /// </summary>
    /// <returns>What the administrator should do next.</returns>
    Task<string> RemoveSiteAsync(string siteName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries to move sites left on an older certificate to the record's current one. Never contacts the certificate authority.
    /// </summary>
    /// <returns>The sites that moved.</returns>
    Task<IReadOnlyList<string>> CatchUpAsync(
        string siteName,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}

namespace SSLense.Core.Iis;

public interface IIisService
{
    Task<IReadOnlyList<IisSite>> GetSitesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Tries the certificate, then changes the site's bindings as <see cref="SwitchHttpsBindingsAsync"/> does.
    /// </summary>
    Task ConfigureHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Offers the certificate to HTTP.sys under a host name no site uses, so a certificate it refuses is found before
    /// a real site loses its binding (docs/design/shared-certificates.md, section 5.1).
    /// </summary>
    /// <exception cref="IisBindingException">HTTP.sys refused the certificate, or the trial could not run. No site changed.</exception>
    Task TryCertificateAsync(
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default);

    /// <summary>Removes an entry left by an interrupted <see cref="TryCertificateAsync"/>.</summary>
    Task RemoveCertificateTrialAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Changes one site's bindings and confirms over HTTPS that a started site serves the certificate. On failure the site
    /// is restored and the restore is checked. Returns what is needed to undo the change later.
    /// </summary>
    /// <exception cref="IisBindingException">The change failed; <see cref="IisBindingException.PreviousBindingsRestored"/> says whether the site is back as it was.</exception>
    Task<HttpsBindingUndo> SwitchHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string certificateThumbprint,
        string certificateStoreName = "My",
        CancellationToken cancellationToken = default);

    /// <summary>Restores a site to how it was before <see cref="SwitchHttpsBindingsAsync"/>, and checks the result.</summary>
    /// <exception cref="IisBindingException">The site could not be confirmed as restored.</exception>
    Task UndoHttpsBindingsAsync(HttpsBindingUndo undo, CancellationToken cancellationToken = default);

    /// <summary>What is wrong if a site's existing HTTPS bindings do not answer now, or null.</summary>
    Task<string?> GetHttpsProblemAsync(
        IisSite site,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default);

    Task RemoveHttpsBindingsAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        string expectedCertificateThumbprint,
        CancellationToken cancellationToken = default);
}

/// <param name="SiteStarted">Whether the site had a listener to check when it was changed.</param>
public sealed record HttpsBindingUndo(string SiteName, bool SiteStarted, IReadOnlyList<HttpsBindingChange> Changes);

/// <param name="WasAdded">The binding did not exist before, so undoing removes it.</param>
/// <param name="SslFlags">The binding's <c>SslFlags</c> value before the change.</param>
public sealed record HttpsBindingChange(
    string Host,
    bool WasAdded,
    string BindingInformation,
    byte[]? CertificateHash,
    string? CertificateStoreName,
    int SslFlags);

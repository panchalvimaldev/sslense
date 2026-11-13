namespace SSLense.Core.Certificates;

public interface ICertificateManagementService
{
    Task<CertificateDetails> GetDetailsAsync(
        string siteName,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(string siteName, CancellationToken cancellationToken = default);

    /// <summary>
    /// SSLense stops renewing, checking and reminding about the certificate, and changes nothing else: its IIS HTTPS
    /// bindings and the certificate in the Windows store stay, so the sites keep working until it expires.
    /// Returns what happened, in a sentence or two.
    /// </summary>
    Task<string> StopManagingAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Connects to each of the certificate's host names now, through IIS, and compares the certificate served with the
    /// one SSLense expects, on every site using it. Read-only.
    /// </summary>
    Task<CertificateCheckResult> CheckServedAsync(string name, CancellationToken cancellationToken = default);
}

/// <param name="Passed">True when every host name serves the expected certificate, or there is nothing to check.</param>
/// <param name="Message">What was found, in a sentence or two.</param>
public sealed record CertificateCheckResult(bool Passed, string Message);

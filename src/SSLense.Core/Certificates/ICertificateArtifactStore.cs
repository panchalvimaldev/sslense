using SSLense.Core.Acme;

namespace SSLense.Core.Certificates;

public interface ICertificateArtifactStore
{
    Task<AcmeIssueResult> SaveAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CertificateBundle bundle,
        string? outputDirectory,
        CancellationToken cancellationToken);
}

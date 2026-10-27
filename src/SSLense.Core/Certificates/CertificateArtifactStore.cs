using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

internal sealed class CertificateArtifactStore : ICertificateArtifactStore
{
    private readonly IFileSystem _fileSystem;

    public CertificateArtifactStore(IFileSystem fileSystem)
    {
        _fileSystem = fileSystem;
    }

    public async Task<AcmeIssueResult> SaveAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CertificateBundle bundle,
        string? outputDirectory,
        CancellationToken cancellationToken)
    {
        var directory = outputDirectory is null
            ? Path.Combine(
                AppPaths.CertificateDirectory,
                SanitizeFileName(siteName),
                DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmssfff"))
            : Path.GetFullPath(outputDirectory);

        _fileSystem.CreateDirectory(directory);
        var pemPath = Path.Combine(directory, "certificate.pem");
        var pfxPath = Path.Combine(directory, "certificate.pfx");
        await _fileSystem.WriteAllTextAsync(pemPath, bundle.CertificatePem, cancellationToken)
            .ConfigureAwait(false);
        await _fileSystem.WriteAllBytesAsync(pfxPath, bundle.PfxBytes, cancellationToken)
            .ConfigureAwait(false);
        return new AcmeIssueResult(pemPath, pfxPath, hosts);
    }

    private static string SanitizeFileName(string value)
    {
        var invalidCharacters = Path.GetInvalidFileNameChars();
        var sanitized = new string(value.Select(character =>
            invalidCharacters.Contains(character) ? '_' : character).ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "site" : sanitized;
    }
}

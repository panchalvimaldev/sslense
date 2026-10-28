using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

internal sealed class CertificateArtifactStore : ICertificateArtifactStore
{
    private readonly IFileSystem _fileSystem;
    private readonly string _defaultDirectory;

    public CertificateArtifactStore(IFileSystem fileSystem)
        : this(fileSystem, AppPaths.CertificateDirectory)
    {
    }

    internal CertificateArtifactStore(IFileSystem fileSystem, string defaultDirectory)
    {
        _fileSystem = fileSystem;
        _defaultDirectory = defaultDirectory;
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
                _defaultDirectory,
                SanitizeFileName(siteName),
                DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmssfff"))
            : Path.GetFullPath(outputDirectory);

        _fileSystem.CreateDirectory(directory);
        var pemPath = Path.Combine(directory, "certificate.pem");
        await _fileSystem.WriteAllTextAsync(pemPath, bundle.CertificatePem, cancellationToken)
            .ConfigureAwait(false);
        return new AcmeIssueResult(pemPath, null, hosts);
    }

    private static string SanitizeFileName(string value)
    {
        var invalidCharacters = Path.GetInvalidFileNameChars();
        var sanitized = new string(value.Select(character =>
            invalidCharacters.Contains(character) ? '_' : character).ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "site" : sanitized;
    }
}

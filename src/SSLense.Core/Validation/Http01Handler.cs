using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Validation;

internal sealed class Http01Handler : IChallengeHandler
{
    private const string ChallengeWebConfig = """
        <?xml version="1.0" encoding="utf-8"?>
        <configuration>
          <system.webServer>
            <validation validateIntegratedModeConfiguration="false" />
            <handlers>
              <remove name="ExtensionlessUrlHandler-Integrated-4.0" />
              <add name="SSLenseAcmeChallenge" path="*" verb="GET,HEAD" modules="StaticFileModule" resourceType="File" requireAccess="Read" />
            </handlers>
            <staticContent>
              <remove fileExtension="." />
              <mimeMap fileExtension="." mimeType="text/plain" />
            </staticContent>
            <security>
              <authorization>
                <clear />
                <add accessType="Allow" users="*" />
              </authorization>
            </security>
          </system.webServer>
        </configuration>
        """;

    private readonly IFileSystem _fileSystem;

    public Http01Handler(IFileSystem fileSystem)
    {
        _fileSystem = fileSystem;
    }

    public async Task<IAsyncDisposable> PrepareAsync(
        string sitePhysicalPath,
        AcmeHttpChallenge challenge,
        CancellationToken cancellationToken)
    {
        ValidateToken(challenge.Token);
        var siteRoot = Path.GetFullPath(sitePhysicalPath);
        if (!_fileSystem.DirectoryExists(siteRoot))
        {
            throw new DirectoryNotFoundException($"IIS site path '{siteRoot}' does not exist.");
        }

        var wellKnownDirectory = Path.Combine(siteRoot, ".well-known");
        var challengeDirectory = Path.Combine(wellKnownDirectory, "acme-challenge");
        var tokenPath = Path.Combine(challengeDirectory, challenge.Token);
        var webConfigPath = Path.Combine(challengeDirectory, "web.config");
        var createdWellKnown = !_fileSystem.DirectoryExists(wellKnownDirectory);
        var createdChallengeDirectory = !_fileSystem.DirectoryExists(challengeDirectory);
        var originalToken = _fileSystem.FileExists(tokenPath)
            ? await _fileSystem.ReadAllTextAsync(tokenPath, cancellationToken).ConfigureAwait(false)
            : null;
        var originalWebConfig = _fileSystem.FileExists(webConfigPath)
            ? await _fileSystem.ReadAllTextAsync(webConfigPath, cancellationToken).ConfigureAwait(false)
            : null;

        _fileSystem.CreateDirectory(challengeDirectory);
        var cleanup = new ChallengeCleanup(
            _fileSystem,
            tokenPath,
            originalToken,
            webConfigPath,
            originalWebConfig,
            challengeDirectory,
            wellKnownDirectory,
            createdChallengeDirectory,
            createdWellKnown);
        try
        {
            await _fileSystem.WriteAllTextAsync(tokenPath, challenge.KeyAuthorization, cancellationToken)
                .ConfigureAwait(false);
            await _fileSystem.WriteAllTextAsync(webConfigPath, ChallengeWebConfig, cancellationToken)
                .ConfigureAwait(false);
            return cleanup;
        }
        catch
        {
            await cleanup.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static void ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token) ||
            token.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            token.Contains(Path.DirectorySeparatorChar) ||
            token.Contains(Path.AltDirectorySeparatorChar))
        {
            throw new InvalidDataException("The ACME server returned an invalid HTTP-01 token.");
        }
    }

    private sealed class ChallengeCleanup(
        IFileSystem fileSystem,
        string tokenPath,
        string? originalToken,
        string webConfigPath,
        string? originalWebConfig,
        string challengeDirectory,
        string wellKnownDirectory,
        bool createdChallengeDirectory,
        bool createdWellKnown) : IAsyncDisposable
    {
        private int _disposed;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            if (originalToken is null)
            {
                fileSystem.DeleteFile(tokenPath);
            }
            else
            {
                await fileSystem.WriteAllTextAsync(tokenPath, originalToken, CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (originalWebConfig is null)
            {
                fileSystem.DeleteFile(webConfigPath);
            }
            else
            {
                await fileSystem.WriteAllTextAsync(webConfigPath, originalWebConfig, CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (createdChallengeDirectory)
            {
                fileSystem.DeleteDirectoryIfEmpty(challengeDirectory);
            }

            if (createdWellKnown)
            {
                fileSystem.DeleteDirectoryIfEmpty(wellKnownDirectory);
            }
        }
    }
}

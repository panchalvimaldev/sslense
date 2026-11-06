using SSLense.Core.Acme;
using System.Text;
using SSLense.Core.Config;
using SSLense.Core.Iis;

namespace SSLense.Core.Validation;

internal sealed class Http01Handler : IChallengeHandler
{
    private const string ChallengePath = ".well-known/acme-challenge";

    /// <summary>
    /// Each section serves the token as a plain static file. One that IIS does not let the folder set is left out, because a
    /// web.config with a locked or unknown section makes IIS answer 500.19 to every request in the folder.
    /// </summary>
    private static readonly (string Path, string Xml)[] ChallengeSections =
    [
        ("system.webServer/validation", """
                <validation validateIntegratedModeConfiguration="false" />
            """),
        ("system.webServer/handlers", """
                <handlers>
                  <remove name="ExtensionlessUrlHandler-Integrated-4.0" />
                  <add name="SSLenseAcmeChallenge" path="*" verb="GET,HEAD" modules="StaticFileModule" resourceType="File" requireAccess="Read" />
                </handlers>
            """),
        ("system.webServer/staticContent", """
                <staticContent>
                  <remove fileExtension="." />
                  <mimeMap fileExtension="." mimeType="text/plain" />
                </staticContent>
            """),
        ("system.webServer/security/authorization", """
                <security>
                  <authorization>
                    <clear />
                    <add accessType="Allow" users="*" />
                  </authorization>
                </security>
            """),
    ];

    private readonly IFileSystem _fileSystem;
    private readonly IChallengeJournal _journal;
    private readonly IIisSectionLocks? _sectionLocks;

    public Http01Handler(IFileSystem fileSystem, IChallengeJournal? journal = null, IIisSectionLocks? sectionLocks = null)
    {
        _fileSystem = fileSystem;
        _journal = journal ?? new NoOpChallengeJournal();
        _sectionLocks = sectionLocks;
    }

    /// <summary>Every section when <paramref name="settable"/> is null, because IIS configuration could not be read.</summary>
    internal static string BuildWebConfig(IReadOnlySet<string>? settable)
    {
        var builder = new StringBuilder();
        builder.AppendLine("""<?xml version="1.0" encoding="utf-8"?>""");
        builder.AppendLine("<configuration>");
        builder.AppendLine("  <system.webServer>");
        foreach (var (path, xml) in ChallengeSections)
        {
            if (settable is null || settable.Contains(path))
            {
                builder.AppendLine(xml);
            }
        }

        builder.AppendLine("  </system.webServer>");
        builder.AppendLine("</configuration>");
        return builder.ToString();
    }

    public async Task<IAsyncDisposable> PrepareAsync(
        string siteName,
        string sitePhysicalPath,
        AcmeHttpChallenge challenge,
        CancellationToken cancellationToken)
    {
        ValidateToken(challenge.Token);
        var webConfig = BuildWebConfig(
            _sectionLocks?.GetSettableSections(siteName, ChallengePath, ChallengeSections.Select(section => section.Path).ToArray()));
        var siteRoot = Path.GetFullPath(sitePhysicalPath);
        if (!_fileSystem.DirectoryExists(siteRoot))
        {
            throw new DirectoryNotFoundException($"IIS site path '{siteRoot}' does not exist.");
        }

        var wellKnownDirectory = Path.Combine(siteRoot, ".well-known");
        var challengeDirectory = Path.Combine(wellKnownDirectory, "acme-challenge");
        var tokenPath = Path.Combine(challengeDirectory, challenge.Token);
        var webConfigPath = Path.Combine(challengeDirectory, "web.config");
        var owner = JsonChallengeJournal.CurrentProcess;
        var artifacts = new ChallengeArtifacts(
            Guid.NewGuid(),
            tokenPath,
            _fileSystem.FileExists(tokenPath)
                ? await _fileSystem.ReadAllTextAsync(tokenPath, cancellationToken).ConfigureAwait(false)
                : null,
            webConfigPath,
            _fileSystem.FileExists(webConfigPath)
                ? await _fileSystem.ReadAllTextAsync(webConfigPath, cancellationToken).ConfigureAwait(false)
                : null,
            challengeDirectory,
            wellKnownDirectory,
            !_fileSystem.DirectoryExists(challengeDirectory),
            !_fileSystem.DirectoryExists(wellKnownDirectory),
            owner.ProcessId,
            owner.StartedAt,
            DateTimeOffset.UtcNow);

        // Journal first: if the process dies after this point, recovery can still restore the site.
        await _journal.RecordAsync(artifacts, cancellationToken).ConfigureAwait(false);
        var cleanup = new ChallengeCleanup(_fileSystem, _journal, artifacts);
        try
        {
            _fileSystem.CreateDirectory(challengeDirectory);
            await _fileSystem.WriteAllTextAsync(tokenPath, challenge.KeyAuthorization, cancellationToken)
                .ConfigureAwait(false);
            await _fileSystem.WriteAllTextAsync(webConfigPath, webConfig, cancellationToken)
                .ConfigureAwait(false);
            return cleanup;
        }
        catch
        {
            await cleanup.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<IReadOnlyList<string>> CleanUpAbandonedAsync(CancellationToken cancellationToken)
    {
        var messages = new List<string>();
        foreach (var artifacts in await _journal.GetAbandonedAsync(cancellationToken).ConfigureAwait(false))
        {
            await new ChallengeCleanup(_fileSystem, _journal, artifacts).DisposeAsync().ConfigureAwait(false);
            messages.Add(
                $"Removed HTTP-01 challenge files left in '{artifacts.ChallengeDirectory}' by an interrupted validation " +
                $"started {artifacts.CreatedAt:yyyy-MM-dd HH:mm} UTC.");
        }

        return messages;
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
        IChallengeJournal journal,
        ChallengeArtifacts artifacts) : IAsyncDisposable
    {
        private int _disposed;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            if (artifacts.OriginalToken is null)
            {
                fileSystem.DeleteFile(artifacts.TokenPath);
            }
            else
            {
                await fileSystem.WriteAllTextAsync(artifacts.TokenPath, artifacts.OriginalToken, CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (artifacts.OriginalWebConfig is null)
            {
                fileSystem.DeleteFile(artifacts.WebConfigPath);
            }
            else
            {
                await fileSystem.WriteAllTextAsync(artifacts.WebConfigPath, artifacts.OriginalWebConfig, CancellationToken.None)
                    .ConfigureAwait(false);
            }

            if (artifacts.CreatedChallengeDirectory)
            {
                fileSystem.DeleteDirectoryIfEmpty(artifacts.ChallengeDirectory);
            }

            if (artifacts.CreatedWellKnown)
            {
                fileSystem.DeleteDirectoryIfEmpty(artifacts.WellKnownDirectory);
            }

            // Only once the site is restored, so a failure above leaves the entry for recovery to retry.
            await journal.CompleteAsync(artifacts.Id).ConfigureAwait(false);
        }
    }
}

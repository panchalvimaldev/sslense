using System.Security.Cryptography;
using System.Text.RegularExpressions;
using SSLense.Core.Config;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// SSLense's own copies of DNS scripts. The service runs as SYSTEM, so it never runs the administrator's original file,
/// which anyone able to change it could use to run code as SYSTEM (docs/design/dns-script.md, section 4).
/// </summary>
internal interface IDnsScriptStore
{
    /// <summary>Copies the script into SSLense's folder and returns the copy's SHA-256.</summary>
    Task<string> SaveAsync(string providerName, string sourcePath, CancellationToken cancellationToken);

    /// <summary>The copy's path, once it is confirmed to be SSLense's own unchanged copy; otherwise throws.</summary>
    string GetVerifiedPath(string providerName, string sha256);

    /// <summary>Why the copy cannot be trusted; empty when it can.</summary>
    IReadOnlyList<string> Inspect(string providerName, string sha256);

    /// <summary>Removes a copy that is no longer used. A copy that cannot be removed is left; it is never run.</summary>
    void Delete(string providerName, string sha256);

    /// <summary>Removes copies whose owner is not in <paramref name="keep"/> and that are older than <paramref name="minimumAge"/>.</summary>
    /// <returns>How many copies were removed.</returns>
    int DeleteUnused(IReadOnlySet<string> keep, TimeSpan minimumAge);
}

internal sealed partial class DnsScriptStore : IDnsScriptStore
{
    private const int MaxScriptBytes = 1024 * 1024;

    private static readonly string[] ReservedNames =
        ["CON", "PRN", "AUX", "NUL", .. Enumerable.Range(1, 9).SelectMany(digit => new[] { $"COM{digit}", $"LPT{digit}" })];

    private readonly string _directory;
    private readonly bool _secure;
    private readonly string _owner;
    private readonly Func<string, string> _refreshHint;

    public DnsScriptStore()
        : this(AppPaths.DnsScriptDirectory, secure: true)
    {
    }

    /// <param name="secure">False only in tests, which run without elevation and so cannot set owners.</param>
    /// <param name="owner">What the scripts belong to, for messages, such as "DNS provider".</param>
    /// <param name="refreshHint">How to take a new copy of a script that can no longer be trusted, given the owner's name.</param>
    internal DnsScriptStore(string directory, bool secure, string owner = "DNS provider", Func<string, string>? refreshHint = null)
    {
        _directory = directory;
        _secure = secure;
        _owner = owner;
        _refreshHint = refreshHint ??
            (name => $"Check the original script, then take a new copy with 'SSLense.Cli dns update-script --name \"{name}\" --script <path>'.");
    }

    /// <summary>SSLense's copies of deployment step scripts, named by step.</summary>
    public static DnsScriptStore ForDeploymentScripts() =>
        new(
            AppPaths.DeployScriptDirectory,
            secure: true,
            "deployment step",
            _ => "Check the original script, then remove the step and add it again with 'SSLense.Cli deploy add'.");

    /// <summary>A provider name that can safely be part of a file name.</summary>
    public static void ValidateName(string name)
    {
        if (!SafeName().IsMatch(name) || ReservedNames.Contains(name.Split('.')[0], StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentException(
                $"'{name}' cannot name a script provider. Use letters, digits, spaces, dots, hyphens, and underscores, " +
                "starting and ending with a letter or digit, up to 64 characters.");
        }
    }

    public async Task<string> SaveAsync(string providerName, string sourcePath, CancellationToken cancellationToken)
    {
        ValidateName(providerName);
        var source = Path.GetFullPath(sourcePath.Trim().Trim('"'));
        if (!string.Equals(Path.GetExtension(source), ".ps1", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException($"'{source}' is not a PowerShell script. The script must be a .ps1 file.");
        }

        var file = new FileInfo(source);
        if (!file.Exists)
        {
            throw new FileNotFoundException($"The script '{source}' was not found.", source);
        }

        if (file.Length > MaxScriptBytes)
        {
            throw new ArgumentException($"'{source}' is larger than 1 MB, which is far more than a DNS script needs.");
        }

        var content = await File.ReadAllBytesAsync(source, cancellationToken).ConfigureAwait(false);
        var sha256 = Convert.ToHexString(SHA256.HashData(content));

        var directory = Directory.CreateDirectory(_directory);
        if (directory.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException($"'{_directory}' is a link or junction. Remove it and let SSLense recreate it.");
        }

        var target = PathFor(providerName, sha256);
        var temporary = $"{target}.{Guid.NewGuid():N}.tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await stream.WriteAsync(content, cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, target, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }

        if (_secure)
        {
            DataDirectorySecurity.SecureFile(target);
        }

        _ = GetVerifiedPath(providerName, sha256);
        return sha256;
    }

    public string GetVerifiedPath(string providerName, string sha256)
    {
        var problems = Inspect(providerName, sha256);
        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                $"SSLense will not run the script for {_owner} '{providerName}': {string.Join(" ", problems)} {_refreshHint(providerName)}");
        }

        return PathFor(providerName, sha256);
    }

    public IReadOnlyList<string> Inspect(string providerName, string sha256)
    {
        var path = PathFor(providerName, sha256);
        if (!File.Exists(path))
        {
            return [$"its copy '{path}' is missing."];
        }

        var problems = new List<string>();
        if (_secure)
        {
            problems.AddRange(DataDirectorySecurity.VerifyFile(path));
        }
        else if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        {
            problems.Add($"'{path}' is a link.");
        }

        if (problems.Count == 0 &&
            !string.Equals(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))), sha256, StringComparison.OrdinalIgnoreCase))
        {
            problems.Add($"its copy '{path}' was changed after SSLense saved it.");
        }

        return problems;
    }

    public void Delete(string providerName, string sha256)
    {
        try
        {
            File.Delete(PathFor(providerName, sha256));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    public int DeleteUnused(IReadOnlySet<string> keep, TimeSpan minimumAge)
    {
        if (!Directory.Exists(_directory))
        {
            return 0;
        }

        var removed = 0;
        foreach (var path in Directory.EnumerateFiles(_directory, "*.ps1"))
        {
            // The name is "<owner>-<16 hex characters>.ps1"; anything else is not SSLense's.
            var name = Path.GetFileNameWithoutExtension(path);
            var dash = name.LastIndexOf('-');
            if (dash <= 0 || name.Length - dash - 1 != 16 || keep.Contains(name[..dash]) ||
                DateTime.UtcNow - File.GetLastWriteTimeUtc(path) < minimumAge)
            {
                continue;
            }

            try
            {
                File.Delete(path);
                removed++;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        return removed;
    }

    /// <summary>The hash is part of the name, so an update can be checked before the copy it replaces is removed.</summary>
    private string PathFor(string providerName, string sha256) =>
        Path.Combine(_directory, $"{providerName}-{sha256[..Math.Min(16, sha256.Length)].ToLowerInvariant()}.ps1");

    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,62}[A-Za-z0-9])?$")]
    private static partial Regex SafeName();
}

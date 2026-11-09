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
}

internal sealed partial class DnsScriptStore : IDnsScriptStore
{
    private const int MaxScriptBytes = 1024 * 1024;

    private static readonly string[] ReservedNames =
        ["CON", "PRN", "AUX", "NUL", .. Enumerable.Range(1, 9).SelectMany(digit => new[] { $"COM{digit}", $"LPT{digit}" })];

    private readonly string _directory;
    private readonly bool _secure;

    public DnsScriptStore()
        : this(AppPaths.DnsScriptDirectory, secure: true)
    {
    }

    /// <param name="secure">False only in tests, which run without elevation and so cannot set owners.</param>
    internal DnsScriptStore(string directory, bool secure)
    {
        _directory = directory;
        _secure = secure;
    }

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
                $"SSLense will not run the script for DNS provider '{providerName}': {string.Join(" ", problems)} " +
                $"Check the original script, then take a new copy with 'SSLense.Cli dns update-script --name \"{providerName}\" --script <path>'.");
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

    /// <summary>The hash is part of the name, so an update can be checked before the copy it replaces is removed.</summary>
    private string PathFor(string providerName, string sha256) =>
        Path.Combine(_directory, $"{providerName}-{sha256[..Math.Min(16, sha256.Length)].ToLowerInvariant()}.ps1");

    [GeneratedRegex("^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,62}[A-Za-z0-9])?$")]
    private static partial Regex SafeName();
}

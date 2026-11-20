using SSLense.Core.Config;
using SSLense.Core.Errors;

namespace SSLense.Core.Validation;

/// <summary>
/// HTTP validation in a web farm (docs/design/web-farms.md): the CA may reach any server behind the load balancer, so
/// each challenge is written to the other servers' site folders too.
/// </summary>
public interface IWebFarmService
{
    /// <summary>Saves the folders a certificate's challenges are copied to; an empty list stops copying.</summary>
    Task<IReadOnlyList<string>> SetFoldersAsync(string name, IReadOnlyList<string> folders, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetFoldersAsync(string name, CancellationToken cancellationToken = default);
}

internal sealed class WebFarmService(IManagedCertificateStore store, IFileSystem fileSystem) : IWebFarmService
{
    public const int MaxFolders = 16;

    public async Task<IReadOnlyList<string>> SetFoldersAsync(string name, IReadOnlyList<string> folders, CancellationToken cancellationToken = default)
    {
        var record = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        var checkedFolders = Check(folders, fileSystem);
        if (checkedFolders.Count > 0 && (record.ValidationMethod != ValidationMethod.Http01 || record.SelfHostedHttp))
        {
            throw new ArgumentException(ErrorCodes.FarmFolderInvalid.Format(
                $"'{record.SiteName}' is not validated over HTTP from its IIS site, so there is nothing to copy. DNS validation already works in a web farm."));
        }

        await store.UpdateRecordAsync(record.Id, current => current with { FarmFolders = checkedFolders.Count == 0 ? null : checkedFolders }, cancellationToken)
            .ConfigureAwait(false);
        return checkedFolders;
    }

    public async Task<IReadOnlyList<string>> GetFoldersAsync(string name, CancellationToken cancellationToken = default) =>
        (await FindAsync(name, cancellationToken).ConfigureAwait(false)).FarmFolders ?? [];

    /// <summary>Full paths to folders that exist, normally UNC paths to each server's site root; WebDAV works as \\host@SSL\DavWWWRoot\path.</summary>
    internal static IReadOnlyList<string> Check(IReadOnlyList<string> folders, IFileSystem fileSystem)
    {
        var result = folders
            .Select(folder => folder.Trim().Trim('"').TrimEnd('\\'))
            .Where(folder => folder.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (result.Length > MaxFolders)
        {
            throw new ArgumentException(ErrorCodes.FarmFolderInvalid.Format($"A certificate can copy its challenges to at most {MaxFolders} folders."));
        }

        foreach (var folder in result)
        {
            if (!Path.IsPathFullyQualified(folder))
            {
                throw new ArgumentException(ErrorCodes.FarmFolderInvalid.Format($"'{folder}' must be a full path, normally a UNC path such as \\\\web2\\c$\\inetpub\\shop."));
            }

            if (!fileSystem.DirectoryExists(folder))
            {
                throw new ArgumentException(ErrorCodes.FarmFolderInvalid.Format(
                    $"'{folder}' cannot be reached from this server. Check the share and that the account SSLense runs as (SYSTEM: the computer account) may write to it."));
            }
        }

        return result;
    }

    private async Task<ManagedCertificate> FindAsync(string name, CancellationToken cancellationToken)
    {
        var records = await store.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return records.FirstOrDefault(value => string.Equals(value.SiteName, name.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw ManagedCertificateNotFound.Create(name, records);
    }
}

/// <summary>Removes every copied challenge, the last first, even when one removal fails.</summary>
internal sealed class FarmChallengeCopies(List<IAsyncDisposable> copies) : IAsyncDisposable
{
    public async ValueTask DisposeAsync()
    {
        for (var index = copies.Count - 1; index >= 0; index--)
        {
            try
            {
                await copies[index].DisposeAsync().ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // The challenge journal removes it at the next start.
            }
        }
    }
}

using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

internal sealed class CertificateOperationLock(IFileSystem fileSystem) : ICertificateOperationLock
{
    public Task<IAsyncDisposable> AcquireAsync(
        string siteName,
        CancellationToken cancellationToken = default) =>
        fileSystem.AcquireExclusiveFileLockAsync(GetLockPath(siteName), cancellationToken);

    public IAsyncDisposable? TryAcquire(string siteName) =>
        fileSystem.TryAcquireExclusiveFileLock(GetLockPath(siteName));

    /// <summary>
    /// One lock per IIS site: every certificate on a site changes that site's bindings, so they take turns
    /// (docs/design/multiple-certificates-per-site.md).
    /// </summary>
    private static string GetLockPath(string siteName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        var normalizedName = ManagedCertificateNames.IisSiteOf(siteName).ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedName)));
        return Path.Combine(AppPaths.OperationLockDirectory, $"{hash}.lock");
    }
}

internal sealed class NoOpCertificateOperationLock : ICertificateOperationLock
{
    public Task<IAsyncDisposable> AcquireAsync(
        string siteName,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IAsyncDisposable>(new Scope());

    public IAsyncDisposable? TryAcquire(string siteName) => new Scope();

    private sealed class Scope : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

internal static class CertificateOperationLockExtensions
{
    /// <summary>
    /// Takes every site's lock in one sorted order, so two processes working on overlapping sites cannot deadlock.
    /// </summary>
    public static async Task<IAsyncDisposable> AcquireAllAsync(
        this ICertificateOperationLock operationLock,
        IEnumerable<string> siteNames,
        CancellationToken cancellationToken = default)
    {
        var held = new List<IAsyncDisposable>();
        try
        {
            foreach (var siteName in InLockOrder(siteNames))
            {
                held.Add(await operationLock.AcquireAsync(siteName, cancellationToken).ConfigureAwait(false));
            }

            return new AllLocks(held);
        }
        catch
        {
            await new AllLocks(held).DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Returns null, holding nothing, when another process holds any of the locks.</summary>
    public static IAsyncDisposable? TryAcquireAll(this ICertificateOperationLock operationLock, IEnumerable<string> siteNames)
    {
        var held = new List<IAsyncDisposable>();
        foreach (var siteName in InLockOrder(siteNames))
        {
            if (operationLock.TryAcquire(siteName) is not { } siteLock)
            {
                // Each lock is a file handle, released as soon as it is disposed.
                new AllLocks(held).DisposeAsync().AsTask().GetAwaiter().GetResult();
                return null;
            }

            held.Add(siteLock);
        }

        return new AllLocks(held);
    }

    private static IEnumerable<string> InLockOrder(IEnumerable<string> siteNames) =>
        // Two certificates on one site share its lock, which must be taken once.
        siteNames
            .Select(ManagedCertificateNames.IisSiteOf)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(siteName => siteName.ToUpperInvariant(), StringComparer.Ordinal);

    private sealed class AllLocks(List<IAsyncDisposable> held) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            for (var index = held.Count - 1; index >= 0; index--)
            {
                await held[index].DisposeAsync().ConfigureAwait(false);
            }

            held.Clear();
        }
    }
}

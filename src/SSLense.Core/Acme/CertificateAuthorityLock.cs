using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Config;

namespace SSLense.Core.Acme;

/// <summary>
/// Keeps a certificate authority from being removed while a certificate is being issued from it, across processes: the
/// GUI, the CLI, and the service. Issuing holds it shared, so issues never wait for each other; removing holds it alone.
/// </summary>
internal interface ICertificateAuthorityLock
{
    /// <summary>Shared with other issues from the same CA. Waits while the CA is being removed.</summary>
    Task<IAsyncDisposable> AcquireUseAsync(string authorityId, CancellationToken cancellationToken);

    /// <summary>Waits until no certificate is being issued from the CA, then keeps any new issue waiting.</summary>
    Task<IAsyncDisposable> AcquireRemovalAsync(string authorityId, CancellationToken cancellationToken);
}

/// <summary>
/// Windows file sharing does the work: holders for use open the lock file for reading and let others read; the remover
/// opens it for writing and lets nobody else in. A process that exits releases its handle, so nothing is left locked.
/// </summary>
internal sealed class FileCertificateAuthorityLock(string directory) : ICertificateAuthorityLock
{
    private static readonly TimeSpan RetryInterval = TimeSpan.FromMilliseconds(200);
    private static readonly TimeSpan UseTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan RemovalTimeout = TimeSpan.FromSeconds(30);

    public FileCertificateAuthorityLock()
        : this(AppPaths.OperationLockDirectory)
    {
    }

    public Task<IAsyncDisposable> AcquireUseAsync(string authorityId, CancellationToken cancellationToken) =>
        AcquireAsync(
            authorityId,
            FileAccess.Read,
            FileShare.Read,
            UseTimeout,
            $"Certificate authority '{authorityId}' was being removed for too long, so nothing was ordered. Try again.",
            cancellationToken);

    public Task<IAsyncDisposable> AcquireRemovalAsync(string authorityId, CancellationToken cancellationToken) =>
        AcquireAsync(
            authorityId,
            FileAccess.ReadWrite,
            FileShare.None,
            RemovalTimeout,
            $"A certificate is being issued from '{authorityId}' right now, so it was not removed. Try again when that finishes.",
            cancellationToken);

    private async Task<IAsyncDisposable> AcquireAsync(
        string authorityId,
        FileAccess access,
        FileShare share,
        TimeSpan timeout,
        string timeoutMessage,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(directory);
        var path = PathFor(authorityId);
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new Held(new FileStream(path, FileMode.OpenOrCreate, access, share));
            }
            catch (IOException) when (DateTimeOffset.UtcNow < deadline)
            {
                // Held the other way by another issue or removal; it is released within seconds or minutes.
            }
            catch (IOException exception)
            {
                throw new InvalidOperationException(timeoutMessage, exception);
            }

            await Task.Delay(RetryInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private string PathFor(string authorityId)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(authorityId.Trim().ToLowerInvariant())));
        return Path.Combine(directory, $"ca-{hash[..32]}.lock");
    }

    private sealed class Held(FileStream stream) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => stream.DisposeAsync();
    }
}

internal sealed class NoOpCertificateAuthorityLock : ICertificateAuthorityLock
{
    public static NoOpCertificateAuthorityLock Instance { get; } = new();

    public Task<IAsyncDisposable> AcquireUseAsync(string authorityId, CancellationToken cancellationToken) =>
        Task.FromResult<IAsyncDisposable>(new Scope());

    public Task<IAsyncDisposable> AcquireRemovalAsync(string authorityId, CancellationToken cancellationToken) =>
        Task.FromResult<IAsyncDisposable>(new Scope());

    private sealed class Scope : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

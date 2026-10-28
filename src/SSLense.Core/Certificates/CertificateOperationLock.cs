using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Config;

namespace SSLense.Core.Certificates;

internal sealed class CertificateOperationLock(IFileSystem fileSystem) : ICertificateOperationLock
{
    public Task<IAsyncDisposable> AcquireAsync(
        string siteName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(siteName);
        var normalizedName = siteName.Trim().ToUpperInvariant();
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedName)));
        return fileSystem.AcquireExclusiveFileLockAsync(
            Path.Combine(AppPaths.OperationLockDirectory, $"{hash}.lock"),
            cancellationToken);
    }
}

internal sealed class NoOpCertificateOperationLock : ICertificateOperationLock
{
    public Task<IAsyncDisposable> AcquireAsync(
        string siteName,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IAsyncDisposable>(new Scope());

    private sealed class Scope : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

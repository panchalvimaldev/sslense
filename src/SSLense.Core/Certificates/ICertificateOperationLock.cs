namespace SSLense.Core.Certificates;

public interface ICertificateOperationLock
{
    Task<IAsyncDisposable> AcquireAsync(
        string siteName,
        CancellationToken cancellationToken = default);

    /// <summary>Returns null when another process currently holds the lock for the site.</summary>
    IAsyncDisposable? TryAcquire(string siteName);
}

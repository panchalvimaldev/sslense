namespace SSLense.Core.Certificates;

public interface ICertificateOperationLock
{
    Task<IAsyncDisposable> AcquireAsync(
        string siteName,
        CancellationToken cancellationToken = default);
}

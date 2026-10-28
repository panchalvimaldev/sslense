using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

public interface IRenewalInfoProvider
{
    Task<RenewalWindow?> GetWindowAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default);
}

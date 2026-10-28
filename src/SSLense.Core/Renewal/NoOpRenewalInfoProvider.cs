using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

internal sealed class NoOpRenewalInfoProvider : IRenewalInfoProvider
{
    public Task<RenewalWindow?> GetWindowAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<RenewalWindow?>(null);
}

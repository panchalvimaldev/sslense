namespace SSLense.Core.Renewal;

public interface IRenewalService
{
    Task<IReadOnlyList<ManagedCertificateStatus>> GetStatusAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<RenewalResult>> RenewAsync(
        RenewalRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}

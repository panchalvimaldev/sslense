namespace SSLense.Core.Acme;

public interface IAcmeService
{
    Task<AcmeIssueResult> IssueAsync(
        AcmeIssueRequest request,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);
}

namespace SSLense.Core.Validation;

public interface IPreflightService
{
    Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default);
}

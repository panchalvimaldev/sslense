namespace SSLense.Core.Validation;

public interface IPreflightService
{
    Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default);

    /// <summary>The same checks for DNS validation: names, bindings, provider, name servers, and CAA. Changes nothing in DNS.</summary>
    Task<IReadOnlyList<PreflightCheck>> CheckDnsAsync(
        DnsPreflightRequest request,
        CancellationToken cancellationToken = default);
}

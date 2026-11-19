namespace SSLense.Core.Validation;

public interface IPreflightService
{
    Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// The HTTP checks, for SSLense answering the challenge itself (docs/design/self-hosted-http-validation.md): any binding
    /// for each host, and port 80 free for SSLense, in place of a port 80 binding and a writable folder.
    /// </summary>
    Task<IReadOnlyList<PreflightCheck>> CheckAsync(
        string siteName,
        IReadOnlyList<string> hosts,
        bool selfHosted,
        CancellationToken cancellationToken = default) =>
        selfHosted ? throw new NotSupportedException("This check cannot test HTTP answered by SSLense.") : CheckAsync(siteName, hosts, cancellationToken);

    /// <summary>The same checks for DNS validation: names, bindings, provider, name servers, and CAA. Changes nothing in DNS.</summary>
    Task<IReadOnlyList<PreflightCheck>> CheckDnsAsync(
        DnsPreflightRequest request,
        CancellationToken cancellationToken = default);
}

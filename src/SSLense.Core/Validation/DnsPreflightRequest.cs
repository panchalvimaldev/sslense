using SSLense.Core.Config;

namespace SSLense.Core.Validation;

/// <param name="CertificateNames">What the certificate covers, when that differs from <paramref name="Hosts"/>.</param>
public sealed record DnsPreflightRequest(
    string SiteName,
    IReadOnlyList<string> Hosts,
    IReadOnlyList<string>? CertificateNames,
    ValidationMethod ValidationMethod,
    string AuthorityId,
    bool NoSite = false);

namespace SSLense.Core.Certificates;

public sealed record CertificateDetails(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Thumbprint,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    IReadOnlyList<string> BoundSites,
    IReadOnlyList<string> RecentLogLines);

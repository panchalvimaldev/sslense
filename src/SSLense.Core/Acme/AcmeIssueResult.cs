namespace SSLense.Core.Acme;

public sealed record AcmeIssueResult(
    string CertificatePemPath,
    string? PfxPath,
    IReadOnlyList<string> Hosts,
    string? CertificateThumbprint = null,
    DateTimeOffset? NotBefore = null,
    DateTimeOffset? NotAfter = null);

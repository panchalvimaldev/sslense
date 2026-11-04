using SSLense.Core.Iis;

namespace SSLense.Core.Acme;

/// <param name="LeftOutSites">Sites of a shared certificate that stayed on their previous certificate because they had a problem.</param>
public sealed record AcmeIssueResult(
    string CertificatePemPath,
    string? PfxPath,
    IReadOnlyList<string> Hosts,
    string? CertificateThumbprint = null,
    DateTimeOffset? NotBefore = null,
    DateTimeOffset? NotAfter = null,
    IReadOnlyList<LeftOutSite>? LeftOutSites = null);

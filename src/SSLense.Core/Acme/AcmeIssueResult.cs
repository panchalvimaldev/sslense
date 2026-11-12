using SSLense.Core.Deployment;
using SSLense.Core.Iis;

namespace SSLense.Core.Acme;

/// <param name="LeftOutSites">Sites of a shared certificate that stayed on their previous certificate because they had a problem.</param>
/// <param name="Deployment">How the certificate's deployment steps ran after the install; null when it has none.</param>
/// <param name="PreviousCertificateKept">True when the replaced certificate stays in the store because deployment steps are pending.</param>
/// <param name="KeyReused">With key reuse asked for: true when the key was kept, false when a new one had to be used. Null otherwise.</param>
public sealed record AcmeIssueResult(
    string CertificatePemPath,
    string? PfxPath,
    IReadOnlyList<string> Hosts,
    string? CertificateThumbprint = null,
    DateTimeOffset? NotBefore = null,
    DateTimeOffset? NotAfter = null,
    IReadOnlyList<LeftOutSite>? LeftOutSites = null,
    DeploymentRunResult? Deployment = null,
    bool PreviousCertificateKept = false,
    bool? KeyReused = null);

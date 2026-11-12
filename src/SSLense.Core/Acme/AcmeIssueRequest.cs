using SSLense.Core.Config;
using SSLense.Core.DnsValidation;

namespace SSLense.Core.Acme;

/// <param name="AuthorityId">The certificate authority to issue from; Let's Encrypt staging unless chosen otherwise.</param>
/// <param name="ConfirmManualDns">Required with <see cref="ValidationMethod.Dns01Manual"/>: shows the records to create and waits.</param>
/// <param name="CertificateNames">What the certificate covers, when that differs from <paramref name="Hosts"/>, as with a wildcard. Needs DNS validation.</param>
/// <param name="AcceptProductionRisk">
/// Confirms issuing from a CA whose certificates are trusted. Required for every CA not marked as a test, so the CLI and the
/// app cannot differ; automatic renewals set it, because the certificate was confirmed when it was first issued.
/// </param>
public sealed record AcmeIssueRequest(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Email,
    string? OutputDirectory = null,
    bool Force = false,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    string? ExpectedCurrentThumbprint = null,
    ValidationMethod ValidationMethod = ValidationMethod.Http01,
    ManualDnsConfirmation? ConfirmManualDns = null,
    IReadOnlyList<string>? CertificateNames = null,
    bool AcceptProductionRisk = false);

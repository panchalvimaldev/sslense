using SSLense.Core.Config;
using SSLense.Core.DnsValidation;

namespace SSLense.Core.Acme;

/// <param name="AuthorityId">The certificate authority to issue from; Let's Encrypt staging unless chosen otherwise.</param>
/// <param name="ConfirmManualDns">Required with <see cref="ValidationMethod.Dns01Manual"/>: shows the records to create and waits.</param>
public sealed record AcmeIssueRequest(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Email,
    string? OutputDirectory = null,
    bool Force = false,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    string? ExpectedCurrentThumbprint = null,
    ValidationMethod ValidationMethod = ValidationMethod.Http01,
    ManualDnsConfirmation? ConfirmManualDns = null);

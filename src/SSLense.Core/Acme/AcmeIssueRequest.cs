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
/// <param name="NoSite">
/// Issue a certificate bound to no IIS site, named <paramref name="SiteName"/>, for services that its deployment steps hand it to.
/// Needs DNS validation; the certificate covers <paramref name="CertificateNames"/>, or <paramref name="Hosts"/> when there are none.
/// </param>
/// <param name="ExportableKey">Install the private key as exportable, so export steps can write it to files.</param>
/// <param name="KeyType">The certificate's key type; ECDSA P-256 unless chosen otherwise.</param>
/// <param name="PreferredChain">The root the chain should end at, as the CA names it.</param>
/// <param name="Profile">An ACME profile the CA lists, such as <c>shortlived</c>.</param>
/// <param name="ReuseKey">Sign the request with the key of the site's current certificate, when it still matches the key type, so the key stays the same.</param>
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
    bool AcceptProductionRisk = false,
    bool NoSite = false,
    bool ExportableKey = false,
    CertificateKeyType KeyType = CertificateKeyType.EcdsaP256,
    string? PreferredChain = null,
    string? Profile = null,
    bool ReuseKey = false)
{
    public AcmeOrderOptions OrderOptions => new(KeyType, string.IsNullOrWhiteSpace(PreferredChain) ? null : PreferredChain.Trim(), string.IsNullOrWhiteSpace(Profile) ? null : Profile.Trim());
}

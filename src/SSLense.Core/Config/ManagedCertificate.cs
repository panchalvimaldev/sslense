using SSLense.Core.Acme;

namespace SSLense.Core.Config;

/// <param name="AuthorityId">
/// The <see cref="CertificateAuthority"/> that issued this certificate and renews it. Schema 1 stored a
/// staging/production environment instead; see <see cref="ManagedCertificateMigrations"/>.
/// </param>
/// <param name="Source">Whether SSLense obtains and renews this certificate, or it was installed from elsewhere.</param>
/// <param name="Issuer">The issuing CA's name, as shown in the certificate, for display.</param>
/// <param name="Reminders">Whether this certificate is included in reminder digests; see <see cref="ReminderMode"/>.</param>
/// <param name="SnoozedUntil">With <see cref="ReminderMode.Snoozed"/>, when reminders resume.</param>
/// <param name="LastRemindedAt">When this certificate was last included in a sent digest as needing attention or as a repeated automatic reminder.</param>
/// <param name="UpcomingNoticeSent">Whether the one upcoming-renewal notice was sent for this certificate.</param>
/// <param name="ValidationMethod">How the certificate authority checks control of the names.</param>
/// <param name="CertificateNames">The names on the certificate, when they differ from the IIS hosts in <paramref name="Hosts"/>, as with a wildcard.</param>
/// <param name="AdditionalTargets">Other IIS sites using this certificate. <paramref name="SiteName"/> and <paramref name="Hosts"/> stay the first site. See docs/design/shared-certificates.md.</param>
/// <param name="SitePendingSince">When the first site was left on its previous certificate; see <see cref="CertificateTarget.PendingSince"/>.</param>
/// <param name="DeploymentSteps">What runs after every install and renewal, in order: see <see cref="DeploymentStep"/> and docs/design/deployment-steps.md.</param>
/// <param name="Deployment">How the deployment steps last ran. Null until they first run.</param>
/// <param name="NoSite">True for a certificate with no IIS site, used by other services through its deployment steps. <paramref name="SiteName"/> is then a name the administrator chose, and <paramref name="Hosts"/> the certificate's names. See docs/design/no-site-certificates.md.</param>
/// <param name="ExportableKey">Whether the private key is installed as exportable, chosen at issue and kept at renewal, so export steps can write it to files. See docs/design/certificate-export.md.</param>
/// <param name="KeyType">The key type, chosen at issue and kept at renewal. See docs/design/key-and-order-options.md.</param>
/// <param name="PreferredChain">The root the chain should end at, when not the CA's default.</param>
/// <param name="Profile">The ACME profile the certificate is ordered with, when not the CA's default.</param>
/// <param name="ReuseKey">Keep the same private key at every renewal. See docs/design/key-reuse.md.</param>
/// <remarks>
/// The reminder fields belong to the record, not to a certificate: <see cref="IManagedCertificateStore.UpsertAsync"/> keeps
/// them across installs and resets them when the thumbprint changes (except <see cref="ReminderMode.Off"/>).
/// </remarks>
public sealed record ManagedCertificate(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Email,
    string Thumbprint,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string? OutputDirectory = null,
    DateTimeOffset? LastRenewalAttempt = null,
    bool? LastRenewalSucceeded = null,
    string? LastRenewalMessage = null,
    string AuthorityId = CertificateAuthorities.LetsEncryptStagingId,
    int ConsecutiveFailures = 0,
    DateTimeOffset? NextRetryAt = null,
    Guid Id = default,
    CertificateSource Source = CertificateSource.Acme,
    string? Issuer = null,
    ReminderMode Reminders = ReminderMode.On,
    DateTimeOffset? SnoozedUntil = null,
    DateTimeOffset? LastRemindedAt = null,
    bool UpcomingNoticeSent = false,
    ValidationMethod ValidationMethod = ValidationMethod.Http01,
    IReadOnlyList<string>? CertificateNames = null,
    IReadOnlyList<CertificateTarget>? AdditionalTargets = null,
    DateTimeOffset? SitePendingSince = null,
    IReadOnlyList<DeploymentStep>? DeploymentSteps = null,
    DeploymentState? Deployment = null,
    bool NoSite = false,
    bool ExportableKey = false,
    CertificateKeyType KeyType = CertificateKeyType.EcdsaP256,
    string? PreferredChain = null,
    string? Profile = null,
    bool ReuseKey = false);

/// <summary>An IIS site and the hosts on it that use a certificate.</summary>
/// <param name="PendingSince">When this site was left on its previous certificate because it had a problem during a renewal. Null when it uses the record's certificate.</param>
public sealed record CertificateTarget(string SiteName, IReadOnlyList<string> Hosts, DateTimeOffset? PendingSince = null);

public enum ValidationMethod
{
    /// <summary>A file served by the IIS site on port 80.</summary>
    Http01 = 0,

    /// <summary>A TXT record SSLense publishes through a configured DNS provider.</summary>
    Dns01Provider = 1,

    /// <summary>A TXT record the administrator creates by hand, so renewal needs the administrator too.</summary>
    Dns01Manual = 2
}

public enum ReminderMode
{
    On = 0,

    /// <summary>Not reminding until <see cref="ManagedCertificate.SnoozedUntil"/>, or until the certificate is replaced.</summary>
    Snoozed = 1,

    /// <summary>Not reminding until the certificate is replaced; the replacement is reminded about again.</summary>
    OffUntilReplaced = 2,

    /// <summary>Never reminding about this site's certificate, including its replacements.</summary>
    Off = 3
}

/// <summary>How close a certificate is to expiry, relative to its lifetime; used by the health check.</summary>
public enum ExpiryWarningLevel
{
    None = 0,
    Warning = 1,
    Critical = 2,
    Expired = 3
}

public enum CertificateSource
{
    /// <summary>Obtained and renewed automatically by SSLense from an ACME certificate authority.</summary>
    Acme = 0,

    /// <summary>Obtained elsewhere (bought from a reseller, or issued by another tool) and renewed manually.</summary>
    Imported = 1
}

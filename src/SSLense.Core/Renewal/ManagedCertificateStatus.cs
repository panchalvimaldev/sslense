namespace SSLense.Core.Renewal;

public sealed record ManagedCertificateStatus(
    string SiteName,
    IReadOnlyList<string> Hosts,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    int DaysRemaining,
    string Thumbprint,
    DateTimeOffset? LastRenewalAttempt,
    bool? LastRenewalSucceeded,
    string? LastRenewalMessage,
    Acme.AcmeEnvironment Environment = Acme.AcmeEnvironment.Staging);

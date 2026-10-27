namespace SSLense.Core.Config;

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
    string? LastRenewalMessage = null);

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
    string? LastRenewalMessage = null,
    Acme.AcmeEnvironment Environment = Acme.AcmeEnvironment.Staging,
    int ConsecutiveFailures = 0,
    DateTimeOffset? NextRetryAt = null,
    ExpiryWarningLevel ExpiryWarningSent = ExpiryWarningLevel.None,
    Guid Id = default);

/// <summary>Expiry notification levels, each sent at most once per certificate.</summary>
public enum ExpiryWarningLevel
{
    None = 0,
    Warning = 1,
    Critical = 2,
    Expired = 3
}

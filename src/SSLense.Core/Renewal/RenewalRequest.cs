namespace SSLense.Core.Renewal;

public sealed record RenewalRequest(
    bool All = false,
    string? SiteName = null,
    bool Force = false,
    bool RetryFailures = false);

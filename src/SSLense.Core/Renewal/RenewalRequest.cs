namespace SSLense.Core.Renewal;

/// <param name="Scheduled">
/// True for the background service: honors the saved retry backoff and escalates failure notifications.
/// Manual renewals from the GUI or CLI attempt immediately and always notify on failure.
/// </param>
public sealed record RenewalRequest(
    bool All = false,
    string? SiteName = null,
    bool Force = false,
    bool Scheduled = false);

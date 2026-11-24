namespace SSLense.Core.Renewal;

/// <param name="Waiting">
/// Not renewed now by the administrator's choice: held after a rollback, or waiting for the maintenance window. Not a
/// failure, so it is logged as information and the service's heartbeat does not report it as failing.
/// </param>
public sealed record RenewalResult(
    string SiteName,
    bool Attempted,
    bool Succeeded,
    string Message,
    string? PreviousThumbprint = null,
    string? NewThumbprint = null,
    bool Waiting = false);

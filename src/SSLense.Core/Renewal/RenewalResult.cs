namespace SSLense.Core.Renewal;

public sealed record RenewalResult(
    string SiteName,
    bool Attempted,
    bool Succeeded,
    string Message,
    string? PreviousThumbprint = null,
    string? NewThumbprint = null);

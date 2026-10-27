namespace SSLense.Core.Acme;

public sealed record AcmeIssueRequest(
    string SiteName,
    IReadOnlyList<string> Hosts,
    string Email,
    string? OutputDirectory = null,
    bool Force = false);

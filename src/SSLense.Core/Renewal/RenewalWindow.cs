namespace SSLense.Core.Renewal;

public sealed record RenewalWindow(
    DateTimeOffset Start,
    DateTimeOffset End,
    string? ExplanationUrl = null);

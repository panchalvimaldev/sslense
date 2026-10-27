namespace SSLense.Core.Iis;

public sealed record IisSite(
    long Id,
    string Name,
    string State,
    string? PhysicalPath,
    IReadOnlyList<IisBinding> Bindings);

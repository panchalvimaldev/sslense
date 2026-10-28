namespace SSLense.Core.Logs;

public sealed record LogSnapshot(string? FilePath, IReadOnlyList<string> Lines);

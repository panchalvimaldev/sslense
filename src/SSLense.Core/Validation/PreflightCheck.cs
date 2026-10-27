namespace SSLense.Core.Validation;

public sealed record PreflightCheck(string Name, bool Succeeded, string Message);

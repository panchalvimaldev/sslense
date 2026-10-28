namespace SSLense.Core.Acme;

/// <summary>
/// The ACME server refused a request because a rate limit was reached. Retrying immediately
/// only extends the limit, so callers must not retry until a later scheduled check.
/// </summary>
public sealed class AcmeRateLimitedException(string message, Exception? innerException = null)
    : InvalidOperationException(message, innerException)
{
    public const string ProblemType = "urn:ietf:params:acme:error:rateLimited";
}

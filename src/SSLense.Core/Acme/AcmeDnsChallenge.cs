namespace SSLense.Core.Acme;

/// <param name="Host">The name being validated; for a wildcard, its base name.</param>
/// <param name="RecordName">The TXT record name the CA reads, before any CNAME is followed.</param>
public sealed record AcmeDnsChallenge(string Host, bool IsWildcard, string RecordName, string TxtValue);

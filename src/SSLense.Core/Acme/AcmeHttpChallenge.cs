namespace SSLense.Core.Acme;

public sealed record AcmeHttpChallenge(string Host, string Token, string KeyAuthorization);

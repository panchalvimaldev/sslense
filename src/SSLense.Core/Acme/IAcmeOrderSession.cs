namespace SSLense.Core.Acme;

public interface IAcmeOrderSession
{
    IReadOnlyList<AcmeHttpChallenge> Challenges { get; }

    /// <summary>The DNS challenges still to complete; authorizations the CA already holds as valid are left out.</summary>
    IReadOnlyList<AcmeDnsChallenge> DnsChallenges { get; }

    Task ValidateAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken);

    Task ValidateAsync(AcmeDnsChallenge challenge, CancellationToken cancellationToken);

    Task<CertificateBundle> FinalizeAsync(
        string commonName,
        string pfxPassword,
        CancellationToken cancellationToken);
}

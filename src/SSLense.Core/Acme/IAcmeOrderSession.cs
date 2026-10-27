namespace SSLense.Core.Acme;

public interface IAcmeOrderSession
{
    IReadOnlyList<AcmeHttpChallenge> Challenges { get; }

    Task ValidateAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken);

    Task<CertificateBundle> FinalizeAsync(
        string commonName,
        string pfxPassword,
        CancellationToken cancellationToken);
}

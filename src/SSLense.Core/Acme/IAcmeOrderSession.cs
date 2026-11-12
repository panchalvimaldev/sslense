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

    /// <summary>
    /// Finalizes with a certificate request signed by a key SSLense already holds, and returns the certificate and its
    /// chain as PEM. Used to keep the same key at renewal (docs/design/key-reuse.md).
    /// </summary>
    Task<string> FinalizeWithRequestAsync(byte[] certificateRequest, CancellationToken cancellationToken) =>
        throw new NotSupportedException("This ACME client cannot finalize with an existing key.");
}

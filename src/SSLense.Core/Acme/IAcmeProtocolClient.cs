namespace SSLense.Core.Acme;

public interface IAcmeProtocolClient
{
    /// <summary>Loads or creates the ACME account for <paramref name="authority"/>, then creates an order.</summary>
    Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        CancellationToken cancellationToken);

    /// <summary>The same as <see cref="CreateOrderAsync"/>, for an order validated through DNS-01.</summary>
    Task<IAcmeOrderSession> CreateDnsOrderAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        CancellationToken cancellationToken);

    /// <summary>As <see cref="CreateOrderAsync(string, IReadOnlyList{string}, CertificateAuthority, CancellationToken)"/>, with a key type, chain, or profile.</summary>
    Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CertificateAuthority authority,
        AcmeOrderOptions options,
        CancellationToken cancellationToken) =>
        options.IsDefault
            ? CreateOrderAsync(email, hosts, authority, cancellationToken)
            : throw new NotSupportedException("This ACME client cannot change the key, chain, or profile.");

    /// <summary>As <see cref="CreateDnsOrderAsync(string, IReadOnlyList{string}, CertificateAuthority, CancellationToken)"/>, with a key type, chain, or profile.</summary>
    Task<IAcmeOrderSession> CreateDnsOrderAsync(
        string email,
        IReadOnlyList<string> names,
        CertificateAuthority authority,
        AcmeOrderOptions options,
        CancellationToken cancellationToken) =>
        options.IsDefault
            ? CreateDnsOrderAsync(email, names, authority, cancellationToken)
            : throw new NotSupportedException("This ACME client cannot change the key, chain, or profile.");

    /// <summary>
    /// Revokes a certificate this server's account for <paramref name="authority"/> issued, signed with the account key
    /// (docs/design/compromise-recovery.md).
    /// </summary>
    Task RevokeAsync(
        string email,
        CertificateAuthority authority,
        byte[] certificateDer,
        CertificateRevocationReason reason,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This ACME client cannot revoke certificates.");

    /// <summary>Replaces the account's key with a new one at the CA, then saves the new key in its place.</summary>
    Task ChangeAccountKeyAsync(CertificateAuthority authority, CancellationToken cancellationToken) =>
        throw new NotSupportedException("This ACME client cannot change the account key.");
}

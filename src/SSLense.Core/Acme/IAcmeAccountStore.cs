namespace SSLense.Core.Acme;

public interface IAcmeAccountStore
{
    Task<string?> LoadKeyAsync(CancellationToken cancellationToken);

    Task<string?> LoadKeyAsync(AcmeEnvironment environment, CancellationToken cancellationToken);

    Task SaveKeyAsync(string accountKeyPem, CancellationToken cancellationToken);

    Task SaveKeyAsync(
        AcmeEnvironment environment,
        string accountKeyPem,
        CancellationToken cancellationToken);
}

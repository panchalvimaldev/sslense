namespace SSLense.Core.Acme;

public interface IAcmeAccountStore
{
    Task<string?> LoadKeyAsync(CancellationToken cancellationToken);

    Task SaveKeyAsync(string accountKeyPem, CancellationToken cancellationToken);
}

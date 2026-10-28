using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Config;

namespace SSLense.Core.Acme;

internal sealed class AcmeAccountStore : IAcmeAccountStore
{
    private readonly IFileSystem _fileSystem;
    private readonly ISecretProtector _protector;

    public AcmeAccountStore(IFileSystem fileSystem, ISecretProtector protector)
    {
        _fileSystem = fileSystem;
        _protector = protector;
    }

    public Task<string?> LoadKeyAsync(CancellationToken cancellationToken) =>
        LoadKeyAsync(AcmeEnvironment.Staging, cancellationToken);

    public async Task<string?> LoadKeyAsync(
        AcmeEnvironment environment,
        CancellationToken cancellationToken)
    {
        var path = AppPaths.GetAccountKeyFile(environment);
        if (!_fileSystem.FileExists(path))
        {
            return null;
        }

        var encoded = await _fileSystem.ReadAllTextAsync(path, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            var encrypted = Convert.FromBase64String(encoded);
            var plaintext = _protector.Unprotect(encrypted);
            try
            {
                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        catch (FormatException exception)
        {
            throw new InvalidDataException("The saved ACME account key is corrupt.", exception);
        }
    }

    public Task SaveKeyAsync(string accountKeyPem, CancellationToken cancellationToken) =>
        SaveKeyAsync(AcmeEnvironment.Staging, accountKeyPem, cancellationToken);

    public async Task SaveKeyAsync(
        AcmeEnvironment environment,
        string accountKeyPem,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accountKeyPem);

        var plaintext = Encoding.UTF8.GetBytes(accountKeyPem);
        try
        {
            var encrypted = _protector.Protect(plaintext);
            await _fileSystem.WriteAllTextAtomicAsync(
                    AppPaths.GetAccountKeyFile(environment),
                    Convert.ToBase64String(encrypted),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

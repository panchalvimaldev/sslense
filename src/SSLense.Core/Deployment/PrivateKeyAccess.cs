using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using SSLense.Core.Certificates;

namespace SSLense.Core.Deployment;

/// <summary>Gives accounts read access to an installed certificate's private key.</summary>
internal interface IPrivateKeyAccess
{
    /// <summary>The account as Windows names it. Throws when Windows does not know the account.</summary>
    string ResolveAccount(string account);

    /// <summary>Adds one allow rule for read access to the key. Existing rules are never changed or removed.</summary>
    Task GrantReadAsync(string thumbprint, string account, CancellationToken cancellationToken);
}

internal sealed class PrivateKeyAccess(ICertificateStore certificateStore) : IPrivateKeyAccess
{
    /// <summary>Where Windows keeps machine keys: CNG keys, then keys from the older CryptoAPI providers.</summary>
    private static IReadOnlyList<string> MachineKeyDirectories =>
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Crypto", "Keys"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Crypto", "RSA", "MachineKeys")
    ];

    public string ResolveAccount(string account) => Resolve(account).Name;

    public async Task GrantReadAsync(string thumbprint, string account, CancellationToken cancellationToken)
    {
        var (sid, name) = Resolve(account);
        using var certificate = await certificateStore.OpenAsync(thumbprint, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"The certificate {thumbprint} is not installed in LocalMachine\\My.");
        GrantRead(certificate, sid, MachineKeyDirectories, name);
    }

    internal static (SecurityIdentifier Sid, string Name) Resolve(string account)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(account);
        try
        {
            var sid = (SecurityIdentifier)new NTAccount(account.Trim()).Translate(typeof(SecurityIdentifier));
            return (sid, sid.Translate(typeof(NTAccount)).Value);
        }
        catch (IdentityNotMappedException)
        {
            throw new ArgumentException(
                $"Windows does not know the account '{account.Trim()}'. Check the name, such as 'IIS AppPool\\Shop' or " +
                "'NT Service\\MSSQLSERVER'; an application pool's account exists only while the pool does.");
        }
    }

    /// <param name="keyDirectories">Where to look for the key's file; tests pass the current user's key folder.</param>
    internal static void GrantRead(
        X509Certificate2 certificate,
        SecurityIdentifier sid,
        IReadOnlyList<string> keyDirectories,
        string accountName)
    {
        var uniqueName = KeyFileName(certificate);
        var path = keyDirectories
            .Select(directory => Path.Combine(directory, uniqueName))
            .FirstOrDefault(File.Exists)
            ?? throw new InvalidOperationException(
                $"The private key file of certificate {certificate.Thumbprint} was not found, so '{accountName}' could not be given access.");

        var file = new FileInfo(path);
        if (file.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException($"The private key file '{path}' is a link. SSLense will not change its access.");
        }

        var security = file.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.Read, AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    private static string KeyFileName(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException($"The certificate {certificate.Thumbprint} has no private key.");
        }

        using AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)certificate.GetRSAPrivateKey() ?? certificate.GetECDsaPrivateKey();
        var name = key switch
        {
            RSACng rsa => rsa.Key.UniqueName,
            ECDsaCng ecdsa => ecdsa.Key.UniqueName,
            RSACryptoServiceProvider csp => csp.CspKeyContainerInfo.UniqueKeyContainerName,
            _ => null
        };

        if (string.IsNullOrEmpty(name) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new InvalidOperationException(
                $"SSLense cannot find where the private key of certificate {certificate.Thumbprint} is kept.");
        }

        return name;
    }
}

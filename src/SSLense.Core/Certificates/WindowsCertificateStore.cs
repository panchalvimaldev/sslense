using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SSLense.Core.Certificates;

internal sealed class WindowsCertificateStore : ICertificateStore
{
    public Task<InstalledCertificate?> FindByThumbprintAsync(
        string thumbprint,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();
        var normalizedThumbprint = NormalizeThumbprint(thumbprint);

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            normalizedThumbprint,
            validOnly: false);
        try
        {
            var certificate = matches.OfType<X509Certificate2>().FirstOrDefault();
            return Task.FromResult(certificate is null ? null : Map(certificate));
        }
        finally
        {
            foreach (var certificate in matches.OfType<X509Certificate2>())
            {
                certificate.Dispose();
            }
        }
    }

    public Task<InstalledCertificate> ImportPfxAsync(
        byte[] pfxBytes,
        string password,
        string friendlyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pfxBytes);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(friendlyName);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();

        try
        {
            using var certificate = new X509Certificate2(
                pfxBytes,
                password,
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable);
            if (!certificate.HasPrivateKey)
            {
                throw new CryptographicException("The issued PFX does not contain a private key.");
            }

            certificate.FriendlyName = friendlyName;
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
            store.Add(certificate);
            return Task.FromResult(Map(certificate));
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                "The certificate could not be imported into LocalMachine\\My. " +
                "Run SSLense as Administrator and verify the PFX is valid.",
                exception);
        }
    }

    public Task RemoveAsync(string thumbprint, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EnsureWindows();

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            NormalizeThumbprint(thumbprint),
            validOnly: false);
        try
        {
            foreach (var certificate in matches.OfType<X509Certificate2>())
            {
                store.Remove(certificate);
            }
        }
        finally
        {
            foreach (var certificate in matches.OfType<X509Certificate2>())
            {
                certificate.Dispose();
            }
        }

        return Task.CompletedTask;
    }

    private static InstalledCertificate Map(X509Certificate2 certificate) => new(
        NormalizeThumbprint(certificate.Thumbprint),
        certificate.NotBefore.ToUniversalTime(),
        certificate.NotAfter.ToUniversalTime(),
        certificate.HasPrivateKey,
        certificate.Issuer);

    private static string NormalizeThumbprint(string thumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);
        return string.Concat(thumbprint.Where(Uri.IsHexDigit)).ToUpperInvariant();
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The LocalMachine certificate store is only available on Windows.");
        }
    }
}

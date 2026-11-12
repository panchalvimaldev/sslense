using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using SSLense.Core.Certificates;

namespace SSLense.Core.Deployment;

/// <summary>Writes an installed certificate, with its exportable key, to files. See docs/design/certificate-export.md.</summary>
internal interface ICertificateExporter
{
    /// <summary>The certificate, its intermediates, and its key in one PFX protected by <paramref name="password"/>.</summary>
    Task ExportPfxAsync(string thumbprint, string path, string password, CancellationToken cancellationToken);

    /// <summary><c>cert.pem</c>, <c>chain.pem</c>, <c>fullchain.pem</c>, and <c>key.pem</c>, the key readable only by Administrators and SYSTEM.</summary>
    Task ExportPemAsync(string thumbprint, string folder, CancellationToken cancellationToken);

    /// <summary>One PFX per name, named as the IIS Central Certificate Store expects.</summary>
    Task ExportCentralStoreAsync(
        string thumbprint,
        IReadOnlyList<string> names,
        string folder,
        string password,
        CancellationToken cancellationToken);
}

internal sealed class CertificateExporter(ICertificateStore certificateStore) : ICertificateExporter
{
    public async Task ExportPfxAsync(string thumbprint, string path, string password, CancellationToken cancellationToken)
    {
        var pfx = await ExportPkcs12Async(thumbprint, password, cancellationToken).ConfigureAwait(false);
        try
        {
            WriteAtomically(path, pfx, restricted: false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    public async Task ExportCentralStoreAsync(
        string thumbprint,
        IReadOnlyList<string> names,
        string folder,
        string password,
        CancellationToken cancellationToken)
    {
        var pfx = await ExportPkcs12Async(thumbprint, password, cancellationToken).ConfigureAwait(false);
        try
        {
            foreach (var name in names)
            {
                WriteAtomically(Path.Combine(folder, CentralStoreFileName(name)), pfx, restricted: false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }
    }

    public async Task ExportPemAsync(string thumbprint, string folder, CancellationToken cancellationToken)
    {
        // Through a PKCS#12 with a throwaway password, so only "allow export" is needed on the stored key.
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        var pfx = await ExportPkcs12Async(thumbprint, password, cancellationToken).ConfigureAwait(false);
        X509Certificate2Collection loaded;
        try
        {
            loaded = X509CertificateLoader.LoadPkcs12Collection(
                pfx,
                password,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pfx);
        }

        try
        {
            var leaf = loaded.First(certificate => certificate.HasPrivateKey);
            var chain = loaded.Where(certificate => !ReferenceEquals(certificate, leaf)).ToArray();
            var certificatePem = leaf.ExportCertificatePem() + "\n";
            var chainPem = string.Concat(chain.Select(certificate => certificate.ExportCertificatePem() + "\n"));
            char[] keyPem;
            using (AsymmetricAlgorithm key = (AsymmetricAlgorithm?)leaf.GetRSAPrivateKey() ?? leaf.GetECDsaPrivateKey()
                       ?? throw new InvalidOperationException("The certificate's key is neither RSA nor ECDSA."))
            {
                keyPem = key.ExportPkcs8PrivateKeyPem().ToCharArray();
            }

            var keyBytes = Encoding.ASCII.GetBytes(keyPem);
            try
            {
                Directory.CreateDirectory(folder);
                WriteAtomically(Path.Combine(folder, "key.pem"), keyBytes, restricted: true);
                WriteAtomically(Path.Combine(folder, "cert.pem"), Encoding.ASCII.GetBytes(certificatePem), restricted: false);
                WriteAtomically(Path.Combine(folder, "chain.pem"), Encoding.ASCII.GetBytes(chainPem), restricted: false);
                WriteAtomically(Path.Combine(folder, "fullchain.pem"), Encoding.ASCII.GetBytes(certificatePem + chainPem), restricted: false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
                Array.Clear(keyPem);
            }
        }
        finally
        {
            foreach (var certificate in loaded)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>The IIS Central Certificate Store looks for <c>example.com.pfx</c>, and <c>_.example.com.pfx</c> for <c>*.example.com</c>.</summary>
    internal static string CentralStoreFileName(string name) => $"{name.Trim().TrimEnd('.').Replace('*', '_').ToLowerInvariant()}.pfx";

    private async Task<byte[]> ExportPkcs12Async(string thumbprint, string password, CancellationToken cancellationToken)
    {
        using var certificate = await certificateStore.OpenAsync(thumbprint, cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"The certificate {thumbprint} is not installed in LocalMachine\\My.");
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException($"The certificate {thumbprint} has no private key to export.");
        }

        var collection = new X509Certificate2Collection(certificate);
        var intermediates = Intermediates(certificate);
        collection.AddRange(intermediates);
        try
        {
            return collection.Export(X509ContentType.Pkcs12, password)
                ?? throw new InvalidOperationException("The certificate could not be exported.");
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                $"The private key of certificate {thumbprint} cannot be exported. Issue the certificate again with an exportable key " +
                "('issue --exportable-key', or Exportable private key in the app).",
                exception);
        }
        finally
        {
            foreach (var intermediate in intermediates)
            {
                intermediate.Dispose();
            }
        }
    }

    /// <summary>The intermediates Windows finds for the certificate; a self-signed root is left out, as servers do.</summary>
    private static X509Certificate2[] Intermediates(X509Certificate2 certificate)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
        chain.Build(certificate);
        var found = chain.ChainElements
            .Skip(1)
            .Select(element => element.Certificate)
            .Where(value => value.SubjectName.RawData.AsSpan().SequenceEqual(value.IssuerName.RawData) is false)
            .Select(value => X509CertificateLoader.LoadCertificate(value.RawData))
            .ToArray();
        foreach (var element in chain.ChainElements)
        {
            element.Certificate.Dispose();
        }

        return found;
    }

    /// <summary>
    /// Writes beside the target, then moves into place, so a reader never sees half a file. A restricted file is created
    /// readable only by Administrators and SYSTEM, without inherited permissions, before anything is written to it.
    /// </summary>
    internal static void WriteAtomically(string path, byte[] content, bool restricted)
    {
        var directory = Path.GetDirectoryName(path) ?? throw new ArgumentException($"'{path}' has no folder.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = restricted
                       ? new FileInfo(temporary).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, RestrictedSecurity())
                       : new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static FileSecurity RestrictedSecurity()
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        // The account writing it is SYSTEM or an elevated administrator; it is named too, so it can still replace the file
        // when its token does not carry the Administrators group.
        using var current = WindowsIdentity.GetCurrent();
        foreach (var sid in new[]
                 {
                     new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                     new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                     current.User!
                 }.Distinct())
        {
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        return security;
    }
}

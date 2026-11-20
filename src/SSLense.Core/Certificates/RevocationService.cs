using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Errors;

namespace SSLense.Core.Certificates;

/// <summary>Recovery from a compromised private key or ACME account (docs/design/compromise-recovery.md).</summary>
public interface IRevocationService
{
    /// <summary>
    /// Revokes the certificate SSLense manages as <paramref name="name"/>. With <paramref name="replace"/>, a new
    /// certificate with a new key is installed first, so no site is left serving a revoked certificate.
    /// </summary>
    Task<RevocationResult> RevokeAsync(
        string name,
        CertificateRevocationReason reason,
        bool replace,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>Revokes a certificate from a file (PEM or DER) that this server's account with the CA issued.</summary>
    Task<string> RevokeFileAsync(
        string path,
        string authorityId,
        CertificateRevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>Replaces the ACME account key for a certificate authority; certificates are not affected.</summary>
    Task<string> ChangeAccountKeyAsync(string authorityId, CancellationToken cancellationToken = default);
}

/// <param name="NewThumbprint">The replacement, when one was installed.</param>
public sealed record RevocationResult(string Name, string RevokedThumbprint, string? NewThumbprint, string Message);

internal sealed class RevocationService(
    IManagedCertificateStore managedStore,
    ICertificateStore certificateStore,
    IAcmeService acmeService,
    IAcmeProtocolClient protocolClient,
    ICertificateAuthorityRegistry authorities,
    IFileSystem fileSystem,
    ICertificateAuthorityLock? authorityLock = null,
    ICertificateHistoryStore? history = null) : IRevocationService
{
    private readonly ICertificateAuthorityLock _authorityLock = authorityLock ?? NoOpCertificateAuthorityLock.Instance;

    /// <summary>Where an old certificate is kept when it was replaced but could not be revoked, so it can be tried again.</summary>
    internal static string PendingDirectory => Path.Combine(AppPaths.DataDirectory, "revocations");

    public async Task<RevocationResult> RevokeAsync(
        string name,
        CertificateRevocationReason reason,
        bool replace,
        IProgress<ProgressEvent>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var record = records.FirstOrDefault(value => string.Equals(value.SiteName, name.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw ManagedCertificateNotFound.Create(name, records);
        if (record.Source != CertificateSource.Acme)
        {
            throw new SslenseException(ErrorCodes.RevokeBoughtCertificate,
                $"'{record.SiteName}' came from {record.Issuer ?? "another provider"}, which revokes it, not SSLense. Ask the provider to " +
                "revoke it, get a new certificate with a new key, and install it with Install renewal.");
        }

        if (replace && record.ValidationMethod == ValidationMethod.Dns01Manual)
        {
            throw new SslenseException(ErrorCodes.RevokeManualDnsCertificate,
                $"'{record.SiteName}' uses manual DNS validation, so SSLense cannot replace it on its own. Renew it by hand first, " +
                $"then revoke the old certificate with 'SSLense.Cli revoke --file <old certificate> --ca {record.AuthorityId}'.");
        }

        using var installed = await certificateStore.OpenAsync(record.Thumbprint, cancellationToken).ConfigureAwait(false)
            ?? throw new SslenseException(ErrorCodes.CertificateNotInStore,
                $"Certificate {record.Thumbprint} of '{record.SiteName}' is not in LocalMachine\\My, so SSLense cannot read it to revoke it. " +
                "If you have its file, use 'SSLense.Cli revoke --file'.");
        var oldCertificate = installed.RawData;
        var authority = await authorities.GetAsync(record.AuthorityId, cancellationToken).ConfigureAwait(false);

        string? newThumbprint = null;
        if (replace)
        {
            progress?.Report(new ProgressEvent("replace", $"Replacing '{record.SiteName}' with a new certificate and a new key before revoking the old one."));
            var issued = await acmeService.IssueAsync(
                    new AcmeIssueRequest(
                        record.SiteName,
                        record.Hosts,
                        record.Email,
                        record.OutputDirectory,
                        Force: true,
                        record.AuthorityId,
                        record.Thumbprint,
                        record.ValidationMethod,
                        CertificateNames: record.CertificateNames,
                        NoSite: record.NoSite,
                        ExportableKey: record.ExportableKey,
                        KeyType: record.KeyType,
                        PreferredChain: record.PreferredChain,
                        Profile: record.Profile,
                        // The old key may be the one that leaked, so the replacement never reuses it.
                        ReuseKey: false,
                        SelfHostedHttp: record.SelfHostedHttp,

                        // A compromised certificate is never one to go back to.
                        KeepReplacedForRollback: false,
                        // Confirmed when the certificate was first issued from this CA.
                        AcceptProductionRisk: true),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false);
            newThumbprint = issued.CertificateThumbprint;
            if (record.ReuseKey)
            {
                // Later renewals keep reusing a key: from now on, the new one.
                var saved = (await managedStore.GetAllAsync(CancellationToken.None).ConfigureAwait(false))
                    .FirstOrDefault(value => string.Equals(value.SiteName, record.SiteName, StringComparison.OrdinalIgnoreCase));
                if (saved is not null)
                {
                    await managedStore.UpsertAsync(saved with { ReuseKey = true }, CancellationToken.None).ConfigureAwait(false);
                }
            }
        }

        progress?.Report(new ProgressEvent("revoke", $"Asking {authority.Name} to revoke certificate {record.Thumbprint} ({Describe(reason)})."));
        try
        {
            await protocolClient.RevokeAsync(record.Email, authority, oldCertificate, reason, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (replace && exception is not OperationCanceledException)
        {
            // The sites already use the new certificate, and the old one may have left the store: keep it to try again.
            var path = Path.Combine(PendingDirectory, $"{record.Thumbprint}.cer");
            fileSystem.CreateDirectory(PendingDirectory);
            await fileSystem.WriteAllBytesAsync(path, oldCertificate, CancellationToken.None).ConfigureAwait(false);
            throw new SslenseException(ErrorCodes.RevocationFailed,
                $"'{record.SiteName}' now uses a new certificate with a new key, but {authority.Name} did not revoke the old one: " +
                $"{ErrorCode.Describe(exception)} The old certificate was saved; try again with " +
                $"'SSLense.Cli revoke --file \"{path}\" --ca {authority.Id} --reason {CliName(reason)}'.",
                exception);
        }

        await history.TryAddAsync(new CertificateHistoryEntry(
                DateTimeOffset.UtcNow, record.Id, record.SiteName, CertificateHistoryKind.Revoked,
                $"Revoked by {authority.Name} ({Describe(reason)}).", record.Thumbprint, NotAfter: record.NotAfter))
            .ConfigureAwait(false);
        var message = newThumbprint is null
            ? $"Certificate {record.Thumbprint} of '{record.SiteName}' was revoked. Its sites still serve it, and browsers will refuse it: issue or install a replacement now."
            : $"'{record.SiteName}' now uses certificate {newThumbprint} with a new key, and the old certificate {record.Thumbprint} was revoked.";
        return new RevocationResult(record.SiteName, record.Thumbprint, newThumbprint, message);
    }

    public async Task<string> RevokeFileAsync(
        string path,
        string authorityId,
        CertificateRevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        var certificate = CertificateInspector.LoadCertificates(await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false)).FirstOrDefault(value => !CertificateInspector.IsCertificateAuthority(value))
            ?? throw new SslenseException(ErrorCodes.NotACertificateFile, $"'{path}' holds no certificate to revoke.");
        var authority = await authorities.GetAsync(authorityId, cancellationToken).ConfigureAwait(false);
        var sameAccount = (await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(value => string.Equals(value.AuthorityId, authority.Id, StringComparison.OrdinalIgnoreCase));
        await protocolClient.RevokeAsync(sameAccount?.Email ?? string.Empty, authority, certificate.RawData, reason, cancellationToken).ConfigureAwait(false);
        await history.TryAddAsync(new CertificateHistoryEntry(
                DateTimeOffset.UtcNow, Guid.Empty, CertificateInspector.Describe(certificate), CertificateHistoryKind.Revoked,
                $"Revoked from a file by {authority.Name} ({Describe(reason)}).", certificate.Thumbprint, NotAfter: certificate.NotAfter))
            .ConfigureAwait(false);
        var pending = Path.Combine(PendingDirectory, $"{certificate.Thumbprint}.cer");
        if (fileSystem.FileExists(pending))
        {
            fileSystem.DeleteFile(pending);
        }

        return $"Certificate {certificate.Thumbprint} ({CertificateInspector.Describe(certificate)}) was revoked by {authority.Name}.";
    }

    public async Task<string> ChangeAccountKeyAsync(string authorityId, CancellationToken cancellationToken = default)
    {
        // No order may use the old key while it is replaced.
        await using var exclusive = await _authorityLock.AcquireRemovalAsync(authorityId, cancellationToken).ConfigureAwait(false);
        var authority = await authorities.GetAsync(authorityId, cancellationToken).ConfigureAwait(false);
        await protocolClient.ChangeAccountKeyAsync(authority, cancellationToken).ConfigureAwait(false);
        return $"The account key for {authority.Name} was replaced. The old key no longer works, and certificates are not affected.";
    }

    internal static string CliName(CertificateRevocationReason reason) => reason switch
    {
        CertificateRevocationReason.KeyCompromise => "key-compromise",
        CertificateRevocationReason.Superseded => "superseded",
        CertificateRevocationReason.CessationOfOperation => "cessation",
        _ => "unspecified"
    };

    private static string Describe(CertificateRevocationReason reason) => reason switch
    {
        CertificateRevocationReason.KeyCompromise => "the key was compromised",
        CertificateRevocationReason.Superseded => "replaced",
        CertificateRevocationReason.CessationOfOperation => "no longer used",
        _ => "no reason given"
    };
}

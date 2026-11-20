using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

/// <summary>A certificate nothing uses, with why it can go.</summary>
public sealed record CleanupCandidate(string Thumbprint, string Name, string Issuer, DateTimeOffset NotAfter, string Reason);

/// <summary>
/// Finds certificates in LocalMachine\My that nothing uses and that are expired, test leftovers or replaced, and removes
/// the ones the administrator chooses (docs/design/certificate-cleanup.md). Nothing is removed without being chosen.
/// </summary>
public interface ICertificateCleanupService
{
    Task<IReadOnlyList<CleanupCandidate>> FindAsync(CancellationToken cancellationToken = default);

    /// <summary>Removes the chosen certificates that are still candidates when they are removed; returns what happened to each.</summary>
    Task<IReadOnlyList<string>> RemoveAsync(IReadOnlyList<string> thumbprints, CancellationToken cancellationToken = default);
}

internal sealed class CertificateCleanupService(
    ICertificateStore store,
    IIisService iisService,
    IManagedCertificateStore managedStore) : ICertificateCleanupService
{
    public async Task<IReadOnlyList<CleanupCandidate>> FindAsync(CancellationToken cancellationToken = default)
    {
        var certificates = await store.ListAsync(cancellationToken).ConfigureAwait(false);
        var inUse = await InUseAsync(cancellationToken).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var candidates = new List<CleanupCandidate>();
        foreach (var certificate in certificates.Where(value => !inUse.Contains(value.Thumbprint)))
        {
            var names = certificate.DnsNames ?? [];
            var newer = names.Count == 0
                ? null
                : certificates.Where(other => other.Thumbprint != certificate.Thumbprint &&
                                              other.NotAfter > certificate.NotAfter && other.NotAfter > now &&
                                              names.All(name => (other.DnsNames ?? []).Contains(name, StringComparer.OrdinalIgnoreCase)))
                    .OrderByDescending(other => other.NotAfter)
                    .FirstOrDefault();
            var reason = certificate.NotAfter <= now
                ? $"Expired on {certificate.NotAfter:yyyy-MM-dd}."
                : IsTestCertificate(certificate)
                    ? "A test certificate (Let's Encrypt staging or another test CA) that no site uses."
                    : newer is not null
                        ? $"Replaced by a newer certificate for the same names ({(newer.Thumbprint.Length > 8 ? newer.Thumbprint[..8] + "…" : newer.Thumbprint)}, expires {newer.NotAfter:yyyy-MM-dd})."
                        : null;
            if (reason is not null)
            {
                candidates.Add(new CleanupCandidate(
                    certificate.Thumbprint,
                    names.Count > 0 ? string.Join(", ", names) : certificate.FriendlyName is { Length: > 0 } friendly ? friendly : certificate.Subject ?? certificate.Thumbprint,
                    certificate.IssuerName ?? certificate.Issuer ?? "unknown",
                    certificate.NotAfter,
                    reason));
            }
        }

        return [.. candidates.OrderBy(candidate => candidate.NotAfter)];
    }

    public async Task<IReadOnlyList<string>> RemoveAsync(IReadOnlyList<string> thumbprints, CancellationToken cancellationToken = default)
    {
        // Looked at again now: a binding or a record may have started using one since the list was shown.
        var candidates = (await FindAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(candidate => candidate.Thumbprint, StringComparer.OrdinalIgnoreCase);
        var results = new List<string>();
        foreach (var thumbprint in thumbprints.Select(value => string.Concat(value.Where(char.IsAsciiLetterOrDigit)).ToUpperInvariant()).Distinct())
        {
            if (!candidates.TryGetValue(thumbprint, out var candidate))
            {
                results.Add(ErrorCodes.CleanupRefused.Format($"{thumbprint}: not removed, because it is in use, managed, or no longer a clean-up candidate."));
                continue;
            }

            await store.RemoveAsync(thumbprint, cancellationToken).ConfigureAwait(false);
            results.Add($"{thumbprint}: removed ({candidate.Name}). {candidate.Reason}");
        }

        return results;
    }

    private async Task<HashSet<string>> InUseAsync(CancellationToken cancellationToken)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var binding in (await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false)).SelectMany(site => site.Bindings))
        {
            if (binding.CertificateThumbprint is { } thumbprint) used.Add(thumbprint);
        }

        foreach (var thumbprint in await iisService.GetHttpSysCertificateThumbprintsAsync(cancellationToken).ConfigureAwait(false))
        {
            used.Add(thumbprint);
        }

        // An FTP site's certificate for FTP over TLS is not an HTTPS binding.
        foreach (var site in await iisService.GetFtpSitesAsync(cancellationToken).ConfigureAwait(false) ?? [])
        {
            if (site.Thumbprint is { } ftp) used.Add(ftp);
        }

        foreach (var record in await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
        {
            used.Add(record.Thumbprint);

            // Kept so the site can go back to it.
            if (record.PreviousThumbprint is { } previous) used.Add(previous);
        }

        return used;
    }

    private static bool IsTestCertificate(InstalledCertificate certificate) =>
        (certificate.Issuer ?? string.Empty).Contains("(STAGING)", StringComparison.OrdinalIgnoreCase) ||
        (certificate.Issuer ?? string.Empty).Contains("Pebble", StringComparison.OrdinalIgnoreCase) ||
        (certificate.Issuer ?? string.Empty).Contains("Fake LE", StringComparison.OrdinalIgnoreCase);
}

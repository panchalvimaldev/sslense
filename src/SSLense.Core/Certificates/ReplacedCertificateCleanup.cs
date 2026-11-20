using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

internal static class ReplacedCertificateCleanup
{
    /// <summary>
    /// Removes a certificate that was just replaced, unless an IIS binding still uses it.
    /// Returns what the administrator should know, or null when it was removed or nothing needed doing.
    /// </summary>
    /// <param name="sitesLeftOut">
    /// Sites expected to keep the old certificate for now, which are reported separately. The certificate stays while there are any,
    /// even if their bindings show none: IIS reads it from HTTP.sys, so a binding that lost its entry looks as if it uses nothing.
    /// </param>
    public static async Task<string?> RemoveIfUnusedAsync(
        IIisService iisService,
        ICertificateStore certificateStore,
        string oldThumbprint,
        string newThumbprint,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? sitesLeftOut = null)
    {
        if (string.Equals(oldThumbprint, newThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        var stillUsedBy = sites
            .Where(value => value.Bindings.Any(binding =>
                string.Equals(binding.CertificateThumbprint, oldThumbprint, StringComparison.OrdinalIgnoreCase)))
            .Select(value => value.Name)
            .Where(name => sitesLeftOut is null || !sitesLeftOut.Contains(name, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (stillUsedBy.Length > 0)
        {
            return "the old certificate was retained because an IIS binding still uses it on " +
                   $"{string.Join(", ", stillUsedBy.Select(name => $"'{name}'"))}. SSLense does not update those bindings, " +
                   "so they will keep the old certificate until it expires.";
        }

        if (sitesLeftOut is { Count: > 0 })
        {
            return null;
        }

        // An FTP site whose step has not moved it yet still serves the old certificate (docs/design/ftp-sites.md).
        var ftpSites = ((await iisService.GetFtpSitesAsync(cancellationToken).ConfigureAwait(false)) ?? [])
            .Where(site => string.Equals(site.Thumbprint, oldThumbprint, StringComparison.OrdinalIgnoreCase))
            .Select(site => $"'{site.Name}'")
            .ToArray();
        if (ftpSites.Length > 0)
        {
            return $"the old certificate was retained because the FTP site {string.Join(", ", ftpSites)} still uses it.";
        }

        try
        {
            await certificateStore.RemoveAsync(oldThumbprint, cancellationToken).ConfigureAwait(false);
            return null;
        }
        catch (Exception exception)
        {
            return $"the unused old certificate could not be removed: {exception.Message}";
        }
    }
}

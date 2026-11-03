using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

internal static class ReplacedCertificateCleanup
{
    /// <summary>
    /// Removes a certificate that was just replaced, unless an IIS binding still uses it.
    /// Returns what the administrator should know, or null when it was removed or nothing needed doing.
    /// </summary>
    public static async Task<string?> RemoveIfUnusedAsync(
        IIisService iisService,
        ICertificateStore certificateStore,
        string oldThumbprint,
        string newThumbprint,
        CancellationToken cancellationToken)
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
            .ToArray();
        if (stillUsedBy.Length > 0)
        {
            return "the old certificate was retained because an IIS binding still uses it on " +
                   $"{string.Join(", ", stillUsedBy.Select(name => $"'{name}'"))}. SSLense does not update those bindings, " +
                   "so they will keep the old certificate until it expires.";
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

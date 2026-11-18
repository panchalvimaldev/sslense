using SSLense.Core.Iis;

namespace SSLense.Core.Config;

/// <summary>
/// The names of certificates on IIS sites. The first certificate on a site is named after the site; every other one is
/// named <c>&lt;site&gt;/&lt;its first host&gt;</c>. IIS does not allow <c>/</c> in site names, so the site is always the
/// part before the first <c>/</c>. See docs/design/multiple-certificates-per-site.md.
/// </summary>
public static class ManagedCertificateNames
{
    public const char Separator = '/';

    /// <summary>The IIS site a certificate name belongs to: the name itself, or the part before the first <c>/</c>.</summary>
    public static string IisSiteOf(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var trimmed = name.Trim();
        var index = trimmed.IndexOf(Separator, StringComparison.Ordinal);
        return index < 0 ? trimmed : trimmed[..index].TrimEnd();
    }

    /// <summary>True for a certificate other than the first on its IIS site.</summary>
    public static bool IsAdditional(string name) => name.Contains(Separator, StringComparison.Ordinal);

    /// <summary>The name of another certificate on <paramref name="siteName"/>.</summary>
    public static string Additional(string siteName, string firstHost) => $"{siteName.Trim()}{Separator}{firstHost.Trim().ToLowerInvariant()}";

    /// <summary>The IIS site of a certificate name, or null when it does not exist.</summary>
    public static IisSite? FindSite(this IEnumerable<IisSite> sites, string name)
    {
        var siteName = IisSiteOf(name);
        return sites.FirstOrDefault(site => string.Equals(site.Name, siteName, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The certificates managed on an IIS site as their own record (not as a site sharing another's).</summary>
    public static IReadOnlyList<ManagedCertificate> OnSite(IEnumerable<ManagedCertificate> records, string siteName) =>
        records.Where(record => !record.NoSite &&
                                string.Equals(IisSiteOf(record.SiteName), IisSiteOf(siteName), StringComparison.OrdinalIgnoreCase))
            .ToArray();

    /// <summary>
    /// Which certificate on <paramref name="siteName"/> the host names belong to: the one that has any of them, or a new
    /// one, named after the site when the site has none yet. Refused when they belong to several.
    /// </summary>
    public static string Resolve(IEnumerable<ManagedCertificate> records, string siteName, IReadOnlyList<string> hosts)
    {
        if (IsAdditional(siteName))
        {
            return siteName.Trim();
        }

        var onSite = OnSite(records, siteName);
        var owners = onSite
            .Where(record => record.Hosts.Any(host => hosts.Contains(host, StringComparer.OrdinalIgnoreCase)))
            .ToArray();
        if (owners.Length > 1)
        {
            throw new InvalidOperationException(
                $"The host names {string.Join(", ", hosts)} belong to {owners.Length} certificates on IIS site '{siteName.Trim()}' " +
                $"({string.Join(", ", owners.Select(owner => $"'{owner.SiteName}': {string.Join(", ", owner.Hosts)}"))}). " +
                "Choose the host names of one certificate.");
        }

        if (owners.Length == 1)
        {
            return owners[0].SiteName;
        }

        var site = siteName.Trim();
        if (!onSite.Any(record => string.Equals(record.SiteName, site, StringComparison.OrdinalIgnoreCase)))
        {
            return site;
        }

        var name = Additional(site, hosts[0]);
        if (onSite.Any(record => string.Equals(record.SiteName, name, StringComparison.OrdinalIgnoreCase)))
        {
            // The certificate first named after this host has moved to other host names.
            throw new InvalidOperationException(
                $"IIS site '{site}' already has a certificate named '{name}', for other host names. Replace that certificate " +
                $"with --site \"{name}\", or choose the host names in another order.");
        }

        return name;
    }

    /// <summary>
    /// Refuses host names that another certificate on the same IIS site already has, because each host's binding has
    /// one certificate.
    /// </summary>
    public static void ThrowIfHostsTaken(IEnumerable<ManagedCertificate> records, string name, IReadOnlyList<string> hosts)
    {
        foreach (var other in OnSite(records, name).Where(record => !string.Equals(record.SiteName, name.Trim(), StringComparison.OrdinalIgnoreCase)))
        {
            var taken = other.Hosts.Where(host => hosts.Contains(host, StringComparer.OrdinalIgnoreCase)).ToArray();
            if (taken.Length > 0)
            {
                throw new InvalidOperationException(
                    $"{string.Join(", ", taken)} on IIS site '{IisSiteOf(name)}' already use{(taken.Length == 1 ? "s" : string.Empty)} the certificate " +
                    $"managed as '{other.SiteName}'. Each host name on a site has one certificate; replace that one instead.");
            }
        }
    }
}

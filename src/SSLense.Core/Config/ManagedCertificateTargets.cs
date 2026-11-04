namespace SSLense.Core.Config;

/// <summary>
/// The sites a record covers. One IIS site belongs to one record, so <c>--site</c> and the per-site locks stay unambiguous
/// (docs/design/shared-certificates.md, section 3).
/// </summary>
public static class ManagedCertificateTargets
{
    /// <summary>From this close to expiry, a site with a problem no longer holds back the others (section 6 of that design).</summary>
    internal static readonly TimeSpan LeaveOutWindow = TimeSpan.FromDays(7);

    public static bool IsShared(this ManagedCertificate record) => record.AdditionalTargets is { Count: > 0 };

    /// <summary>Only certificates SSLense obtains through DNS validation, because HTTP validation would have to reach every site.</summary>
    public static bool CanBeShared(this ManagedCertificate record) =>
        record.Source == CertificateSource.Acme && record.ValidationMethod != ValidationMethod.Http01;

    /// <summary>Every site using the record's certificate, starting with the first site.</summary>
    public static IReadOnlyList<CertificateTarget> AllTargets(this ManagedCertificate record) =>
        [new CertificateTarget(record.SiteName, record.Hosts, record.SitePendingSince), .. record.AdditionalTargets ?? []];

    public static IReadOnlyList<string> AllSiteNames(this ManagedCertificate record) =>
        [record.SiteName, .. (record.AdditionalTargets ?? []).Select(target => target.SiteName)];

    public static bool ManagesSite(this ManagedCertificate record, string siteName) =>
        record.AllSiteNames().Contains(siteName.Trim(), StringComparer.OrdinalIgnoreCase);

    public static bool HasPendingSites(this ManagedCertificate record) =>
        record.AllTargets().Any(target => target.PendingSince is not null);

    /// <summary>The record with these sites; the first becomes the record's site.</summary>
    public static ManagedCertificate WithTargets(this ManagedCertificate record, IReadOnlyList<CertificateTarget> targets) =>
        record with
        {
            SiteName = targets[0].SiteName,
            Hosts = targets[0].Hosts,
            SitePendingSince = targets[0].PendingSince,
            AdditionalTargets = targets.Count > 1 ? targets.Skip(1).ToArray() : null
        };

    /// <summary>The site and hosts for display: the first site alone, or every site of a shared certificate.</summary>
    public static string DescribeSites(this ManagedCertificate record) =>
        string.Join(", ", record.AllTargets().Select(target => $"{target.SiteName} ({string.Join(", ", target.Hosts)})"));

    /// <summary>
    /// A site that uses another site's certificate cannot get its own, because renewal would put it back.
    /// </summary>
    internal static void ThrowIfAdditionalSite(IReadOnlyList<ManagedCertificate> records, string siteName)
    {
        var owner = records.FirstOrDefault(record =>
            !string.Equals(record.SiteName, siteName.Trim(), StringComparison.OrdinalIgnoreCase) &&
            record.ManagesSite(siteName));
        if (owner is not null)
        {
            throw new InvalidOperationException(
                $"IIS site '{siteName}' uses the certificate managed for '{owner.SiteName}'. Renew it with " +
                $"'SSLense.Cli renew --site \"{siteName}\"'. To give the site its own certificate, first run " +
                $"'SSLense.Cli share remove --site \"{siteName}\"'.");
        }
    }
}

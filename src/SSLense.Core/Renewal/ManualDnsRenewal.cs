using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

internal static class ManualDnsRenewal
{
    /// <summary>The command that renews a manual DNS certificate by hand, with the same names, hosts, and CA.</summary>
    public static string Command(ManagedCertificate certificate)
    {
        var names = certificate.CertificateNames is { } values
            ? $" --names \"{string.Join(",", values)}\""
            : string.Empty;

        // Always listed: without them, issue would use every named binding on the site.
        var hosts = $" --hosts \"{string.Join(",", certificate.Hosts)}\"";
        var output = certificate.OutputDirectory is { } directory ? $" --output \"{directory}\"" : string.Empty;
        // Let's Encrypt keeps the short forms; any other CA is named. Confirming production is harmless for a test CA.
        var authority = certificate.AuthorityId switch
        {
            CertificateAuthorities.LetsEncryptStagingId => string.Empty,
            CertificateAuthorities.LetsEncryptId => " --production --accept-production-risk",
            var id => $" --ca {id} --accept-production-risk"
        };
        return $"SSLense.Cli issue --site \"{certificate.SiteName}\" --email {certificate.Email} --validation dns-manual --force{names}{hosts}{output}{authority}";
    }
}

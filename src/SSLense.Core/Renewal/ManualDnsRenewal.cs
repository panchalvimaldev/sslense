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
        var production = certificate.AuthorityId == CertificateAuthorities.LetsEncryptId
            ? " --production --accept-production-risk"
            : string.Empty;
        return $"SSLense.Cli issue --site \"{certificate.SiteName}\" --email {certificate.Email} --validation dns-manual --force{names}{hosts}{output}{production}";
    }
}

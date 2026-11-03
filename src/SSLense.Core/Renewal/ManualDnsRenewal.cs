using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

internal static class ManualDnsRenewal
{
    /// <summary>The command that renews a manual DNS certificate by hand, with the same names, hosts, and CA.</summary>
    public static string Command(ManagedCertificate certificate)
    {
        var names = certificate.CertificateNames is { } values
            ? $" --names \"{string.Join(",", values)}\" --hosts \"{string.Join(",", certificate.Hosts)}\""
            : string.Empty;
        var production = certificate.AuthorityId == CertificateAuthorities.LetsEncryptId
            ? " --production --accept-production-risk"
            : string.Empty;
        return $"SSLense.Cli issue --site \"{certificate.SiteName}\" --email {certificate.Email} --validation dns-manual --force{names}{production}";
    }
}

namespace SSLense.Core.DnsValidation;

public enum DnsProviderType
{
    Cloudflare = 0,

    /// <summary>The administrator's PowerShell script (docs/design/dns-script.md).</summary>
    Script = 1,

    /// <summary>An account on an acme-dns server, reached through one CNAME (docs/design/acme-dns.md).</summary>
    AcmeDns = 2
}

/// <summary>Credentials for changing one DNS zone. The name identifies the profile.</summary>
/// <param name="ZoneName">
/// The zone records are changed in. For acme-dns, the account's full domain on the acme-dns server, which is where the CNAME
/// leads, so the usual selection by zone finds the account.
/// </param>
/// <param name="ZoneId">The provider's ID for the zone, so the token needs no permission to list zones.</param>
/// <param name="ProtectedToken">
/// The API token, encrypted with DPAPI and Base64-encoded. Empty for a script that needs no secret. For acme-dns, the
/// account's password.
/// </param>
/// <param name="ScriptSha256">For a script, the SHA-256 of SSLense's own copy, checked before every run.</param>
/// <param name="ScriptTimeoutSeconds">For a script, how long one call may run; the default when null.</param>
/// <param name="AcmeDnsServer">For acme-dns, the server's HTTPS address.</param>
/// <param name="AcmeDnsUsername">For acme-dns, the account's username.</param>
/// <param name="AcmeDnsSubdomain">For acme-dns, the account's subdomain, which updates name.</param>
/// <param name="AcmeDnsDomain">For acme-dns, the domain whose <c>_acme-challenge</c> CNAME points to the account.</param>
public sealed record DnsProviderProfile(
    string Name,
    DnsProviderType Provider,
    string ZoneName,
    string? ZoneId,
    string ProtectedToken,
    string? ScriptSha256 = null,
    int? ScriptTimeoutSeconds = null,
    Uri? AcmeDnsServer = null,
    string? AcmeDnsUsername = null,
    string? AcmeDnsSubdomain = null,
    string? AcmeDnsDomain = null)
{
    /// <summary>For acme-dns, the record the administrator creates at their DNS host.</summary>
    public string? AcmeDnsCname => AcmeDnsDomain is { } domain
        ? $"{DnsNames.ChallengeRecord(domain)}  CNAME  {DnsNames.Normalize(ZoneName)}"
        : null;
}

/// <summary>One TXT record that must be visible in public DNS for a validation.</summary>
public sealed record DnsTxtRecord(string Name, string Value);

/// <summary>
/// Shows the administrator the records to create by hand. Returns true once they are created, or false to stop.
/// </summary>
public delegate Task<bool> ManualDnsConfirmation(IReadOnlyList<DnsTxtRecord> records, CancellationToken cancellationToken);

internal static class DnsNames
{
    private const string ChallengePrefix = "_acme-challenge.";

    public static string Normalize(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    public static bool IsWildcard(string certificateName) => certificateName.StartsWith("*.", StringComparison.Ordinal);

    /// <summary>The record a CA reads for a certificate name; a wildcard uses its base name's record.</summary>
    public static string ChallengeRecord(string certificateName)
    {
        var name = Normalize(certificateName);
        return ChallengePrefix + (name.StartsWith("*.", StringComparison.Ordinal) ? name[2..] : name);
    }

    public static bool IsInZone(string name, string zone)
    {
        name = Normalize(name);
        zone = Normalize(zone);
        return name == zone || name.EndsWith($".{zone}", StringComparison.Ordinal);
    }

    /// <summary>The profile with the longest zone name containing the record, or null.</summary>
    public static DnsProviderProfile? SelectProfile(IEnumerable<DnsProviderProfile> profiles, string recordName) =>
        profiles
            .Where(profile => IsInZone(recordName, profile.ZoneName))
            .OrderByDescending(profile => Normalize(profile.ZoneName).Length)
            .FirstOrDefault();
}

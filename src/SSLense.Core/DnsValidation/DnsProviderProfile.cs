namespace SSLense.Core.DnsValidation;

public enum DnsProviderType
{
    Cloudflare = 0
}

/// <summary>Credentials for changing one DNS zone. The name identifies the profile.</summary>
/// <param name="ZoneId">The provider's ID for the zone, so the token needs no permission to list zones.</param>
/// <param name="ProtectedToken">The API token, encrypted with DPAPI and Base64-encoded.</param>
public sealed record DnsProviderProfile(
    string Name,
    DnsProviderType Provider,
    string ZoneName,
    string? ZoneId,
    string ProtectedToken);

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

namespace SSLense.Core.DnsValidation;

internal sealed record DnsCaaRecord(int Flags, string Tag, string Value);

/// <summary>Decides whether CAA records allow a CA to issue a name, following RFC 8659.</summary>
internal static class CaaPolicy
{
    private const int CriticalFlag = 128;
    private static readonly string[] KnownTags = ["issue", "issuewild", "iodef", "issuemail", "issuevmc"];

    /// <param name="owner">The name that holds <paramref name="records"/>: the certificate name or its closest parent with CAA records.</param>
    /// <returns>Why the CA would refuse, or null when it is allowed.</returns>
    public static string? FindProblem(string certificateName, string owner, IReadOnlyList<DnsCaaRecord> records, string caDomain) =>
        FindProblem(certificateName, owner, records, [caDomain]);

    /// <param name="caDomains">Every domain the CA accepts in CAA records; the first is the one to suggest.</param>
    public static string? FindProblem(string certificateName, string owner, IReadOnlyList<DnsCaaRecord> records, IReadOnlyList<string> caDomains)
    {
        var caDomain = caDomains[0];
        var critical = records.FirstOrDefault(record =>
            (record.Flags & CriticalFlag) != 0 && !KnownTags.Contains(record.Tag, StringComparer.OrdinalIgnoreCase));
        if (critical is not null)
        {
            return $"The CAA record '{critical.Tag}' at '{owner}' is marked critical and is not understood, so the certificate authority would refuse '{certificateName}'.";
        }

        var wildcard = DnsNames.IsWildcard(certificateName);
        var tag = wildcard && records.Any(record => HasTag(record, "issuewild")) ? "issuewild" : "issue";
        var relevant = records.Where(record => HasTag(record, tag)).ToArray();
        if (relevant.Length == 0 || relevant.Any(record => caDomains.Contains(IssuerDomain(record), StringComparer.OrdinalIgnoreCase)))
        {
            return null;
        }

        return $"The CAA records at '{owner}' do not allow {caDomain} to issue '{certificateName}'. " +
               $"Add a CAA record at '{owner}' with the tag '{(wildcard ? "issuewild" : "issue")}' and the value '{caDomain}'.";
    }

    private static bool HasTag(DnsCaaRecord record, string tag) => string.Equals(record.Tag, tag, StringComparison.OrdinalIgnoreCase);

    /// <summary>The value may carry parameters after a semicolon; a value of only ";" allows no CA.</summary>
    private static string IssuerDomain(DnsCaaRecord record) => record.Value.Split(';')[0].Trim();
}

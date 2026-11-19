using System.Net;
using System.Text;
using System.Xml.Linq;
using SSLense.Core.Acme;
using SSLense.Core.Errors;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// Amazon Route 53, through its REST API signed with Signature Version 4 (docs/design/dns-providers.md). The secret is
/// "access key ID:secret access key"; the zone ID is the hosted zone's ID, such as Z0123456789ABCDEFGHIJ.
/// </summary>
internal sealed class Route53DnsProvider(HttpClient httpClient, ISecretProtector protector) : HttpDnsProvider(httpClient, protector)
{
    private const string Endpoint = "https://route53.amazonaws.com/2013-04-01";
    private static readonly XNamespace Ns = "https://route53.amazonaws.com/doc/2013-04-01/";

    /// <summary>For tests: the time requests are signed at.</summary>
    internal Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    public override DnsProviderType Type => DnsProviderType.Route53;

    protected override string ServiceName => "Amazon Route 53";

    protected override string PermissionAdvice(DnsProviderProfile profile) =>
        $"Check that the access key is active and its IAM policy allows route53:GetHostedZone, route53:ListResourceRecordSets and " +
        $"route53:ChangeResourceRecordSets on hosted zone {profile.ZoneId}.";

    public override async Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        using var request = Signed(HttpMethod.Get, $"{Endpoint}/hostedzone/{ZoneId(profile)}", string.Empty, profile);
        var (_, body) = await SendAsync(request, "read the hosted zone", profile, cancellationToken).ConfigureAwait(false);
        var zone = XDocument.Parse(body).Descendants(Ns + "Name").FirstOrDefault()?.Value;
        if (zone is not null && DnsNames.Normalize(zone) != DnsNames.Normalize(profile.ZoneName))
        {
            throw new SslenseException(ErrorCodes.DnsProviderDetailsInvalid,
                $"Hosted zone {profile.ZoneId} is {DnsNames.Normalize(zone)}, not {DnsNames.Normalize(profile.ZoneName)}. Check the zone ID.");
        }
    }

    public override async Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        var (values, _) = await ReadAsync(profile, name, cancellationToken).ConfigureAwait(false);
        if (values.Contains(value))
        {
            return;
        }

        // A record set holds every value at the name, so the new value is added to the others.
        await ChangeAsync(profile, "UPSERT", name, [.. values, value], RecordTtlSeconds, $"add the TXT record '{name}'", cancellationToken).ConfigureAwait(false);
    }

    public override async Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        var (values, ttl) = await ReadAsync(profile, name, cancellationToken).ConfigureAwait(false);
        if (!values.Contains(value))
        {
            return;
        }

        var remaining = values.Where(existing => existing != value).ToArray();
        await (remaining.Length > 0
                ? ChangeAsync(profile, "UPSERT", name, remaining, ttl, $"remove the TXT record '{name}'", cancellationToken)
                : ChangeAsync(profile, "DELETE", name, values, ttl, $"remove the TXT record '{name}'", cancellationToken))
            .ConfigureAwait(false);
    }

    private async Task<(IReadOnlyList<string> Values, int Ttl)> ReadAsync(DnsProviderProfile profile, string name, CancellationToken cancellationToken)
    {
        var fqdn = DnsNames.Normalize(name) + ".";
        using var request = Signed(
            HttpMethod.Get,
            $"{Endpoint}/hostedzone/{ZoneId(profile)}/rrset?name={Uri.EscapeDataString(fqdn)}&type=TXT&maxitems=1",
            string.Empty,
            profile);
        var (_, body) = await SendAsync(request, $"read the TXT records at '{name}'", profile, cancellationToken).ConfigureAwait(false);

        // The list starts at the name, so the first set may be another name's.
        var set = XDocument.Parse(body).Descendants(Ns + "ResourceRecordSet").FirstOrDefault(element =>
            DnsNames.Normalize(element.Element(Ns + "Name")?.Value ?? string.Empty) == DnsNames.Normalize(name) &&
            element.Element(Ns + "Type")?.Value == "TXT");
        if (set is null)
        {
            return ([], RecordTtlSeconds);
        }

        var values = set.Descendants(Ns + "Value").Select(element => Unquote(element.Value)).ToArray();
        return (values, int.TryParse(set.Element(Ns + "TTL")?.Value, out var ttl) ? ttl : RecordTtlSeconds);
    }

    private async Task ChangeAsync(
        DnsProviderProfile profile,
        string action,
        string name,
        IReadOnlyList<string> values,
        int ttl,
        string description,
        CancellationToken cancellationToken)
    {
        var body = new XDocument(
            new XElement(Ns + "ChangeResourceRecordSetsRequest",
                new XElement(Ns + "ChangeBatch",
                    new XElement(Ns + "Comment", "SSLense certificate validation"),
                    new XElement(Ns + "Changes",
                        new XElement(Ns + "Change",
                            new XElement(Ns + "Action", action),
                            new XElement(Ns + "ResourceRecordSet",
                                new XElement(Ns + "Name", DnsNames.Normalize(name) + "."),
                                new XElement(Ns + "Type", "TXT"),
                                new XElement(Ns + "TTL", ttl),
                                new XElement(Ns + "ResourceRecords",
                                    values.Select(value => new XElement(Ns + "ResourceRecord", new XElement(Ns + "Value", Quote(value))))))))))).ToString(SaveOptions.DisableFormatting);
        using var request = Signed(HttpMethod.Post, $"{Endpoint}/hostedzone/{ZoneId(profile)}/rrset", body, profile);
        request.Content = new StringContent(body, Encoding.UTF8, "text/xml");
        await SendAsync(request, description, profile, cancellationToken).ConfigureAwait(false);
    }

    private HttpRequestMessage Signed(HttpMethod method, string url, string body, DnsProviderProfile profile)
    {
        var secret = Secret(profile);
        var separator = secret.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0)
        {
            throw new SslenseException(ErrorCodes.DnsSecretUnreadable,
                $"The credentials for DNS provider '{profile.Name}' are not an access key ID and secret access key. Remove the provider and add it again.");
        }

        var request = new HttpRequestMessage(method, url);
        AwsSignatureV4.Sign(request, body, secret[..separator], secret[(separator + 1)..], "us-east-1", "route53", Clock());
        return request;
    }

    private static string ZoneId(DnsProviderProfile profile) =>
        Uri.EscapeDataString((profile.ZoneId ?? throw new SslenseException(ErrorCodes.DnsProviderDetailsInvalid,
            $"DNS provider '{profile.Name}' has no Route 53 hosted zone ID.")).Replace("/hostedzone/", string.Empty, StringComparison.OrdinalIgnoreCase));
}

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SSLense.Core.Acme;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// DigitalOcean, with an API token with read and write access to Domains (docs/design/dns-providers.md). The zone is the
/// domain as DigitalOcean lists it.
/// </summary>
internal sealed class DigitalOceanDnsProvider(HttpClient httpClient, ISecretProtector protector) : HttpDnsProvider(httpClient, protector)
{
    private const string Api = "https://api.digitalocean.com/v2";

    // DigitalOcean's lowest TTL.
    private const int Ttl = 30;

    public override DnsProviderType Type => DnsProviderType.DigitalOcean;

    protected override string ServiceName => "DigitalOcean";

    protected override string PermissionAdvice(DnsProviderProfile profile) =>
        $"Check that the API token is valid and has read and write access to Domains, including {profile.ZoneName}.";

    public override async Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        using var request = Authorized(HttpMethod.Get, $"{Api}/domains/{Domain(profile)}", profile);
        await SendAsync(request, "read the domain", profile, cancellationToken).ConfigureAwait(false);
    }

    public override async Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        if ((await FindAsync(profile, name, cancellationToken).ConfigureAwait(false)).Any(record => record.Value == value))
        {
            return;
        }

        using var request = Authorized(HttpMethod.Post, $"{Api}/domains/{Domain(profile)}/records", profile);
        request.Content = System.Net.Http.Json.JsonContent.Create(new { type = "TXT", name = Relative(name, profile.ZoneName), data = value, ttl = Ttl });
        await SendAsync(request, $"add the TXT record '{name}'", profile, cancellationToken).ConfigureAwait(false);
    }

    public override async Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        foreach (var record in (await FindAsync(profile, name, cancellationToken).ConfigureAwait(false)).Where(record => record.Value == value))
        {
            using var request = Authorized(HttpMethod.Delete, $"{Api}/domains/{Domain(profile)}/records/{record.Id}", profile);
            await SendAsync(request, $"remove the TXT record '{name}'", profile, cancellationToken, HttpStatusCode.NotFound).ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyList<(long Id, string Value)>> FindAsync(DnsProviderProfile profile, string name, CancellationToken cancellationToken)
    {
        using var request = Authorized(
            HttpMethod.Get,
            $"{Api}/domains/{Domain(profile)}/records?type=TXT&name={Uri.EscapeDataString(DnsNames.Normalize(name))}&per_page=200",
            profile);
        var (_, body) = await SendAsync(request, $"read the TXT records at '{name}'", profile, cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(body);
        return document.RootElement.TryGetProperty("domain_records", out var records)
            ? records.EnumerateArray()
                .Select(record => (record.GetProperty("id").GetInt64(), Unquote(record.GetProperty("data").GetString() ?? string.Empty)))
                .ToArray()
            : [];
    }

    private HttpRequestMessage Authorized(HttpMethod method, string url, DnsProviderProfile profile)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Secret(profile));
        return request;
    }

    private static string Domain(DnsProviderProfile profile) => Uri.EscapeDataString(DnsNames.Normalize(profile.ZoneName));
}

/// <summary>
/// Hetzner DNS, through the Hetzner Cloud API's zones (docs/design/dns-providers.md), with an API token of a project
/// whose zones it may change. The zone is the zone's name. Records are added to and removed from the record set, so
/// other values at the name are kept.
/// </summary>
internal sealed class HetznerDnsProvider(HttpClient httpClient, ISecretProtector protector) : HttpDnsProvider(httpClient, protector)
{
    private const string Api = "https://api.hetzner.cloud/v1";

    public override DnsProviderType Type => DnsProviderType.Hetzner;

    protected override string ServiceName => "Hetzner";

    protected override string PermissionAdvice(DnsProviderProfile profile) =>
        $"Check that the API token is valid, has read and write permission, and belongs to the project that holds zone {profile.ZoneName}.";

    public override async Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        using var request = Authorized(HttpMethod.Get, $"{Api}/zones/{Zone(profile)}", profile);
        await SendAsync(request, "read the zone", profile, cancellationToken).ConfigureAwait(false);
    }

    public override async Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        using var request = Authorized(HttpMethod.Post, $"{RecordSetUrl(profile, name)}/actions/add_records", profile);
        request.Content = System.Net.Http.Json.JsonContent.Create(new { ttl = RecordTtlSeconds, records = new[] { new { value = Quote(value) } } });
        await SendAsync(request, $"add the TXT record '{name}'", profile, cancellationToken).ConfigureAwait(false);
    }

    public override async Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        using var request = Authorized(HttpMethod.Post, $"{RecordSetUrl(profile, name)}/actions/remove_records", profile);
        request.Content = System.Net.Http.Json.JsonContent.Create(new { records = new[] { new { value = Quote(value) } } });
        await SendAsync(request, $"remove the TXT record '{name}'", profile, cancellationToken, HttpStatusCode.NotFound).ConfigureAwait(false);
    }

    private HttpRequestMessage Authorized(HttpMethod method, string url, DnsProviderProfile profile)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Secret(profile));
        return request;
    }

    private static string Zone(DnsProviderProfile profile) => Uri.EscapeDataString(DnsNames.Normalize(profile.ZoneName));

    private static string RecordSetUrl(DnsProviderProfile profile, string name) =>
        $"{Api}/zones/{Zone(profile)}/rrsets/{Uri.EscapeDataString(Relative(name, profile.ZoneName))}/TXT";
}

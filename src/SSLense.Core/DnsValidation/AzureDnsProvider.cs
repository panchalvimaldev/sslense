using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SSLense.Core.Acme;
using SSLense.Core.Errors;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// Azure DNS, through Azure Resource Manager with an app registration's client secret (docs/design/dns-providers.md).
/// The secret is "tenant ID:client ID:client secret"; the zone ID is "subscription ID/resource group".
/// </summary>
internal sealed class AzureDnsProvider(HttpClient httpClient, ISecretProtector protector) : HttpDnsProvider(httpClient, protector)
{
    private const string ApiVersion = "2018-05-01";

    public override DnsProviderType Type => DnsProviderType.AzureDns;

    protected override string ServiceName => "Azure DNS";

    protected override string PermissionAdvice(DnsProviderProfile profile) =>
        $"Check the client secret has not expired, and that the app registration has the DNS Zone Contributor role on the zone {profile.ZoneName}.";

    public override async Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        using var request = await AuthorizedAsync(HttpMethod.Get, ZoneUrl(profile), profile, cancellationToken).ConfigureAwait(false);
        await SendAsync(request, "read the DNS zone", profile, cancellationToken).ConfigureAwait(false);
    }

    public override async Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        var values = await ReadAsync(profile, name, cancellationToken).ConfigureAwait(false);
        if (!values.Contains(value))
        {
            await WriteAsync(profile, name, [.. values, value], $"add the TXT record '{name}'", cancellationToken).ConfigureAwait(false);
        }
    }

    public override async Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        var values = await ReadAsync(profile, name, cancellationToken).ConfigureAwait(false);
        if (!values.Contains(value))
        {
            return;
        }

        var remaining = values.Where(existing => existing != value).ToArray();
        if (remaining.Length > 0)
        {
            await WriteAsync(profile, name, remaining, $"remove the TXT record '{name}'", cancellationToken).ConfigureAwait(false);
            return;
        }

        using var request = await AuthorizedAsync(HttpMethod.Delete, RecordUrl(profile, name), profile, cancellationToken).ConfigureAwait(false);
        await SendAsync(request, $"remove the TXT record '{name}'", profile, cancellationToken, HttpStatusCode.NotFound).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<string>> ReadAsync(DnsProviderProfile profile, string name, CancellationToken cancellationToken)
    {
        using var request = await AuthorizedAsync(HttpMethod.Get, RecordUrl(profile, name), profile, cancellationToken).ConfigureAwait(false);
        var (status, body) = await SendAsync(request, $"read the TXT records at '{name}'", profile, cancellationToken, HttpStatusCode.NotFound).ConfigureAwait(false);
        if (status == HttpStatusCode.NotFound)
        {
            return [];
        }

        using var document = JsonDocument.Parse(body);
        return document.RootElement.TryGetProperty("properties", out var properties) &&
               properties.TryGetProperty("TXTRecords", out var records)
            ? records.EnumerateArray()
                .Select(record => string.Concat(record.GetProperty("value").EnumerateArray().Select(part => part.GetString())))
                .ToArray()
            : [];
    }

    private async Task WriteAsync(DnsProviderProfile profile, string name, IReadOnlyList<string> values, string action, CancellationToken cancellationToken)
    {
        using var request = await AuthorizedAsync(HttpMethod.Put, RecordUrl(profile, name), profile, cancellationToken).ConfigureAwait(false);
        request.Content = System.Net.Http.Json.JsonContent.Create(new
        {
            properties = new
            {
                TTL = RecordTtlSeconds,
                TXTRecords = values.Select(value => new { value = new[] { value } }).ToArray()
            }
        });
        await SendAsync(request, action, profile, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpRequestMessage> AuthorizedAsync(HttpMethod method, string url, DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        var parts = Secret(profile).Split(':', 3);
        if (parts.Length != 3 || parts.Any(part => part.Length == 0))
        {
            throw new SslenseException(ErrorCodes.DnsSecretUnreadable,
                $"The credentials for DNS provider '{profile.Name}' are not a tenant ID, client ID and client secret. Remove the provider and add it again.");
        }

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{Uri.EscapeDataString(parts[0])}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = parts[1],
                ["client_secret"] = parts[2],
                ["scope"] = "https://management.azure.com/.default"
            })
        };
        var (_, body) = await SendAsync(tokenRequest, "sign in with the app registration", profile, cancellationToken).ConfigureAwait(false);
        using var document = JsonDocument.Parse(body);
        var request = new HttpRequestMessage(method, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", document.RootElement.GetProperty("access_token").GetString());
        return request;
    }

    private static string ZoneUrl(DnsProviderProfile profile)
    {
        var location = (profile.ZoneId ?? string.Empty).Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (location.Length != 2)
        {
            throw new SslenseException(ErrorCodes.DnsProviderDetailsInvalid,
                $"DNS provider '{profile.Name}' needs its zone's subscription ID and resource group, as <subscription ID>/<resource group>.");
        }

        return $"https://management.azure.com/subscriptions/{Uri.EscapeDataString(location[0])}/resourceGroups/{Uri.EscapeDataString(location[1])}" +
               $"/providers/Microsoft.Network/dnsZones/{Uri.EscapeDataString(DnsNames.Normalize(profile.ZoneName))}?api-version={ApiVersion}";
    }

    private static string RecordUrl(DnsProviderProfile profile, string name)
    {
        var zone = ZoneUrl(profile);
        var path = zone[..zone.IndexOf('?', StringComparison.Ordinal)];
        return $"{path}/TXT/{Uri.EscapeDataString(Relative(name, profile.ZoneName))}?api-version={ApiVersion}";
    }
}

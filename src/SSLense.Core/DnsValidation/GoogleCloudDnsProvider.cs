using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSLense.Core.Acme;
using SSLense.Core.Errors;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// Google Cloud DNS, with a service account key (docs/design/dns-providers.md). The secret is the key's JSON file, as
/// Google gives it; the zone ID is the managed zone's name, such as example-com.
/// </summary>
internal sealed class GoogleCloudDnsProvider(HttpClient httpClient, ISecretProtector protector) : HttpDnsProvider(httpClient, protector)
{
    private const string Api = "https://dns.googleapis.com/dns/v1";
    private const string Scope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

    /// <summary>For tests: the time the sign-in token is issued at.</summary>
    internal Func<DateTimeOffset> Clock { get; init; } = () => DateTimeOffset.UtcNow;

    public override DnsProviderType Type => DnsProviderType.GoogleCloudDns;

    protected override string ServiceName => "Google Cloud DNS";

    protected override string PermissionAdvice(DnsProviderProfile profile) =>
        $"Check that the service account key is active, and that the account has the DNS Administrator role on managed zone {profile.ZoneId}.";

    public override async Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken)
    {
        var (request, _) = await AuthorizedAsync(HttpMethod.Get, profile, string.Empty, cancellationToken).ConfigureAwait(false);
        using (request)
        {
            await SendAsync(request, "read the managed zone", profile, cancellationToken).ConfigureAwait(false);
        }
    }

    public override async Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        var current = await ReadAsync(profile, name, cancellationToken).ConfigureAwait(false);
        if (current?.Values.Contains(value) == true)
        {
            return;
        }

        await ChangeAsync(profile, name, current, [.. current?.Values ?? [], value], $"add the TXT record '{name}'", cancellationToken).ConfigureAwait(false);
    }

    public override async Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken)
    {
        var current = await ReadAsync(profile, name, cancellationToken).ConfigureAwait(false);
        if (current is null || !current.Values.Contains(value))
        {
            return;
        }

        await ChangeAsync(profile, name, current, [.. current.Values.Where(existing => existing != value)], $"remove the TXT record '{name}'", cancellationToken)
            .ConfigureAwait(false);
    }

    private sealed record RecordSet(IReadOnlyList<string> Values, int Ttl, JsonElement Original);

    private async Task<RecordSet?> ReadAsync(DnsProviderProfile profile, string name, CancellationToken cancellationToken)
    {
        var (request, _) = await AuthorizedAsync(
                HttpMethod.Get, profile, $"/rrsets?type=TXT&name={Uri.EscapeDataString(DnsNames.Normalize(name) + ".")}", cancellationToken)
            .ConfigureAwait(false);
        using (request)
        {
            var (_, body) = await SendAsync(request, $"read the TXT records at '{name}'", profile, cancellationToken).ConfigureAwait(false);
            using var document = JsonDocument.Parse(body);
            if (!document.RootElement.TryGetProperty("rrsets", out var sets) || sets.GetArrayLength() == 0)
            {
                return null;
            }

            var set = sets[0].Clone();
            return new RecordSet(
                set.GetProperty("rrdatas").EnumerateArray().Select(data => Unquote(data.GetString() ?? string.Empty)).ToArray(),
                set.TryGetProperty("ttl", out var ttl) && ttl.TryGetInt32(out var seconds) ? seconds : RecordTtlSeconds,
                set);
        }
    }

    /// <summary>Google replaces a record set by deleting it exactly as it is and adding the new one, in one change.</summary>
    private async Task ChangeAsync(
        DnsProviderProfile profile,
        string name,
        RecordSet? current,
        IReadOnlyList<string> values,
        string action,
        CancellationToken cancellationToken)
    {
        var change = new Dictionary<string, object>
        {
            ["deletions"] = current is null ? Array.Empty<JsonElement>() : [current.Original],
            ["additions"] = values.Count == 0
                ? Array.Empty<object>()
                : [new { name = DnsNames.Normalize(name) + ".", type = "TXT", ttl = current?.Ttl ?? RecordTtlSeconds, rrdatas = values.Select(Quote).ToArray() }]
        };
        var (request, _) = await AuthorizedAsync(HttpMethod.Post, profile, "/changes", cancellationToken).ConfigureAwait(false);
        using (request)
        {
            request.Content = System.Net.Http.Json.JsonContent.Create(change);
            await SendAsync(request, action, profile, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<(HttpRequestMessage Request, string Project)> AuthorizedAsync(
        HttpMethod method,
        DnsProviderProfile profile,
        string path,
        CancellationToken cancellationToken)
    {
        string email, privateKey, project, tokenUri;
        try
        {
            using var key = JsonDocument.Parse(Secret(profile));
            var root = key.RootElement;
            email = root.GetProperty("client_email").GetString()!;
            privateKey = root.GetProperty("private_key").GetString()!;
            project = root.GetProperty("project_id").GetString()!;
            tokenUri = root.TryGetProperty("token_uri", out var uri) ? uri.GetString()! : "https://oauth2.googleapis.com/token";
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new SslenseException(ErrorCodes.DnsSecretUnreadable,
                $"The credentials for DNS provider '{profile.Name}' are not a Google service account key. Remove the provider and add it again with the key's JSON file.",
                exception);
        }

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenUri)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                ["assertion"] = CreateAssertion(email, privateKey, tokenUri, Clock())
            })
        };
        var (_, body) = await SendAsync(tokenRequest, "sign in with the service account", profile, cancellationToken).ConfigureAwait(false);
        using var token = JsonDocument.Parse(body);
        var zone = Uri.EscapeDataString(profile.ZoneId ?? throw new SslenseException(ErrorCodes.DnsProviderDetailsInvalid,
            $"DNS provider '{profile.Name}' has no Google Cloud DNS managed zone name."));
        var request = new HttpRequestMessage(method, $"{Api}/projects/{Uri.EscapeDataString(project)}/managedZones/{zone}{path}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.RootElement.GetProperty("access_token").GetString());
        return (request, project);
    }

    /// <summary>The signed JWT a service account exchanges for an access token (RFC 7523).</summary>
    internal static string CreateAssertion(string email, string privateKeyPem, string audience, DateTimeOffset now)
    {
        static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var header = Encode(JsonSerializer.SerializeToUtf8Bytes(new { alg = "RS256", typ = "JWT" }));
        var claims = Encode(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iss = email,
            scope = Scope,
            aud = audience,
            iat = now.ToUnixTimeSeconds(),
            exp = now.AddHours(1).ToUnixTimeSeconds()
        }));
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var signature = rsa.SignData(Encoding.ASCII.GetBytes($"{header}.{claims}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{claims}.{Encode(signature)}";
    }
}

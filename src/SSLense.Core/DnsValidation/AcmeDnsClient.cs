using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SSLense.Core.Acme;

namespace SSLense.Core.DnsValidation;

/// <summary>An account on an acme-dns server, as registration returns it.</summary>
public sealed record AcmeDnsAccount(string Username, string Password, string Subdomain, string FullDomain);

/// <summary>The acme-dns API (docs/design/acme-dns.md, section 2).</summary>
internal interface IAcmeDnsClient
{
    /// <param name="allowFrom">Networks, such as 203.0.113.10/32, that may update the account; any when empty.</param>
    Task<AcmeDnsAccount> RegisterAsync(Uri server, IReadOnlyList<string> allowFrom, CancellationToken cancellationToken);

    /// <summary>Sets one of the account's two TXT values; the older of the two is replaced.</summary>
    Task UpdateAsync(Uri server, string username, string password, string subdomain, string value, CancellationToken cancellationToken);

    Task CheckHealthAsync(Uri server, CancellationToken cancellationToken);
}

internal sealed class AcmeDnsClient(HttpClient httpClient) : IAcmeDnsClient
{
    public const int ValueLength = 43;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public async Task<AcmeDnsAccount> RegisterAsync(Uri server, IReadOnlyList<string> allowFrom, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint(server, "register"));
        request.Headers.UserAgent.Add(AcmeHttp.UserAgent);
        request.Content = allowFrom.Count > 0 ? JsonContent.Create(new { allowfrom = allowFrom }) : new StringContent(string.Empty);
        var body = await SendAsync(server, request, "register an account", cancellationToken).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var account = new AcmeDnsAccount(
                Text(root, "username"),
                Text(root, "password"),
                Text(root, "subdomain"),
                DnsNames.Normalize(Text(root, "fulldomain")));
            if (Uri.CheckHostName(account.FullDomain) != UriHostNameType.Dns)
            {
                throw new FormatException();
            }

            return account;
        }
        catch (Exception exception) when (exception is JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
        {
            throw new InvalidOperationException($"The acme-dns server at {server} did not return an account. Check that it is an acme-dns server.", exception);
        }
    }

    public async Task UpdateAsync(Uri server, string username, string password, string subdomain, string value, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint(server, "update"));
        request.Headers.UserAgent.Add(AcmeHttp.UserAgent);
        request.Headers.Add("X-Api-User", username);
        request.Headers.Add("X-Api-Key", password);
        request.Content = JsonContent.Create(new { subdomain, txt = value });
        await SendAsync(server, request, "update the validation record", cancellationToken).ConfigureAwait(false);
    }

    public async Task CheckHealthAsync(Uri server, CancellationToken cancellationToken)
    {
        using var request = AcmeHttp.Get(Endpoint(server, "health"));
        await SendAsync(server, request, "answer its health check", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>The server's address may have a path, such as a reverse proxy's; endpoints go below it.</summary>
    internal static Uri Endpoint(Uri server, string name) =>
        new(new Uri(server.AbsoluteUri.EndsWith('/') ? server.AbsoluteUri : server.AbsoluteUri + "/"), name);

    private async Task<string> SendAsync(Uri server, HttpRequestMessage request, string purpose, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(request, timeout.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException($"The acme-dns server at {server} could not be reached to {purpose}: {exception.Message}", exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException($"The acme-dns server at {server} did not {purpose} within {Timeout.TotalSeconds:0} seconds.", exception);
        }

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                return body;
            }

            throw new InvalidOperationException(response.StatusCode switch
            {
                HttpStatusCode.Unauthorized =>
                    $"The acme-dns server at {server} refused the account's username or password. Remove the provider and register or import the account again.",
                HttpStatusCode.Forbidden =>
                    $"The acme-dns server at {server} refused this server's address. The account only accepts updates from its allow-from networks.",
                _ => $"The acme-dns server at {server} could not {purpose} (HTTP {(int)response.StatusCode}){Detail(body)}"
            });
        }
    }

    /// <summary>acme-dns explains a refusal in a short JSON error, such as {"error": "bad_txt"}.</summary>
    private static string Detail(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            return document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String
                ? $": {error.GetString()}."
                : ".";
        }
        catch (JsonException)
        {
            return ".";
        }
    }

    private static string Text(JsonElement root, string property) =>
        root.GetProperty(property).GetString() is { Length: > 0 } value ? value : throw new FormatException();
}

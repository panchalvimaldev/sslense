using SSLense.Core.Errors;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SSLense.Core.Deployment;

/// <summary>An Azure App Service app, as subscription/resource group/app (docs/design/app-service.md).</summary>
internal sealed partial record AppServiceTarget(string Subscription, string ResourceGroup, string App)
{
    public string SiteUri => $"https://management.azure.com/subscriptions/{Subscription}/resourceGroups/{ResourceGroup}/providers/Microsoft.Web/sites/{App}";

    public string CertificateUri(string name) =>
        $"https://management.azure.com/subscriptions/{Subscription}/resourceGroups/{ResourceGroup}/providers/Microsoft.Web/certificates/{name}";

    public override string ToString() => $"{Subscription}/{ResourceGroup}/{App}";

    public static AppServiceTarget Parse(string value)
    {
        var parts = value.Trim().Trim('/').Split('/');
        if (parts.Length != 3 || !Guid.TryParse(parts[0], out var subscription) || !ResourceGroupName().IsMatch(parts[1]) || !AppName().IsMatch(parts[2]))
        {
            throw new ArgumentException(ErrorCodes.DeploymentStepInvalid.Format(
                $"'{value}' is not <subscription ID>/<resource group>/<app>, such as 00000000-0000-0000-0000-000000000000/web-rg/contoso-shop."));
        }

        return new AppServiceTarget(subscription.ToString(), parts[1], parts[2]);
    }

    [GeneratedRegex(@"^[\w\-.()]{1,90}$")]
    private static partial Regex ResourceGroupName();

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9-]{0,58}$")]
    private static partial Regex AppName();
}

/// <summary>Uploads a certificate to App Service and binds it to the app's host names it covers, with no SDK.</summary>
internal interface IAppServiceClient
{
    /// <param name="names">The certificate's names; each custom host name of the app they cover is bound with SNI.</param>
    /// <returns>The host names now bound to the certificate.</returns>
    Task<IReadOnlyList<string>> DeployAsync(
        AppServiceTarget target, string credentials, string thumbprint, IReadOnlyList<string> names, byte[] pfx, string password, CancellationToken cancellationToken);
}

internal sealed class AppServiceClient : IAppServiceClient, IDisposable
{
    private const string ApiVersion = "2023-12-01";
    private readonly HttpClient _httpClient;

    public AppServiceClient()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(100) })
    {
    }

    internal AppServiceClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<IReadOnlyList<string>> DeployAsync(
        AppServiceTarget target, string credentials, string thumbprint, IReadOnlyList<string> names, byte[] pfx, string password, CancellationToken cancellationToken)
    {
        var token = await TokenAsync(credentials, cancellationToken).ConfigureAwait(false);

        using var site = await SendAsync(HttpMethod.Get, $"{target.SiteUri}?api-version={ApiVersion}", token, null, "read the app", target, cancellationToken).ConfigureAwait(false);
        var location = site.RootElement.GetProperty("location").GetString()!;
        var serverFarmId = site.RootElement.GetProperty("properties").GetProperty("serverFarmId").GetString();
        var hostNames = site.RootElement.GetProperty("properties").GetProperty("hostNames").EnumerateArray()
            .Select(value => value.GetString()!)
            .Where(host => !host.EndsWith(".azurewebsites.net", StringComparison.OrdinalIgnoreCase))
            .Where(host => names.Any(name => Covers(name, host)))
            .ToArray();
        if (hostNames.Length == 0)
        {
            throw new SslenseException(ErrorCodes.AppServiceFailed,
                $"App '{target.App}' has no custom domain the certificate covers ({string.Join(", ", names)}). Add the domain to the app first.");
        }

        // Named by thumbprint, so each renewal uploads a new certificate and an old one stays until nothing uses it.
        var certificateName = $"sslense-{thumbprint.ToLowerInvariant()}";
        using (await SendAsync(HttpMethod.Put, $"{target.CertificateUri(certificateName)}?api-version={ApiVersion}", token,
                   new { location, properties = new { pfxBlob = Convert.ToBase64String(pfx), password, serverFarmId } },
                   "upload the certificate", target, cancellationToken).ConfigureAwait(false))
        {
        }

        foreach (var host in hostNames)
        {
            using var bound = await SendAsync(HttpMethod.Put, $"{target.SiteUri}/hostNameBindings/{host}?api-version={ApiVersion}", token,
                    new { properties = new { siteName = target.App, sslState = "SniEnabled", thumbprint = thumbprint.ToUpperInvariant() } },
                    $"bind {host}", target, cancellationToken)
                .ConfigureAwait(false);
        }

        return hostNames;
    }

    /// <summary>A wildcard covers one label, as browsers check it.</summary>
    internal static bool Covers(string name, string host) =>
        name.StartsWith("*.", StringComparison.Ordinal)
            ? host.EndsWith(name[1..], StringComparison.OrdinalIgnoreCase) && !host[..^(name.Length - 1)].Contains('.', StringComparison.Ordinal)
            : string.Equals(name, host, StringComparison.OrdinalIgnoreCase);

    private async Task<string> TokenAsync(string credentials, CancellationToken cancellationToken)
    {
        var parts = credentials.Split(':', 3);
        if (parts.Length != 3 || parts.Any(part => part.Length == 0))
        {
            throw new SslenseException(ErrorCodes.StepPasswordMissing, "The step's app registration is not a tenant, client ID and client secret. Remove the step and add it again.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{Uri.EscapeDataString(parts[0])}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = parts[1],
                ["client_secret"] = parts[2],
                ["scope"] = "https://management.azure.com/.default"
            })
        };
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new SslenseException(ErrorCodes.AppServiceFailed,
                $"Microsoft Entra ID refused the app registration's sign-in (HTTP {(int)response.StatusCode}){await ErrorAsync(response, cancellationToken).ConfigureAwait(false)}. " +
                "Check the tenant, the client ID and that the client secret has not expired.");
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        return document.RootElement.GetProperty("access_token").GetString()
               ?? throw new SslenseException(ErrorCodes.AppServiceFailed, "Microsoft Entra ID returned no access token.");
    }

    private async Task<JsonDocument> SendAsync(
        HttpMethod method, string uri, string token, object? body, string action, AppServiceTarget target, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, uri) { Content = body is null ? null : JsonContent.Create(body) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new SslenseException(ErrorCodes.AppServiceFailed,
                $"Azure did not let SSLense {action} for App Service app '{target.App}' (HTTP {(int)response.StatusCode}){await ErrorAsync(response, cancellationToken).ConfigureAwait(false)}. " +
                "Check the subscription, resource group and app names, and that the app registration has the Website Contributor role on the app's resource group.");
        }

        var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        return JsonDocument.Parse(text.Length == 0 ? "{}" : text);
    }

    /// <summary>The service's error code; never the request, which holds the key and the secret.</summary>
    private static async Task<string> ErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            var root = document.RootElement;
            var code = root.TryGetProperty("error", out var error)
                ? error.ValueKind == JsonValueKind.Object && error.TryGetProperty("code", out var inner) ? inner.GetString() : error.GetString()
                : root.TryGetProperty("Code", out var upper) ? upper.GetString() : null;
            return string.IsNullOrEmpty(code) ? string.Empty : $": {code}";
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    public void Dispose() => _httpClient.Dispose();
}

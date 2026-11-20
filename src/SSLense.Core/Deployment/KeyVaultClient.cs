using SSLense.Core.Errors;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SSLense.Core.Deployment;

/// <summary>Imports certificates into Azure Key Vault over its REST API, with no SDK (docs/design/key-vault.md).</summary>
internal interface IKeyVaultClient
{
    /// <param name="target">"vault/certificate" as <see cref="KeyVaultTarget.Parse"/> reads it.</param>
    /// <param name="credentials">"tenant:client ID:client secret".</param>
    /// <returns>The new version's identifier.</returns>
    Task<string> ImportAsync(KeyVaultTarget target, string credentials, byte[] pfx, string password, CancellationToken cancellationToken);
}

/// <summary>A certificate in a vault: names Key Vault accepts, so a mistake shows when the step is added.</summary>
internal sealed partial record KeyVaultTarget(string Vault, string Certificate)
{
    public Uri ImportUri => new($"https://{Vault}.vault.azure.net/certificates/{Certificate}/import?api-version=7.4");

    public override string ToString() => $"{Vault}/{Certificate}";

    /// <summary>"vault/certificate", or the certificate's URL as the Azure portal shows it.</summary>
    public static KeyVaultTarget Parse(string value)
    {
        var text = value.Trim();
        if (Uri.TryCreate(text, UriKind.Absolute, out var uri) && uri.Host.EndsWith(".vault.azure.net", StringComparison.OrdinalIgnoreCase))
        {
            var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            text = segments.Length >= 2 && segments[0].Equals("certificates", StringComparison.OrdinalIgnoreCase)
                ? $"{uri.Host[..uri.Host.IndexOf('.', StringComparison.Ordinal)]}/{segments[1]}"
                : text;
        }

        var parts = text.Split('/');
        if (parts.Length != 2 || !VaultName().IsMatch(parts[0]) || !CertificateName().IsMatch(parts[1]))
        {
            throw new ArgumentException(ErrorCodes.DeploymentStepInvalid.Format(
                $"'{value}' is not <vault>/<certificate>. A vault name has 3 to 24 letters, digits and hyphens, starting with a letter; a certificate name has up to 127 letters, digits and hyphens."));
        }

        return new KeyVaultTarget(parts[0].ToLowerInvariant(), parts[1]);
    }

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$")]
    private static partial Regex VaultName();

    [GeneratedRegex("^[A-Za-z0-9-]{1,127}$")]
    private static partial Regex CertificateName();
}

internal sealed class KeyVaultClient : IKeyVaultClient, IDisposable
{
    private readonly HttpClient _httpClient;

    public KeyVaultClient()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(60) })
    {
    }

    internal KeyVaultClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<string> ImportAsync(KeyVaultTarget target, string credentials, byte[] pfx, string password, CancellationToken cancellationToken)
    {
        var parts = credentials.Split(':', 3);
        if (parts.Length != 3 || parts.Any(part => part.Length == 0))
        {
            throw new SslenseException(ErrorCodes.StepPasswordMissing, "The step's app registration is not a tenant, client ID and client secret. Remove the step and add it again.");
        }

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{Uri.EscapeDataString(parts[0])}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = parts[1],
                ["client_secret"] = parts[2],
                ["scope"] = "https://vault.azure.net/.default"
            })
        };
        string token;
        using (var tokenResponse = await _httpClient.SendAsync(tokenRequest, cancellationToken).ConfigureAwait(false))
        {
            if (!tokenResponse.IsSuccessStatusCode)
            {
                throw new SslenseException(ErrorCodes.KeyVaultFailed,
                    $"Microsoft Entra ID refused the app registration's sign-in (HTTP {(int)tokenResponse.StatusCode}){await ErrorAsync(tokenResponse, cancellationToken).ConfigureAwait(false)}. " +
                    "Check the tenant, the client ID and that the client secret has not expired.");
            }

            using var document = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            token = document.RootElement.GetProperty("access_token").GetString()
                    ?? throw new SslenseException(ErrorCodes.KeyVaultFailed, "Microsoft Entra ID returned no access token.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, target.ImportUri)
        {
            Content = JsonContent.Create(new
            {
                value = Convert.ToBase64String(pfx),
                pwd = password,
                policy = new { secret_props = new { contentType = "application/x-pkcs12" } }
            })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new SslenseException(ErrorCodes.KeyVaultFailed,
                $"Azure Key Vault did not import the certificate into '{target}' (HTTP {(int)response.StatusCode}){await ErrorAsync(response, cancellationToken).ConfigureAwait(false)}. " +
                "Check that the vault exists, that its firewall lets this server in, and that the app may import certificates " +
                "(the Key Vault Certificates Officer role, or the Import certificate permission in an access policy).");
        }

        using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        return result.RootElement.TryGetProperty("id", out var id) ? id.GetString() ?? target.ToString() : target.ToString();
    }

    /// <summary>A random password for the upload only: Key Vault keeps the key itself, not the PFX.</summary>
    internal static string NewUploadPassword() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));

    /// <summary>The service's error code, which says what is wrong; never the request, which holds the key and the secret.</summary>
    private static async Task<string> ErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            var root = document.RootElement;
            var code = root.TryGetProperty("error", out var error)
                ? error.ValueKind == JsonValueKind.Object && error.TryGetProperty("code", out var inner) ? inner.GetString() : error.GetString()
                : null;
            return string.IsNullOrEmpty(code) ? string.Empty : $": {code}";
        }
        catch (JsonException)
        {
            return string.Empty;
        }
    }

    public void Dispose() => _httpClient.Dispose();
}

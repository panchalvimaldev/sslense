using System.Net;
using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Errors;

namespace SSLense.Core.DnsValidation;

/// <summary>
/// What the built-in DNS providers share (docs/design/dns-providers.md): their secret, decrypted only for a request,
/// and refusals reported with the service's answer but never the secret. Each calls its service over HTTPS; none uses a
/// vendor SDK.
/// </summary>
internal abstract class HttpDnsProvider(HttpClient httpClient, ISecretProtector protector) : IDnsProvider
{
    /// <summary>Validation records live for minutes, so the lowest TTL the services accept is used.</summary>
    protected const int RecordTtlSeconds = 60;

    public abstract DnsProviderType Type { get; }

    /// <summary>The service's name, for messages.</summary>
    protected abstract string ServiceName { get; }

    /// <summary>What the credentials need, added to a refusal with HTTP 401 or 403.</summary>
    protected abstract string PermissionAdvice(DnsProviderProfile profile);

    protected HttpClient Http => httpClient;

    public abstract Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken);

    public abstract Task AddTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken);

    public abstract Task RemoveTxtRecordAsync(DnsProviderProfile profile, string name, string value, CancellationToken cancellationToken);

    /// <summary>The provider's secret, decrypted for this request only.</summary>
    protected string Secret(DnsProviderProfile profile)
    {
        byte[] plaintext;
        try
        {
            plaintext = protector.Unprotect(Convert.FromBase64String(profile.ProtectedToken));
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or System.ComponentModel.Win32Exception)
        {
            throw new SslenseException(ErrorCodes.DnsSecretUnreadable,
                $"The credentials for DNS provider '{profile.Name}' cannot be decrypted. Remove the provider and add it again on this server.",
                exception);
        }

        try
        {
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>Sends the request; a refusal becomes SSL3039 with the service's answer. Returns the body.</summary>
    protected async Task<(HttpStatusCode Status, string Body)> SendAsync(
        HttpRequestMessage request,
        string action,
        DnsProviderProfile profile,
        CancellationToken cancellationToken,
        params HttpStatusCode[] alsoAccepted)
    {
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (response.IsSuccessStatusCode || alsoAccepted.Contains(response.StatusCode))
        {
            return (response.StatusCode, body);
        }

        var advice = response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden ? $" {PermissionAdvice(profile)}" : string.Empty;
        throw new SslenseException(ErrorCodes.DnsProviderRequestFailed,
            $"{ServiceName} could not {action} for DNS provider '{profile.Name}' (HTTP {(int)response.StatusCode}). {Excerpt(body)}{advice}".TrimEnd());
    }

    /// <summary>The record's name relative to the zone, as most services take it: "_acme-challenge.www" in example.com.</summary>
    protected static string Relative(string name, string zone)
    {
        name = DnsNames.Normalize(name);
        zone = DnsNames.Normalize(zone);
        return name == zone ? "@" : name[..^(zone.Length + 1)];
    }

    /// <summary>TXT data as zone files and most APIs write it: in quotes.</summary>
    protected static string Quote(string value) => $"\"{value}\"";

    protected static string Unquote(string value) =>
        value.Length >= 2 && value[0] == '"' && value[^1] == '"' ? value[1..^1].Replace("\" \"", string.Empty, StringComparison.Ordinal) : value;

    /// <summary>The start of a service's answer, without line breaks, for a message.</summary>
    private static string Excerpt(string body)
    {
        var text = string.Join(' ', body.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)).Trim();
        return text.Length <= 300 ? text : text[..300] + "…";
    }
}

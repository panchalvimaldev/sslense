using SSLense.Core.Config;
using SSLense.Core.Errors;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SSLense.Core.Notifications;

/// <summary>
/// Sends email through Microsoft Graph for Microsoft 365 tenants that have no SMTP (docs/design/graph-email.md): an app
/// registration with the Mail.Send application permission signs in with its client secret and sends as the From mailbox.
/// </summary>
internal sealed class GraphEmailSender : IEmailSender, IDisposable
{
    private readonly HttpClient _httpClient;

    public GraphEmailSender()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
    }

    internal GraphEmailSender(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task SendAsync(EmailDelivery settings, NotificationMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (string.IsNullOrEmpty(settings.Username) || string.IsNullOrEmpty(settings.Password))
        {
            throw new SslenseException(ErrorCodes.EmailFailed, "Email through Microsoft Graph needs the app registration's client ID and client secret.");
        }

        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"https://login.microsoftonline.com/{Uri.EscapeDataString(settings.Host)}/oauth2/v2.0/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = settings.Username,
                ["client_secret"] = settings.Password,
                ["scope"] = "https://graph.microsoft.com/.default"
            })
        };
        string token;
        using (var tokenResponse = await _httpClient.SendAsync(tokenRequest, cancellationToken).ConfigureAwait(false))
        {
            if (!tokenResponse.IsSuccessStatusCode)
            {
                throw new SslenseException(ErrorCodes.EmailFailed,
                    $"Microsoft Entra ID refused the app registration's sign-in (HTTP {(int)tokenResponse.StatusCode}){await ErrorAsync(tokenResponse, cancellationToken).ConfigureAwait(false)}. " +
                    "Check the tenant, the client ID and that the client secret has not expired.");
            }

            using var document = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
            token = document.RootElement.GetProperty("access_token").GetString()
                    ?? throw new SslenseException(ErrorCodes.EmailFailed, "Microsoft Entra ID returned no access token.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://graph.microsoft.com/v1.0/users/{Uri.EscapeDataString(settings.From)}/sendMail")
        {
            Content = JsonContent.Create(CreateMessage(settings, message))
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Accepted && !response.IsSuccessStatusCode)
        {
            throw new SslenseException(ErrorCodes.EmailFailed,
                $"Microsoft Graph did not send the email (HTTP {(int)response.StatusCode}){await ErrorAsync(response, cancellationToken).ConfigureAwait(false)}. " +
                $"Check that the app has the Mail.Send application permission with admin consent, and may send as {settings.From}.");
        }
    }

    internal static object CreateMessage(EmailDelivery settings, NotificationMessage message) => new
    {
        message = new
        {
            subject = message.Subject,
            body = new { contentType = "Text", content = message.Body },
            toRecipients = settings.To.Select(address => new { emailAddress = new { address } }).ToArray(),
            importance = message.EffectiveSeverity == NotificationSeverity.Error ? "high" : "normal"
        },
        saveToSentItems = false
    };

    /// <summary>Graph's and Entra ID's error code, which says what is wrong; never the request, which holds the secret.</summary>
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

/// <summary>Sends through Microsoft Graph or SMTP, whichever the email settings choose.</summary>
internal sealed class RoutingEmailSender(MailKitEmailSender smtp, GraphEmailSender graph) : IEmailSender
{
    public Task SendAsync(EmailDelivery settings, NotificationMessage message, CancellationToken cancellationToken) =>
        settings.Authentication == SmtpAuthentication.MicrosoftGraph
            ? graph.SendAsync(settings, message, cancellationToken)
            : smtp.SendAsync(settings, message, cancellationToken);
}

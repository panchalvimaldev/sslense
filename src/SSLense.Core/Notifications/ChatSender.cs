using SSLense.Core.Config;
using SSLense.Core.Errors;
using System.Net.Http.Json;
using System.Text;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Web;

namespace SSLense.Core.Notifications;

public interface IChatSender
{
    Task SendAsync(ChatFormat format, Uri url, NotificationMessage message, CancellationToken cancellationToken);

    /// <summary>A generic webhook whose payload is signed with the shared secret (docs/design/signed-webhooks.md).</summary>
    Task SendSignedAsync(Uri url, NotificationMessage message, string secret, CancellationToken cancellationToken) =>
        throw new NotSupportedException("This sender cannot sign payloads.");
}

/// <summary>Posts to Teams, Slack, Discord, Telegram, ntfy, or a generic webhook in each one's native format.</summary>
internal sealed class ChatSender : IChatSender, IDisposable
{
    // Discord rejects content over 2,000 characters and Telegram over 4,096; notifications are far shorter.
    private const int MaximumTextLength = 1900;

    private readonly HttpClient _httpClient;

    public ChatSender()
        : this(new HttpClient { Timeout = TimeSpan.FromSeconds(30) })
    {
    }

    internal ChatSender(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public Task SendAsync(ChatFormat format, Uri url, NotificationMessage message, CancellationToken cancellationToken) =>
        SendAsync(CreateRequest(format, url, message), format, url, cancellationToken);

    public Task SendSignedAsync(Uri url, NotificationMessage message, string secret, CancellationToken cancellationToken) =>
        SendAsync(CreateRequest(ChatFormat.Generic, url, message, secret), ChatFormat.Generic, url, cancellationToken);

    private async Task SendAsync(HttpRequestMessage created, ChatFormat format, Uri url, CancellationToken cancellationToken)
    {
        using var request = created;
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // The URL is never included: chat webhook URLs embed their credential.
            throw new SslenseException(ErrorCodes.ChatRejected, 
                $"The {format} notification was rejected with HTTP {(int)response.StatusCode} by {url.Host}. " +
                "Check that the webhook URL is complete and still active.");
        }
    }

    internal static HttpRequestMessage CreateRequest(ChatFormat format, Uri url, NotificationMessage message, string? signingSecret = null)
    {
        var text = Truncate(message.Body);
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        switch (format)
        {
            case ChatFormat.Teams:
                // An Adaptive Card message works with Teams Workflows and the older incoming-webhook connectors.
                request.Content = JsonContent.Create(new
                {
                    type = "message",
                    attachments = new[]
                    {
                        new
                        {
                            contentType = "application/vnd.microsoft.card.adaptive",
                            content = new Dictionary<string, object>
                            {
                                ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
                                ["type"] = "AdaptiveCard",
                                ["version"] = "1.4",
                                ["body"] = new object[]
                                {
                                    new { type = "TextBlock", text = message.Subject, weight = "Bolder", size = "Medium", wrap = true },
                                    new { type = "TextBlock", text, wrap = true }
                                }
                            }
                        }
                    }
                });
                break;
            case ChatFormat.Slack:
                request.Content = JsonContent.Create(new { text = $"*{message.Subject}*\n{text}" });
                break;
            case ChatFormat.Discord:
                request.Content = JsonContent.Create(new { content = $"**{message.Subject}**\n{text}" });
                break;
            case ChatFormat.Telegram:
                // chat_id is read from the configured URL and sent in the body, which the Bot API always accepts.
                var query = HttpUtility.ParseQueryString(url.Query);
                request.RequestUri = new UriBuilder(url) { Query = string.Empty }.Uri;
                request.Content = JsonContent.Create(new { chat_id = query["chat_id"], text = $"{message.Subject}\n\n{text}" });
                break;
            case ChatFormat.Ntfy:
                request.Content = new StringContent(text, Encoding.UTF8, "text/plain");
                request.Headers.Add("Title", ToHeaderValue(message.Subject));
                request.Headers.Add("Priority", message.EffectiveSeverity switch
                {
                    NotificationSeverity.Error => "high",
                    NotificationSeverity.Warning => "default",
                    _ => "low"
                });
                request.Headers.Add("Tags", message.EffectiveSeverity switch
                {
                    NotificationSeverity.Error => "rotating_light",
                    NotificationSeverity.Warning => "warning",
                    _ => "white_check_mark"
                });
                break;
            default:
                // Serialized once, so the signature covers exactly the bytes sent.
                var payload = JsonSerializer.Serialize(new
                {
                    kind = message.Kind.ToString(),
                    severity = message.EffectiveSeverity.ToString(),
                    subject = message.Subject,
                    body = message.Body,
                    occurredAtUtc = DateTimeOffset.UtcNow
                });
                request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                if (signingSecret is not null)
                {
                    var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
                    request.Headers.Add(TimestampHeader, timestamp);
                    request.Headers.Add(SignatureHeader, Sign(signingSecret, timestamp, payload));
                }

                break;
        }

        return request;
    }

    /// <summary>
    /// Validates a channel URL when it is saved, so mistakes show up during setup rather than on the first failure.
    /// </summary>
    internal static void Validate(ChatFormat format, Uri url)
    {
        // Plain HTTP is allowed only where self-hosting on an internal network is common.
        if (url.Scheme != Uri.UriSchemeHttps &&
            !(url.Scheme == Uri.UriSchemeHttp && format is ChatFormat.Generic or ChatFormat.Ntfy))
        {
            throw new ArgumentException(ErrorCodes.NotificationSettingsInvalid.Format($"The {format} URL must start with https://."));
        }

        if (format == ChatFormat.Telegram &&
            (!url.AbsolutePath.EndsWith("/sendMessage", StringComparison.Ordinal) ||
             string.IsNullOrWhiteSpace(HttpUtility.ParseQueryString(url.Query)["chat_id"])))
        {
            throw new ArgumentException(
                ErrorCodes.NotificationSettingsInvalid.Format("Use a Telegram URL of the form https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat id>."));
        }

        if (format == ChatFormat.Ntfy && url.AbsolutePath.Trim('/').Length == 0)
        {
            throw new ArgumentException(ErrorCodes.NotificationSettingsInvalid.Format("Include the topic in the ntfy URL, for example https://ntfy.sh/my-sslense-alerts."));
        }
    }

    internal const string TimestampHeader = "X-SSLense-Timestamp";
    internal const string SignatureHeader = "X-SSLense-Signature";

    /// <summary>HMAC-SHA256 over "&lt;timestamp&gt;.&lt;body&gt;" with the shared secret, as "sha256=&lt;hex&gt;".</summary>
    internal static string Sign(string secret, string timestamp, string payload) =>
        "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{timestamp}.{payload}")));

    /// <summary>A new shared secret: 32 random bytes, base64url, so it pastes cleanly into any receiver.</summary>
    internal static string NewSecret() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    public void Dispose() => _httpClient.Dispose();

    private static string Truncate(string text) =>
        text.Length <= MaximumTextLength ? text : string.Concat(text.AsSpan(0, MaximumTextLength), "…");

    // HTTP headers are ASCII; ntfy documents that non-ASCII titles must be encoded, so drop them instead.
    private static string ToHeaderValue(string value) =>
        new(value.Select(character => character is >= ' ' and <= '~' ? character : '?').ToArray());
}

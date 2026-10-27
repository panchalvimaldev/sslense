using System.Net.Http.Json;

namespace SSLense.Core.Notifications;

internal sealed class WebhookSender : IWebhookSender, IDisposable
{
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(30) };

    public async Task SendAsync(
        Uri url,
        NotificationMessage message,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
                url,
                new
                {
                    kind = message.Kind.ToString(),
                    subject = message.Subject,
                    body = message.Body,
                    occurredAtUtc = DateTimeOffset.UtcNow
                },
                cancellationToken)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"Webhook notification returned HTTP {(int)response.StatusCode}. Check the URL and receiving service.");
        }
    }

    public void Dispose() => _httpClient.Dispose();
}

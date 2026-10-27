using SSLense.Core.Acme;

namespace SSLense.Core.Validation;

internal sealed class HttpChallengeProbe : IChallengeProbe, IDisposable
{
    private readonly HttpClient _httpClient;

    public HttpChallengeProbe()
    {
        _httpClient = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
    }

    public async Task VerifyAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken)
    {
        var url = new UriBuilder(
            Uri.UriSchemeHttp,
            challenge.Host,
            80,
            $".well-known/acme-challenge/{challenge.Token}").Uri;

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException(
                $"HTTP-01 self-check could not connect to '{challenge.Host}' on port 80. " +
                "Confirm public DNS or tunnel routing, the HTTP Host header, and IIS availability.",
                exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"HTTP-01 self-check for '{challenge.Host}' timed out after 15 seconds. " +
                "Confirm the public route reaches this IIS server on port 80.",
                exception);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"HTTP-01 self-check for '{challenge.Host}' returned {(int)response.StatusCode}. " +
                    "Confirm public DNS or tunnel routing targets this server, preserves the HTTP Host header, " +
                    "and reaches port 80.");
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(body, challenge.KeyAuthorization, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"HTTP-01 self-check for '{challenge.Host}' returned unexpected content. " +
                    "Check IIS routing, authentication, proxy caching, and rewrite rules for .well-known/acme-challenge.");
            }
        }
    }

    public void Dispose() => _httpClient.Dispose();
}

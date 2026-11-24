using SSLense.Core.Acme;
using SSLense.Core.Errors;

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
            throw new SslenseException(ErrorCodes.ChallengeSelfCheckUnreachable, 
                $"HTTP-01 self-check could not connect to '{challenge.Host}' on port 80. " +
                "Confirm public DNS or tunnel routing, the HTTP Host header, and IIS availability.",
                exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                ErrorCodes.ChallengeSelfCheckTimeout.Format($"HTTP-01 self-check for '{challenge.Host}' timed out after 15 seconds. " +
                "Confirm the public route reaches this IIS server on port 80."),
                exception);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new SslenseException(ErrorCodes.ChallengeSelfCheckStatus,
                    $"HTTP-01 self-check for '{challenge.Host}' returned {(int)response.StatusCode}. {StatusHint((int)response.StatusCode)}");
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            if (!string.Equals(body, challenge.KeyAuthorization, StringComparison.Ordinal))
            {
                throw new SslenseException(ErrorCodes.ChallengeSelfCheckContent, 
                    $"HTTP-01 self-check for '{challenge.Host}' returned unexpected content. " +
                    "Check IIS routing, authentication, proxy caching, and rewrite rules for .well-known/acme-challenge.");
            }
        }
    }

    /// <summary>
    /// What the status says about the cause. The request did reach a web server, so for these the cause is usually the
    /// site, not the route (found in the combined test: a site pointed at a folder IIS could not read answered 401 and 500).
    /// </summary>
    internal static string StatusHint(int status) => status switch
    {
        401 or 403 =>
            "The site refused to serve the challenge file: check that IIS can read the site's folder (IUSR and IIS_IUSRS need " +
            "read access) and that anonymous access is allowed for /.well-known/acme-challenge.",
        404 =>
            "The challenge file was not found: check that this host name reaches this site, not another site or the Default " +
            "Web Site, and that the site's physical folder is the one SSLense wrote to.",
        >= 500 and < 600 =>
            "The web server failed to serve the challenge file: check the web.config files of the site and its folders, and " +
            "that the site's physical folder is its own (not IIS's configuration history folder, C:\\inetpub\\history).",
        _ =>
            "Confirm public DNS or tunnel routing targets this server, preserves the HTTP Host header, and reaches port 80."
    };

    public void Dispose() => _httpClient.Dispose();
}

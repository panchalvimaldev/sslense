using System.Net;
using SSLense.Core.Config;
using SSLense.Core.Errors;

namespace SSLense.Core.Iis;

/// <summary>
/// The HTTP-to-HTTPS redirect helper (docs/design/https-redirect.md): an IIS URL Rewrite rule that sends plain HTTP to
/// HTTPS but never the ACME challenge path, checked after it is added and removed again if validation would break.
/// </summary>
public interface IHttpsRedirectService
{
    Task<HttpsRedirectState> GetAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Adds the redirect to the certificate's IIS site; returns what was done and confirmed.</summary>
    Task<string> EnableAsync(string name, CancellationToken cancellationToken = default);

    Task<string> DisableAsync(string name, CancellationToken cancellationToken = default);
}

internal sealed class HttpsRedirectService : IHttpsRedirectService, IDisposable
{
    private readonly IIisService iisService;
    private readonly HttpClient httpClient;

    // Redirects are what it checks for, so they are never followed.
    public HttpsRedirectService(IIisService iisService)
        : this(iisService, new HttpClientHandler { AllowAutoRedirect = false })
    {
    }

    internal HttpsRedirectService(IIisService iisService, HttpMessageHandler handler)
    {
        this.iisService = iisService;
        httpClient = new HttpClient(handler);
    }

    public void Dispose() => httpClient.Dispose();

    public Task<HttpsRedirectState> GetAsync(string name, CancellationToken cancellationToken = default) =>
        iisService.GetHttpsRedirectAsync(ManagedCertificateNames.IisSiteOf(name), cancellationToken);

    public async Task<string> EnableAsync(string name, CancellationToken cancellationToken = default)
    {
        var siteName = ManagedCertificateNames.IisSiteOf(name);
        var state = await iisService.GetHttpsRedirectAsync(siteName, cancellationToken).ConfigureAwait(false);
        if (state == HttpsRedirectState.UrlRewriteMissing)
        {
            throw new SslenseException(ErrorCodes.UrlRewriteMissing, "The IIS URL Rewrite module is not installed, so SSLense cannot add the redirect.");
        }

        var site = (await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false)).FindSite(siteName)
            ?? throw new SslenseException(ErrorCodes.IisSiteNotFound, $"IIS site '{siteName}' was not found.");
        if (!site.Bindings.Any(binding => string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) && binding.CertificateThumbprint is not null))
        {
            throw new SslenseException(ErrorCodes.RedirectNeedsHttps, $"IIS site '{site.Name}' has no HTTPS binding with a certificate, so a redirect would send visitors nowhere.");
        }

        if (state == HttpsRedirectState.On)
        {
            return $"IIS site '{site.Name}' already redirects HTTP to HTTPS.";
        }

        await iisService.SetHttpsRedirectAsync(site.Name, true, cancellationToken).ConfigureAwait(false);

        // Host names this site answers on port 80, to confirm: the challenge path must not be redirected.
        var hosts = site.Bindings
            .Where(binding => string.Equals(binding.Protocol, "http", StringComparison.OrdinalIgnoreCase) && binding.Port == 80 && binding.HostName.Length > 0)
            .Select(binding => binding.HostName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var confirmed = new List<string>();
        foreach (var host in hosts)
        {
            var challenge = await StatusAsync(host, $"/.well-known/acme-challenge/sslense-redirect-check-{Guid.NewGuid():N}", cancellationToken).ConfigureAwait(false);
            if (challenge is { } status && IsRedirect(status))
            {
                await iisService.SetHttpsRedirectAsync(site.Name, false, CancellationToken.None).ConfigureAwait(false);
                throw new SslenseException(ErrorCodes.RedirectBlocksValidation,
                    $"With the redirect, http://{host}/.well-known/acme-challenge/ was redirected (HTTP {(int)status}), which would stop HTTP validation, so the rule was removed again.");
            }

            if (await StatusAsync(host, "/", cancellationToken).ConfigureAwait(false) is { } home && IsRedirect(home))
            {
                confirmed.Add(host);
            }
        }

        return confirmed.Count > 0
            ? $"IIS site '{site.Name}' now redirects HTTP to HTTPS, confirmed for {string.Join(", ", confirmed)}; validation requests are not redirected."
            : $"IIS site '{site.Name}' now redirects HTTP to HTTPS, except validation requests. This server could not confirm it through its host names; check from a browser.";
    }

    public async Task<string> DisableAsync(string name, CancellationToken cancellationToken = default)
    {
        var siteName = ManagedCertificateNames.IisSiteOf(name);
        if (await iisService.GetHttpsRedirectAsync(siteName, cancellationToken).ConfigureAwait(false) != HttpsRedirectState.On)
        {
            return $"IIS site '{siteName}' has no SSLense redirect.";
        }

        await iisService.SetHttpsRedirectAsync(siteName, false, cancellationToken).ConfigureAwait(false);
        return $"IIS site '{siteName}' no longer redirects HTTP to HTTPS through SSLense's rule.";
    }

    /// <summary>The status of a plain HTTP request to the host, not following redirects; null when it cannot be reached.</summary>
    private async Task<HttpStatusCode?> StatusAsync(string host, string path, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new UriBuilder(Uri.UriSchemeHttp, host, 80, path).Uri);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            return response.StatusCode;
        }
        catch (Exception exception) when (exception is HttpRequestException || exception is TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static bool IsRedirect(HttpStatusCode status) => (int)status is 301 or 302 or 303 or 307 or 308;
}

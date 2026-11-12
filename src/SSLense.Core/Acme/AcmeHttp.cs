using System.Net.Http.Headers;

namespace SSLense.Core.Acme;

/// <summary>
/// Requests SSLense sends to an ACME server itself, outside Certes. RFC 8555, section 6.1, requires every ACME request to
/// carry a User-Agent, and some CAs refuse one without it.
/// </summary>
internal static class AcmeHttp
{
    public static ProductInfoHeaderValue UserAgent { get; } =
        new("SSLense", typeof(AcmeHttp).Assembly.GetName().Version?.ToString(3) ?? "0.0.0");

    public static HttpRequestMessage Get(Uri uri)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.Add(UserAgent);
        return request;
    }
}

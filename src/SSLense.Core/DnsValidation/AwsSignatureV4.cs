using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SSLense.Core.DnsValidation;

/// <summary>AWS Signature Version 4, for Route 53 requests without the AWS SDK (docs/design/dns-providers.md).</summary>
internal static class AwsSignatureV4
{
    /// <summary>Adds the x-amz-date and Authorization headers to <paramref name="request"/>.</summary>
    public static void Sign(
        HttpRequestMessage request,
        string body,
        string accessKeyId,
        string secretAccessKey,
        string region,
        string service,
        DateTimeOffset now)
    {
        var uri = request.RequestUri ?? throw new ArgumentException("The request has no address.", nameof(request));
        var amzDate = now.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var date = amzDate[..8];
        request.Headers.Remove("x-amz-date");
        request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);

        var host = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
        var canonicalRequest = string.Join('\n',
            request.Method.Method,
            CanonicalPath(uri.AbsolutePath),
            CanonicalQuery(uri.Query),
            $"host:{host}\nx-amz-date:{amzDate}\n",
            "host;x-amz-date",
            Hex(SHA256.HashData(Encoding.UTF8.GetBytes(body))));
        var scope = $"{date}/{region}/{service}/aws4_request";
        var stringToSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{scope}\n{Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest)))}";

        var key = HMACSHA256.HashData(Encoding.UTF8.GetBytes("AWS4" + secretAccessKey), Encoding.UTF8.GetBytes(date));
        key = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(region));
        key = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(service));
        key = HMACSHA256.HashData(key, "aws4_request"u8.ToArray());
        var signature = Hex(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(stringToSign)));
        CryptographicOperations.ZeroMemory(key);

        request.Headers.TryAddWithoutValidation(
            "Authorization",
            $"AWS4-HMAC-SHA256 Credential={accessKeyId}/{scope}, SignedHeaders=host;x-amz-date, Signature={signature}");
    }

    private static string CanonicalPath(string path) =>
        path.Length == 0 ? "/" : string.Join('/', path.Split('/').Select(segment => Encode(Uri.UnescapeDataString(segment))));

    private static string CanonicalQuery(string query) =>
        string.Join('&', query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2))
            .Select(parts => (Name: Encode(Uri.UnescapeDataString(parts[0])), Value: Encode(Uri.UnescapeDataString(parts.Length > 1 ? parts[1] : string.Empty))))
            .OrderBy(parts => parts.Name, StringComparer.Ordinal)
            .ThenBy(parts => parts.Value, StringComparer.Ordinal)
            .Select(parts => $"{parts.Name}={parts.Value}"));

    /// <summary>RFC 3986 encoding, as AWS requires: everything but unreserved characters.</summary>
    private static string Encode(string value)
    {
        var builder = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(value))
        {
            var c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~')
            {
                builder.Append(c);
            }
            else
            {
                builder.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    private static string Hex(byte[] value) => Convert.ToHexStringLower(value);
}

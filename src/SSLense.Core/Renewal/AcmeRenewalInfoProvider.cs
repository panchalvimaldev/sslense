using System.Formats.Asn1;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.Renewal;

internal sealed class AcmeRenewalInfoProvider(HttpClient httpClient) : IRenewalInfoProvider
{
    public async Task<RenewalWindow?> GetWindowAsync(
        ManagedCertificate certificate,
        CancellationToken cancellationToken = default)
    {
        if (certificate.NotAfter <= DateTimeOffset.UtcNow || !OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            using var installed = FindCertificate(certificate.Thumbprint);
            if (installed is null)
            {
                return null;
            }

            var certificateId = CreateCertificateId(installed);
            using var directoryResponse = await httpClient
                .GetAsync(certificate.Environment.DirectoryUri(), cancellationToken)
                .ConfigureAwait(false);
            if (!directoryResponse.IsSuccessStatusCode)
            {
                return null;
            }

            await using var directoryStream = await directoryResponse.Content
                .ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            using var directory = await JsonDocument
                .ParseAsync(directoryStream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (!directory.RootElement.TryGetProperty("renewalInfo", out var renewalInfoProperty) ||
                renewalInfoProperty.GetString() is not { Length: > 0 } renewalInfoUrl)
            {
                return null;
            }

            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"{renewalInfoUrl.TrimEnd('/')}/{certificateId}");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            await using var responseStream = await response.Content
                .ReadAsStreamAsync(cancellationToken)
                .ConfigureAwait(false);
            using var document = await JsonDocument
                .ParseAsync(responseStream, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            var root = document.RootElement;
            if (!root.TryGetProperty("suggestedWindow", out var window) ||
                !window.TryGetProperty("start", out var startProperty) ||
                !window.TryGetProperty("end", out var endProperty) ||
                !startProperty.TryGetDateTimeOffset(out var start) ||
                !endProperty.TryGetDateTimeOffset(out var end) ||
                end <= start)
            {
                return null;
            }

            var explanationUrl = root.TryGetProperty("explanationURL", out var explanation)
                ? explanation.GetString()
                : null;
            return new RenewalWindow(start, end, explanationUrl);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (HttpRequestException)
        {
            return null;
        }
        catch (JsonException)
        {
            return null;
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    internal static string CreateCertificateId(X509Certificate2 certificate)
    {
        var authorityKeyIdentifier = certificate.Extensions["2.5.29.35"]
            ?? throw new CryptographicException("The certificate has no Authority Key Identifier extension.");
        var reader = new AsnReader(authorityKeyIdentifier.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        var keyIdentifier = sequence.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));

        var serial = certificate.GetSerialNumber();
        Array.Reverse(serial);
        if (serial.Length > 0 && (serial[0] & 0x80) != 0)
        {
            serial = [0, .. serial];
        }

        return $"{Base64Url(keyIdentifier)}.{Base64Url(serial)}";
    }

    private static X509Certificate2? FindCertificate(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
        var matches = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            string.Concat(thumbprint.Where(Uri.IsHexDigit)),
            validOnly: false);
        try
        {
            return matches.Count == 0 ? null : new X509Certificate2(matches[0]);
        }
        finally
        {
            foreach (var match in matches.OfType<X509Certificate2>())
            {
                match.Dispose();
            }
        }
    }

    private static string Base64Url(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

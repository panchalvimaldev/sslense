using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSLense.Core.Acme;

namespace SSLense.Core.DnsValidation;

internal sealed class CloudflareDnsProvider(HttpClient httpClient, ISecretProtector protector) : IDnsProvider
{
    private const string ApiBase = "https://api.cloudflare.com/client/v4";
    private const int RecordAlreadyExists = 81058;

    // Cloudflare's lowest TTL below its Enterprise plan.
    private const int RecordTtlSeconds = 60;

    public DnsProviderType Type => DnsProviderType.Cloudflare;

    public async Task VerifyAccessAsync(DnsProviderProfile profile, CancellationToken cancellationToken) =>
        _ = await FindRecordsAsync(profile, $"_acme-challenge.{DnsNames.Normalize(profile.ZoneName)}", cancellationToken)
            .ConfigureAwait(false);

    public async Task AddTxtRecordAsync(
        DnsProviderProfile profile,
        string name,
        string value,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(HttpMethod.Post, $"{ZoneUrl(profile)}/dns_records", profile);
        request.Content = JsonContent.Create(new { type = "TXT", name, content = value, ttl = RecordTtlSeconds });
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var result = await ReadAsync(response, cancellationToken).ConfigureAwait(false);

        // An earlier attempt published this exact value; the value is derived from the same token and account key.
        if (!result.Errors.Contains(RecordAlreadyExists))
        {
            EnsureSuccess(response, result, $"add the TXT record '{name}'", profile);
        }
    }

    public async Task RemoveTxtRecordAsync(
        DnsProviderProfile profile,
        string name,
        string value,
        CancellationToken cancellationToken)
    {
        foreach (var record in await FindRecordsAsync(profile, name, cancellationToken).ConfigureAwait(false))
        {
            if (!string.Equals(record.Content, value, StringComparison.Ordinal))
            {
                continue;
            }

            using var request = CreateRequest(HttpMethod.Delete, $"{ZoneUrl(profile)}/dns_records/{Uri.EscapeDataString(record.Id)}", profile);
            using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            EnsureSuccess(
                response,
                await ReadAsync(response, cancellationToken).ConfigureAwait(false),
                $"remove the TXT record '{name}'",
                profile);
        }
    }

    private async Task<IReadOnlyList<ExistingRecord>> FindRecordsAsync(
        DnsProviderProfile profile,
        string name,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(
            HttpMethod.Get,
            $"{ZoneUrl(profile)}/dns_records?type=TXT&per_page=100&name={Uri.EscapeDataString(name)}",
            profile);
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var result = await ReadAsync(response, cancellationToken).ConfigureAwait(false);
        EnsureSuccess(response, result, $"read the TXT records at '{name}'", profile);
        return result.Records;
    }

    private static string ZoneUrl(DnsProviderProfile profile) =>
        $"{ApiBase}/zones/{Uri.EscapeDataString(profile.ZoneId ?? throw new InvalidOperationException(
            $"DNS provider '{profile.Name}' has no Cloudflare zone ID."))}";

    private HttpRequestMessage CreateRequest(HttpMethod method, string url, DnsProviderProfile profile)
    {
        var request = new HttpRequestMessage(method, url);

        // Per request, because this HttpClient is shared with everything else in Core.
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", GetToken(profile));
        return request;
    }

    private string GetToken(DnsProviderProfile profile)
    {
        byte[] plaintext;
        try
        {
            plaintext = protector.Unprotect(Convert.FromBase64String(profile.ProtectedToken));
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or System.ComponentModel.Win32Exception)
        {
            throw new InvalidOperationException(
                $"The token for DNS provider '{profile.Name}' cannot be decrypted. Remove the provider and add it again on this server.",
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

    private static async Task<ApiResult> ReadAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            var errors = root.TryGetProperty("errors", out var errorList) && errorList.ValueKind == JsonValueKind.Array
                ? errorList.EnumerateArray().ToArray()
                : [];
            var records = root.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Array
                ? result.EnumerateArray()
                    .Select(record => new ExistingRecord(
                        record.GetProperty("id").GetString() ?? string.Empty,
                        Unquote(record.GetProperty("content").GetString())))
                    .ToArray()
                : [];
            return new ApiResult(
                root.TryGetProperty("success", out var success) && success.ValueKind == JsonValueKind.True,
                errors.Select(error => error.TryGetProperty("code", out var code) && code.TryGetInt32(out var number) ? number : 0).ToHashSet(),
                string.Join(" ", errors.Select(error => error.TryGetProperty("message", out var message) ? message.GetString() : null).OfType<string>()),
                records);
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return new ApiResult(false, [], string.Empty, []);
        }
    }

    /// <summary>Cloudflare may return TXT content wrapped in quotes.</summary>
    private static string Unquote(string? content) =>
        content is { Length: >= 2 } && content[0] == '"' && content[^1] == '"' ? content[1..^1] : content ?? string.Empty;

    private static void EnsureSuccess(HttpResponseMessage response, ApiResult result, string action, DnsProviderProfile profile)
    {
        if (response.IsSuccessStatusCode && result.Success)
        {
            return;
        }

        var advice = response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
            ? $" Check that the token is valid and has Zone > DNS > Edit permission on {profile.ZoneName}."
            : string.Empty;
        var detail = result.Message.Length > 0 ? $" {result.Message}" : string.Empty;
        throw new InvalidOperationException(
            $"Cloudflare could not {action} (HTTP {(int)response.StatusCode}).{detail}{advice}");
    }

    private sealed record ExistingRecord(string Id, string Content);

    private sealed record ApiResult(bool Success, HashSet<int> Errors, string Message, IReadOnlyList<ExistingRecord> Records);
}

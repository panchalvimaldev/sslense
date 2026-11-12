using System.Text.Json;

namespace SSLense.Core.Acme;

/// <summary>What a CA's ACME directory says about it (RFC 8555, section 7.1.1, and RFC 9773 for ARI).</summary>
/// <param name="ExternalAccountRequired">The CA refuses new accounts without External Account Binding.</param>
/// <param name="CaaIdentities">The domains the CA recognises in CAA records; empty when it publishes none.</param>
/// <param name="SupportsRenewalInfo">The CA suggests renewal times through ARI.</param>
/// <param name="Profiles">The ACME profiles the CA offers, by name, with its description of each.</param>
public sealed record AcmeDirectoryInfo(
    bool ExternalAccountRequired,
    IReadOnlyList<string> CaaIdentities,
    bool SupportsRenewalInfo,
    string? TermsOfService,
    IReadOnlyDictionary<string, string>? Profiles = null);

internal interface IAcmeDirectoryReader
{
    /// <summary>Reads the directory, and throws a message an administrator can act on when it is not an ACME directory.</summary>
    Task<AcmeDirectoryInfo> ReadAsync(Uri directoryUri, CancellationToken cancellationToken);
}

internal sealed class AcmeDirectoryReader(HttpClient httpClient) : IAcmeDirectoryReader
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    public async Task<AcmeDirectoryInfo> ReadAsync(Uri directoryUri, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        string json;
        try
        {
            using var request = AcmeHttp.Get(directoryUri);
            using var response = await httpClient.SendAsync(request, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"The ACME directory at {directoryUri} answered HTTP {(int)response.StatusCode}. Check the address.");
            }

            json = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new InvalidOperationException($"The ACME directory at {directoryUri} could not be reached: {exception.Message}", exception);
        }
        catch (TaskCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException($"The ACME directory at {directoryUri} did not answer within {Timeout.TotalSeconds:0} seconds.", exception);
        }

        return Parse(json, directoryUri);
    }

    internal static AcmeDirectoryInfo Parse(string json, Uri directoryUri)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("newAccount", out _) ||
                !root.TryGetProperty("newOrder", out _) ||
                !root.TryGetProperty("newNonce", out _))
            {
                throw new InvalidOperationException($"{directoryUri} is not an ACME directory: it has no newAccount, newOrder, and newNonce.");
            }

            var required = false;
            string[] caa = [];
            string? terms = null;
            var profiles = new Dictionary<string, string>(StringComparer.Ordinal);
            if (root.TryGetProperty("meta", out var meta) && meta.ValueKind == JsonValueKind.Object)
            {
                required = meta.TryGetProperty("externalAccountRequired", out var value) && value.ValueKind == JsonValueKind.True;
                if (meta.TryGetProperty("caaIdentities", out var identities) && identities.ValueKind == JsonValueKind.Array)
                {
                    caa = identities.EnumerateArray()
                        .Where(identity => identity.ValueKind == JsonValueKind.String)
                        .Select(identity => identity.GetString()!.Trim().ToLowerInvariant())
                        .Where(identity => identity.Length > 0)
                        .Distinct()
                        .ToArray();
                }

                terms = meta.TryGetProperty("termsOfService", out var tos) && tos.ValueKind == JsonValueKind.String ? tos.GetString() : null;
                if (meta.TryGetProperty("profiles", out var offered) && offered.ValueKind == JsonValueKind.Object)
                {
                    foreach (var profile in offered.EnumerateObject())
                    {
                        profiles[profile.Name] = profile.Value.ValueKind == JsonValueKind.String ? profile.Value.GetString() ?? string.Empty : string.Empty;
                    }
                }
            }

            return new AcmeDirectoryInfo(required, caa, root.TryGetProperty("renewalInfo", out _), terms, profiles);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"{directoryUri} did not return an ACME directory: the answer is not JSON.", exception);
        }
    }
}

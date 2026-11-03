using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.DnsValidation;

/// <param name="Token">The API token in plain text; encrypted before it is saved.</param>
public sealed record DnsProviderRequest(string Name, DnsProviderType Provider, string ZoneName, string? ZoneId, string Token);

/// <summary>A DNS provider as shown to the administrator, without its token.</summary>
public sealed record DnsProviderOverview(string Name, DnsProviderType Provider, string ZoneName, string? ZoneId);

public interface IDnsProviderService
{
    Task<IReadOnlyList<DnsProviderOverview>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>Checks the token can read the zone, then saves the provider with its token encrypted.</summary>
    Task AddAsync(DnsProviderRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Proves the token can change the zone by adding and removing a temporary TXT record at
    /// <c>_sslense-test.&lt;zone&gt;</c>. Returns a description of what was done.
    /// </summary>
    Task<string> TestAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces a provider's token, for one that expired or was rotated. The new token is checked first, so a rejected
    /// one leaves the old one in place. Certificates keep renewing through the provider.
    /// </summary>
    Task UpdateTokenAsync(string name, string token, CancellationToken cancellationToken = default);

    /// <summary>Removes a provider, unless a certificate renews through it.</summary>
    Task RemoveAsync(string name, CancellationToken cancellationToken = default);
}

internal sealed class DnsProviderService(
    IConfigStore configStore,
    IManagedCertificateStore managedStore,
    ISecretProtector protector,
    IEnumerable<IDnsProvider> providers,
    IDnsLookup lookup) : IDnsProviderService
{
    public async Task<IReadOnlyList<DnsProviderOverview>> ListAsync(CancellationToken cancellationToken = default) =>
        (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).DnsProviders
            .Select(profile => new DnsProviderOverview(profile.Name, profile.Provider, profile.ZoneName, profile.ZoneId))
            .ToArray();

    public async Task AddAsync(DnsProviderRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var name = request.Name?.Trim() ?? string.Empty;
        if (name.Length == 0)
        {
            throw new ArgumentException("Enter a name for this DNS provider.");
        }

        var zone = DnsNames.Normalize(request.ZoneName ?? string.Empty);
        if (!zone.Contains('.') || zone.Contains('*') || Uri.CheckHostName(zone) != UriHostNameType.Dns)
        {
            throw new ArgumentException($"'{request.ZoneName}' is not a valid DNS zone name, such as example.com.");
        }

        var zoneId = request.ZoneId?.Trim();
        if (request.Provider == DnsProviderType.Cloudflare &&
            (zoneId is not { Length: 32 } || !zoneId.All(Uri.IsHexDigit)))
        {
            throw new ArgumentException("Enter the Cloudflare zone ID: 32 hexadecimal characters, shown on the domain's Overview page.");
        }

        var token = request.Token?.Trim() ?? string.Empty;
        if (token.Length == 0)
        {
            throw new ArgumentException("Enter the API token.");
        }

        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (config.DnsProviders.Any(profile => string.Equals(profile.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A DNS provider named '{name}' already exists. Remove it first, or choose another name.");
        }

        if (config.DnsProviders.Any(profile => DnsNames.Normalize(profile.ZoneName) == zone))
        {
            throw new InvalidOperationException($"A DNS provider for the zone '{zone}' already exists. Remove it first to replace it.");
        }

        var profile = new DnsProviderProfile(name, request.Provider, zone, zoneId, Protect(token));
        await GetProvider(profile).VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);

        // Read again, so a change made while the provider was contacted is not overwritten.
        config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        await configStore.SaveAsync(config with { DnsProviders = [.. config.DnsProviders, profile] }, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<string> TestAsync(string name, CancellationToken cancellationToken = default)
    {
        var profile = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        var provider = GetProvider(profile);
        await provider.VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);

        var recordName = $"_sslense-test.{DnsNames.Normalize(profile.ZoneName)}";
        var value = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        await provider.AddTxtRecordAsync(profile, recordName, value, cancellationToken).ConfigureAwait(false);
        await provider.RemoveTxtRecordAsync(profile, recordName, value, CancellationToken.None).ConfigureAwait(false);
        return $"The token can change the zone {profile.ZoneName}: a temporary TXT record at '{recordName}' was added and removed.";
    }

    public async Task UpdateTokenAsync(string name, string token, CancellationToken cancellationToken = default)
    {
        var trimmed = token?.Trim() ?? string.Empty;
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("Enter the API token.");
        }

        var profile = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        var updated = profile with { ProtectedToken = Protect(trimmed) };
        await GetProvider(updated).VerifyAccessAsync(updated, cancellationToken).ConfigureAwait(false);

        // Read again, so a change made while the provider was contacted is not overwritten.
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!config.DnsProviders.Any(value => value.Name == profile.Name))
        {
            throw new InvalidOperationException($"DNS provider '{profile.Name}' was removed while its token was being checked.");
        }

        await configStore.SaveAsync(
                config with { DnsProviders = config.DnsProviders.Select(value => value.Name == profile.Name ? updated : value).ToArray() },
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RemoveAsync(string name, CancellationToken cancellationToken = default)
    {
        var profile = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
        var users = new List<string>();
        foreach (var certificate in await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false))
        {
            if (certificate.ValidationMethod != ValidationMethod.Dns01Provider)
            {
                continue;
            }

            foreach (var certificateName in certificate.CertificateNames ?? certificate.Hosts)
            {
                var target = await lookup.ResolveCnameAsync(DnsNames.ChallengeRecord(certificateName), cancellationToken).ConfigureAwait(false);
                if (DnsNames.SelectProfile(config.DnsProviders, target)?.Name == profile.Name)
                {
                    users.Add(certificate.SiteName);
                    break;
                }
            }
        }

        if (users.Count > 0)
        {
            throw new InvalidOperationException(
                $"DNS provider '{profile.Name}' cannot be removed, because these certificates renew through it: {string.Join(", ", users)}. " +
                "To change its token, replace the token instead.");
        }

        await configStore.SaveAsync(
                config with { DnsProviders = config.DnsProviders.Where(value => value.Name != profile.Name).ToArray() },
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<DnsProviderProfile> FindAsync(string name, CancellationToken cancellationToken)
    {
        var profiles = (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).DnsProviders;
        return profiles.FirstOrDefault(profile => string.Equals(profile.Name, name?.Trim(), StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                $"DNS provider '{name}' was not found. " +
                (profiles.Count == 0
                    ? "Add one with 'SSLense.Cli dns add'."
                    : $"Available: {string.Join(", ", profiles.Select(profile => profile.Name))}."));
    }

    private IDnsProvider GetProvider(DnsProviderProfile profile) =>
        providers.FirstOrDefault(provider => provider.Type == profile.Provider)
        ?? throw new InvalidOperationException($"DNS provider type '{profile.Provider}' is not supported by this SSLense version.");

    private string Protect(string token)
    {
        var plaintext = Encoding.UTF8.GetBytes(token);
        try
        {
            return Convert.ToBase64String(protector.Protect(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

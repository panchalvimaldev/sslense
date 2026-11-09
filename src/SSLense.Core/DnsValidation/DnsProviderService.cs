using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.Config;

namespace SSLense.Core.DnsValidation;

/// <param name="Token">
/// The API token in plain text; encrypted before it is saved. For a script, its optional secret, which may be empty.
/// </param>
/// <param name="ScriptPath">For a script, the administrator's .ps1 file, which SSLense copies.</param>
/// <param name="ScriptTimeoutSeconds">For a script, how long one call may run; the default when null.</param>
public sealed record DnsProviderRequest(
    string Name,
    DnsProviderType Provider,
    string ZoneName,
    string? ZoneId,
    string Token,
    string? ScriptPath = null,
    int? ScriptTimeoutSeconds = null);

/// <summary>A DNS provider as shown to the administrator, without its token.</summary>
/// <param name="ScriptSha256">For a script, the SHA-256 of the copy SSLense runs, to compare with the original.</param>
public sealed record DnsProviderOverview(string Name, DnsProviderType Provider, string ZoneName, string? ZoneId, string? ScriptSha256 = null);

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

    /// <summary>
    /// Takes a new copy of a script provider's script, after the administrator changed the original. The new copy is
    /// checked with <c>Check</c> first, so a broken script leaves the old copy in use. Returns the new copy's SHA-256.
    /// </summary>
    Task<string> UpdateScriptAsync(string name, string scriptPath, CancellationToken cancellationToken = default);

    /// <summary>Removes a provider, unless a certificate renews through it.</summary>
    Task RemoveAsync(string name, CancellationToken cancellationToken = default);
}

internal sealed class DnsProviderService(
    IConfigStore configStore,
    IManagedCertificateStore managedStore,
    ISecretProtector protector,
    IEnumerable<IDnsProvider> providers,
    IDnsLookup lookup,
    IDnsScriptStore? scripts = null,
    DnsPropagationChecker? propagation = null) : IDnsProviderService
{
    private const int MinScriptTimeoutSeconds = 10;
    private const int MaxScriptTimeoutSeconds = 3600;

    private readonly IDnsScriptStore _scripts = scripts ?? new DnsScriptStore();
    private readonly DnsPropagationChecker _propagation = propagation ?? new DnsPropagationChecker(lookup);

    public async Task<IReadOnlyList<DnsProviderOverview>> ListAsync(CancellationToken cancellationToken = default) =>
        (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).DnsProviders
            .Select(profile => new DnsProviderOverview(profile.Name, profile.Provider, profile.ZoneName, profile.ZoneId, profile.ScriptSha256))
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
        var isScript = request.Provider == DnsProviderType.Script;
        if (token.Length == 0 && !isScript)
        {
            throw new ArgumentException("Enter the API token.");
        }

        if (isScript)
        {
            DnsScriptStore.ValidateName(name);
            if (string.IsNullOrWhiteSpace(request.ScriptPath))
            {
                throw new ArgumentException("Enter the path of the PowerShell script (--script in the CLI).");
            }

            if (request.ScriptTimeoutSeconds is { } seconds and (< MinScriptTimeoutSeconds or > MaxScriptTimeoutSeconds))
            {
                throw new ArgumentException($"The script timeout must be between {MinScriptTimeoutSeconds} and {MaxScriptTimeoutSeconds} seconds.");
            }
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

        var profile = new DnsProviderProfile(name, request.Provider, zone, isScript ? null : zoneId, token.Length == 0 ? string.Empty : Protect(token));
        if (isScript)
        {
            var sha256 = await _scripts.SaveAsync(name, request.ScriptPath!, cancellationToken).ConfigureAwait(false);
            profile = profile with { ScriptSha256 = sha256, ScriptTimeoutSeconds = request.ScriptTimeoutSeconds };
            try
            {
                await GetProvider(profile).VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                _scripts.Delete(name, sha256);
                throw;
            }
        }
        else
        {
            await GetProvider(profile).VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);
        }

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
        if (profile.Provider != DnsProviderType.Script)
        {
            await provider.RemoveTxtRecordAsync(profile, recordName, value, CancellationToken.None).ConfigureAwait(false);
            return $"The token can change the zone {profile.ZoneName}: a temporary TXT record at '{recordName}' was added and removed.";
        }

        // A script's word is not enough: the record must really reach the zone's name servers.
        try
        {
            await _propagation.WaitAsync([new DnsTxtRecord(recordName, value)], null, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await provider.RemoveTxtRecordAsync(profile, recordName, value, CancellationToken.None).ConfigureAwait(false);
        }

        return $"The script can change the zone {profile.ZoneName}: it added a temporary TXT record at '{recordName}', " +
               "every authoritative name server returned it, and the script removed it.";
    }

    public async Task<string> UpdateScriptAsync(string name, string scriptPath, CancellationToken cancellationToken = default)
    {
        var profile = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        if (profile.Provider != DnsProviderType.Script)
        {
            throw new InvalidOperationException($"DNS provider '{profile.Name}' does not use a script.");
        }

        var sha256 = await _scripts.SaveAsync(profile.Name, scriptPath, cancellationToken).ConfigureAwait(false);
        if (string.Equals(sha256, profile.ScriptSha256, StringComparison.OrdinalIgnoreCase))
        {
            // The same content: the copy was just rewritten, which also repairs one that was changed or removed.
            return sha256;
        }

        var updated = profile with { ScriptSha256 = sha256 };
        try
        {
            await GetProvider(updated).VerifyAccessAsync(updated, cancellationToken).ConfigureAwait(false);
            var config = await configStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            if (!config.DnsProviders.Any(value => value.Name == profile.Name))
            {
                throw new InvalidOperationException($"DNS provider '{profile.Name}' was removed while its new script was being checked.");
            }

            await configStore.SaveAsync(
                    config with { DnsProviders = config.DnsProviders.Select(value => value.Name == profile.Name ? updated : value).ToArray() },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            _scripts.Delete(profile.Name, sha256);
            throw;
        }

        if (profile.ScriptSha256 is { } previous)
        {
            _scripts.Delete(profile.Name, previous);
        }

        return sha256;
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
        if (profile.ScriptSha256 is { } sha256)
        {
            _scripts.Delete(profile.Name, sha256);
        }
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

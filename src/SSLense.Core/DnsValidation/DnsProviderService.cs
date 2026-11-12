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
/// <param name="AcmeDnsCname">For acme-dns, the record to create at the DNS host.</param>
public sealed record DnsProviderOverview(
    string Name,
    DnsProviderType Provider,
    string ZoneName,
    string? ZoneId,
    string? ScriptSha256 = null,
    string? AcmeDnsCname = null);

/// <param name="Domain">The domain whose <c>_acme-challenge</c> CNAME will point to the account, such as example.com.</param>
/// <param name="Server">The acme-dns server's HTTPS address, such as https://auth.acme-dns.io.</param>
/// <param name="AllowFrom">Networks, such as 203.0.113.10/32, that may update the account. Only when registering.</param>
/// <param name="Import">An account another tool registered, used instead of registering a new one.</param>
public sealed record AcmeDnsProviderRequest(
    string Name,
    string Domain,
    string Server,
    IReadOnlyList<string>? AllowFrom = null,
    AcmeDnsAccount? Import = null);

public interface IDnsProviderService
{
    Task<IReadOnlyList<DnsProviderOverview>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>Checks the token can read the zone, then saves the provider with its token encrypted.</summary>
    Task AddAsync(DnsProviderRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Registers an acme-dns account, or imports one, and saves it. Returns it with the CNAME the administrator must create.
    /// </summary>
    Task<DnsProviderOverview> AddAcmeDnsAsync(AcmeDnsProviderRequest request, CancellationToken cancellationToken = default);

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
    DnsPropagationChecker? propagation = null,
    IAcmeDnsClient? acmeDns = null) : IDnsProviderService
{
    private const int MinScriptTimeoutSeconds = 10;
    private const int MaxScriptTimeoutSeconds = 3600;

    private readonly IDnsScriptStore _scripts = scripts ?? new DnsScriptStore();
    private readonly DnsPropagationChecker _propagation = propagation ?? new DnsPropagationChecker(lookup);

    public async Task<IReadOnlyList<DnsProviderOverview>> ListAsync(CancellationToken cancellationToken = default) =>
        (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).DnsProviders
            .Select(Overview)
            .ToArray();

    private static DnsProviderOverview Overview(DnsProviderProfile profile) =>
        new(profile.Name, profile.Provider, profile.ZoneName, profile.ZoneId, profile.ScriptSha256, profile.AcmeDnsCname);

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

        if (request.Provider == DnsProviderType.AcmeDns)
        {
            throw new ArgumentException("An acme-dns account is added with its domain and server ('dns add --provider acme-dns --domain ... --server ...').");
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
        }

        try
        {
            await GetProvider(profile).VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);

            // Added to the providers as they are now, so a change made while the provider was contacted is not overwritten.
            await configStore.UpdateAsync(
                    current =>
                    {
                        if (current.DnsProviders.Any(value =>
                                string.Equals(value.Name, name, StringComparison.OrdinalIgnoreCase) || DnsNames.Normalize(value.ZoneName) == zone))
                        {
                            throw new InvalidOperationException($"A DNS provider named '{name}' or for the zone '{zone}' was added while this one was being checked.");
                        }

                        RequireCopy(profile);
                        return current with { DnsProviders = [.. current.DnsProviders, profile] };
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception) when (profile.ScriptSha256 is not null)
        {
            await DeleteCopyIfUnusedAsync(name, profile.ScriptSha256).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<DnsProviderOverview> AddAcmeDnsAsync(AcmeDnsProviderRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var client = acmeDns ?? throw new InvalidOperationException("acme-dns is not available in this SSLense process.");
        var name = request.Name?.Trim() ?? string.Empty;
        if (name.Length == 0)
        {
            throw new ArgumentException("Enter a name for this DNS provider.");
        }

        // A wildcard and its base name use the same record, so the account is for the base name.
        var domain = DnsNames.Normalize(request.Domain ?? string.Empty);
        domain = domain.StartsWith("*.", StringComparison.Ordinal) ? domain[2..] : domain;
        if (!domain.Contains('.') || domain.Contains('*') || Uri.CheckHostName(domain) != UriHostNameType.Dns)
        {
            throw new ArgumentException($"'{request.Domain}' is not a valid domain name, such as example.com.");
        }

        if (!Uri.TryCreate(request.Server?.Trim(), UriKind.Absolute, out var server) || server.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("Enter the acme-dns server's address, starting with https://, such as https://auth.acme-dns.io.");
        }

        var allowFrom = (request.AllowFrom ?? []).Select(value => value.Trim()).Where(value => value.Length > 0).ToArray();
        foreach (var network in allowFrom)
        {
            if (!System.Net.IPNetwork.TryParse(network, out _))
            {
                throw new ArgumentException($"'{network}' is not a network, such as 203.0.113.10/32.");
            }
        }

        if (request.Import is not null && allowFrom.Length > 0)
        {
            throw new ArgumentException("Allowed networks are set when an account is registered, not when one is imported.");
        }

        var existing = (await configStore.LoadAsync(cancellationToken).ConfigureAwait(false)).DnsProviders;
        ThrowIfTaken(existing, name, domain);

        AcmeDnsAccount account;
        if (request.Import is { } import)
        {
            account = import with { FullDomain = DnsNames.Normalize(import.FullDomain ?? string.Empty) };
            if (string.IsNullOrWhiteSpace(account.Username) || string.IsNullOrWhiteSpace(account.Password) ||
                string.IsNullOrWhiteSpace(account.Subdomain) || Uri.CheckHostName(account.FullDomain) != UriHostNameType.Dns)
            {
                throw new ArgumentException("Importing an acme-dns account needs its username, password, subdomain, and full domain.");
            }

            await client.CheckHealthAsync(server, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            account = await client.RegisterAsync(server, allowFrom, cancellationToken).ConfigureAwait(false);
        }

        var profile = new DnsProviderProfile(
            name,
            DnsProviderType.AcmeDns,
            account.FullDomain,
            null,
            Protect(account.Password),
            AcmeDnsServer: server,
            AcmeDnsUsername: account.Username.Trim(),
            AcmeDnsSubdomain: account.Subdomain.Trim(),
            AcmeDnsDomain: domain);
        await configStore.UpdateAsync(
                current =>
                {
                    ThrowIfTaken(current.DnsProviders, name, domain);
                    if (current.DnsProviders.Any(value => DnsNames.Normalize(value.ZoneName) == profile.ZoneName))
                    {
                        throw new InvalidOperationException($"The acme-dns account '{profile.ZoneName}' is already used by another provider.");
                    }

                    return current with { DnsProviders = [.. current.DnsProviders, profile] };
                },
                cancellationToken)
            .ConfigureAwait(false);
        return Overview(profile);
    }

    /// <summary>One acme-dns account per domain: two would answer for the same CNAME.</summary>
    private static void ThrowIfTaken(IReadOnlyList<DnsProviderProfile> profiles, string name, string domain)
    {
        if (profiles.Any(value => string.Equals(value.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A DNS provider named '{name}' already exists. Remove it first, or choose another name.");
        }

        if (profiles.FirstOrDefault(value => value.Provider == DnsProviderType.AcmeDns && value.AcmeDnsDomain == domain) is { } other)
        {
            throw new InvalidOperationException($"The acme-dns account '{other.Name}' is already set up for {domain}. Remove it first to replace it.");
        }
    }

    public async Task<string> TestAsync(string name, CancellationToken cancellationToken = default)
    {
        var profile = await FindAsync(name, cancellationToken).ConfigureAwait(false);
        var provider = GetProvider(profile);
        await provider.VerifyAccessAsync(profile, cancellationToken).ConfigureAwait(false);
        if (profile.Provider == DnsProviderType.AcmeDns)
        {
            return await TestAcmeDnsAsync(profile, provider, cancellationToken).ConfigureAwait(false);
        }

        var recordName = $"_sslense-test.{DnsNames.Normalize(profile.ZoneName)}";
        var value = TestValue();
        await provider.AddTxtRecordAsync(profile, recordName, value, cancellationToken).ConfigureAwait(false);
        if (profile.Provider != DnsProviderType.Script)
        {
            await provider.RemoveTxtRecordAsync(profile, recordName, value, CancellationToken.None).ConfigureAwait(false);
            return $"The token can change the zone {profile.ZoneName}: a temporary TXT record at '{recordName}' was added and removed.";
        }

        // A script's word is not enough: the record must really reach the zone's name servers.
        bool confirmed;
        try
        {
            confirmed = await _propagation.ConfirmAsync([new DnsTxtRecord(recordName, value)], cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await provider.RemoveTxtRecordAsync(profile, recordName, value, CancellationToken.None).ConfigureAwait(false);
        }

        if (!confirmed)
        {
            throw new InvalidOperationException(
                $"The test could not finish: the script reported adding a temporary TXT record at '{recordName}', but this server " +
                "cannot query DNS servers, so SSLense could not check that the record exists. Outbound port 53 may be blocked. " +
                "The script then removed the record. Issuing still works without this check: SSLense waits 2 minutes instead, " +
                "and the certificate authority checks the record itself. To test the script, allow outbound DNS, or check your " +
                "DNS service's records while the script runs by hand.");
        }

        return $"The script can change the zone {profile.ZoneName}: it added a temporary TXT record at '{recordName}', " +
               "every authoritative name server returned it, and the script removed it.";
    }

    /// <summary>The CNAME first, because without it the CA never reaches the account; then a real update, seen at the server.</summary>
    private async Task<string> TestAcmeDnsAsync(DnsProviderProfile profile, IDnsProvider provider, CancellationToken cancellationToken)
    {
        var record = DnsNames.ChallengeRecord(profile.AcmeDnsDomain!);
        var target = DnsNames.Normalize(await lookup.ResolveCnameAsync(record, cancellationToken).ConfigureAwait(false));
        if (target != DnsNames.Normalize(profile.ZoneName))
        {
            throw new InvalidOperationException(
                $"'{record}' does not point to the acme-dns account yet" +
                (target == record ? "" : $"; it leads to '{target}'") +
                $". Create this record at your DNS host, then test again: {profile.AcmeDnsCname}");
        }

        var value = TestValue();
        await provider.AddTxtRecordAsync(profile, profile.ZoneName, value, cancellationToken).ConfigureAwait(false);
        if (!await _propagation.ConfirmAsync([new DnsTxtRecord(profile.ZoneName, value)], cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "The CNAME is in place and the acme-dns server accepted an update, but this server cannot query DNS servers, " +
                "so SSLense could not check that the new value is served. Outbound port 53 may be blocked. Issuing still works.");
        }

        return $"acme-dns works for {profile.AcmeDnsDomain}: '{record}' points to the account, the server accepted a new value, " +
               "and its name servers return it.";
    }

    /// <summary>43 characters of Base64url, like a real validation value; acme-dns accepts nothing else.</summary>
    private static string TestValue() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

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

            // Only the hash changes, on the profile as it is now: a secret replaced meanwhile must survive.
            await SaveProfileChangeAsync(
                    profile.Name,
                    "its new script was being checked",
                    current =>
                    {
                        if (!string.Equals(current.ScriptSha256, profile.ScriptSha256, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new InvalidOperationException(
                                $"The script for DNS provider '{profile.Name}' was replaced by another update while this one was being checked. " +
                                "Nothing was changed by this update. Run it again if it is still needed.");
                        }

                        RequireCopy(updated);
                        return current with { ScriptSha256 = sha256 };
                    },
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Another update may have saved this same copy meanwhile, so it is only removed when nothing uses it.
            await DeleteCopyIfUnusedAsync(profile.Name, sha256).ConfigureAwait(false);
            throw;
        }

        if (profile.ScriptSha256 is { } previous)
        {
            await DeleteCopyIfUnusedAsync(profile.Name, previous).ConfigureAwait(false);
        }

        return sha256;
    }

    /// <summary>
    /// Called under the config store's lock, just before a hash is saved: the copy must still exist, because an update that
    /// failed meanwhile may have removed it. Saved settings then never point at a missing copy.
    /// </summary>
    private void RequireCopy(DnsProviderProfile profile)
    {
        if (profile.ScriptSha256 is { } sha256)
        {
            _ = _scripts.GetVerifiedPath(profile.Name, sha256);
        }
    }

    /// <summary>
    /// Removes a script copy under the config store's lock, and only when no saved provider uses it: two updates to the same
    /// script share one copy. A failure to remove it is ignored; an unused copy is never run.
    /// </summary>
    private async Task DeleteCopyIfUnusedAsync(string name, string sha256)
    {
        try
        {
            await configStore.UpdateAsync(
                    config =>
                    {
                        if (!config.DnsProviders.Any(value =>
                                string.Equals(value.Name, name, StringComparison.OrdinalIgnoreCase) &&
                                string.Equals(value.ScriptSha256, sha256, StringComparison.OrdinalIgnoreCase)))
                        {
                            _scripts.Delete(name, sha256);
                        }

                        return config;
                    },
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException)
        {
        }
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

        // Only the token changes, on the profile as it is now: a script updated meanwhile must keep its new hash.
        await SaveProfileChangeAsync(
                profile.Name,
                "its token was being checked",
                current => current with { ProtectedToken = updated.ProtectedToken },
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

        await configStore.UpdateAsync(
                current => current with { DnsProviders = current.DnsProviders.Where(value => value.Name != profile.Name).ToArray() },
                cancellationToken)
            .ConfigureAwait(false);
        if (profile.ScriptSha256 is { } sha256)
        {
            await DeleteCopyIfUnusedAsync(profile.Name, sha256).ConfigureAwait(false);
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

    /// <summary>
    /// Applies one change to the provider as it is saved now, under the config store's lock. A check before it can take
    /// seconds, so the profile read before the check may be out of date, and saving that copy would undo another change.
    /// </summary>
    private Task SaveProfileChangeAsync(
        string name,
        string during,
        Func<DnsProviderProfile, DnsProviderProfile> change,
        CancellationToken cancellationToken) =>
        configStore.UpdateAsync(
            config =>
            {
                var current = config.DnsProviders.FirstOrDefault(value => value.Name == name)
                    ?? throw new InvalidOperationException($"DNS provider '{name}' was removed while {during}.");
                var changed = change(current);
                return config with { DnsProviders = config.DnsProviders.Select(value => value.Name == name ? changed : value).ToArray() };
            },
            cancellationToken);

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

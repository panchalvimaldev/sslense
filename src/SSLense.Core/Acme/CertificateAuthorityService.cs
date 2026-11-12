using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SSLense.Core.Config;

namespace SSLense.Core.Acme;

/// <param name="Preset">A preset's ID, such as zerossl; or null with <paramref name="Name"/> and <paramref name="DirectoryUrl"/>.</param>
/// <param name="Id">The profile's ID; from the preset or the name when null.</param>
/// <param name="IsTest">For a custom CA: its certificates are not trusted by browsers, so no production confirmation is asked.</param>
/// <param name="EabHmacKey">The EAB HMAC key in plain text, Base64url or Base64; encrypted before it is saved.</param>
/// <param name="CaaDomain">Overrides the CAA identities the directory publishes; for a CA that publishes none.</param>
public sealed record CertificateAuthorityRequest(
    string? Preset = null,
    string? Id = null,
    string? Name = null,
    string? DirectoryUrl = null,
    bool IsTest = false,
    string? EabKeyId = null,
    string? EabHmacKey = null,
    string? CaaDomain = null);

/// <param name="UsedBy">The IIS sites whose certificates renew with this CA.</param>
public sealed record CertificateAuthorityOverview(
    string Id,
    string Name,
    Uri DirectoryUri,
    bool IsTest,
    bool IsBuiltIn,
    bool HasExternalAccountBinding,
    IReadOnlyList<string> CaaIdentities,
    IReadOnlyList<string> UsedBy);

public interface ICertificateAuthorityService
{
    IReadOnlyList<CertificateAuthorityPreset> Presets { get; }

    Task<IReadOnlyList<CertificateAuthorityOverview>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>Reads the CA's directory first, and saves nothing if it cannot be used as given.</summary>
    Task<CertificateAuthorityOverview> AddAsync(CertificateAuthorityRequest request, CancellationToken cancellationToken = default);

    /// <summary>Reads the directory and reports what it says. Creates no account and changes nothing.</summary>
    Task<string> TestAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>Removes a configured CA, unless a certificate renews with it. Its ACME account key is kept.</summary>
    Task RemoveAsync(string id, CancellationToken cancellationToken = default);
}

internal sealed partial class CertificateAuthorityService(
    IConfigStore configStore,
    IManagedCertificateStore managedStore,
    ICertificateAuthorityRegistry registry,
    IAcmeDirectoryReader directoryReader,
    ISecretProtector protector,
    ICertificateAuthorityLock? authorityLock = null) : ICertificateAuthorityService
{
    private readonly ICertificateAuthorityLock _authorityLock = authorityLock ?? NoOpCertificateAuthorityLock.Instance;

    public IReadOnlyList<CertificateAuthorityPreset> Presets => CertificateAuthorities.Presets;

    public async Task<IReadOnlyList<CertificateAuthorityOverview>> ListAsync(CancellationToken cancellationToken = default)
    {
        var certificates = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return (await registry.GetAllAsync(cancellationToken).ConfigureAwait(false))
            .Select(authority => Overview(authority, certificates))
            .ToArray();
    }

    public async Task<CertificateAuthorityOverview> AddAsync(CertificateAuthorityRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        string id, name;
        Uri directory;
        bool isTest;
        if (request.Preset is { } presetId)
        {
            var preset = CertificateAuthorities.Presets.FirstOrDefault(value => string.Equals(value.Id, presetId.Trim(), StringComparison.OrdinalIgnoreCase))
                ?? throw new ArgumentException(
                    $"There is no preset named '{presetId}'. Presets: {string.Join(", ", CertificateAuthorities.Presets.Select(value => value.Id))}. " +
                    "For any other CA, give its name and directory URL.");
            id = request.Id?.Trim() ?? preset.Id;
            name = string.IsNullOrWhiteSpace(request.Name) ? preset.Name : request.Name.Trim();
            directory = preset.DirectoryUri;
            isTest = preset.IsTest;
        }
        else
        {
            name = request.Name?.Trim() ?? string.Empty;
            if (name.Length == 0)
            {
                throw new ArgumentException("Enter a name for the certificate authority, or choose a preset.");
            }

            if (!Uri.TryCreate(request.DirectoryUrl?.Trim(), UriKind.Absolute, out var parsed) || parsed.Scheme != Uri.UriSchemeHttps)
            {
                throw new ArgumentException("Enter the CA's ACME directory URL, starting with https://.");
            }

            id = request.Id?.Trim() ?? Slug(name);
            directory = parsed;
            isTest = request.IsTest;
        }

        id = id.ToLowerInvariant();
        if (!CertificateAuthorities.IsValidId(id))
        {
            throw new ArgumentException($"'{id}' cannot be a certificate authority ID. Use lowercase letters, digits, and hyphens, up to 40 characters.");
        }

        if (CertificateAuthorities.IsBuiltIn(id))
        {
            throw new ArgumentException($"'{id}' is built in. Let's Encrypt needs no setup.");
        }

        var keyId = request.EabKeyId?.Trim() ?? string.Empty;
        var hmac = NormalizeHmacKey(request.EabHmacKey);
        if ((keyId.Length == 0) != (hmac.Length == 0))
        {
            throw new ArgumentException("External Account Binding needs both the key ID and the HMAC key.");
        }

        var caaOverride = request.CaaDomain?.Trim().TrimEnd('.').ToLowerInvariant();
        if (!string.IsNullOrEmpty(caaOverride) && Uri.CheckHostName(caaOverride) != UriHostNameType.Dns)
        {
            throw new ArgumentException($"'{request.CaaDomain}' is not a domain name, such as ca.example.com.");
        }

        if ((await registry.GetAllAsync(cancellationToken).ConfigureAwait(false)).Any(value => value.Id == id))
        {
            throw new InvalidOperationException($"A certificate authority with the ID '{id}' already exists. Remove it first, or give another ID.");
        }

        var info = await directoryReader.ReadAsync(directory, cancellationToken).ConfigureAwait(false);
        if (info.ExternalAccountRequired && keyId.Length == 0)
        {
            throw new ArgumentException(
                $"{name} requires External Account Binding. Get an EAB key ID and HMAC key from your {name} account, " +
                "then add it again with them (--eab in the CLI).");
        }

        var authority = new CertificateAuthority(
            id,
            name,
            directory,
            isTest,
            keyId.Length == 0 ? null : keyId,
            hmac.Length == 0 ? null : Protect(hmac),
            CaaIdentities: string.IsNullOrEmpty(caaOverride) ? info.CaaIdentities : [caaOverride]);
        await configStore.UpdateAsync(
                config => config.CertificateAuthorities.Any(value => value.Id == id)
                    ? throw new InvalidOperationException($"A certificate authority with the ID '{id}' was added while this one was being checked.")
                    : config with { CertificateAuthorities = [.. config.CertificateAuthorities, authority] },
                cancellationToken)
            .ConfigureAwait(false);
        return Overview(authority, []);
    }

    public async Task<string> TestAsync(string id, CancellationToken cancellationToken = default)
    {
        var authority = await registry.GetAsync(id?.Trim() ?? string.Empty, cancellationToken).ConfigureAwait(false);
        var info = await directoryReader.ReadAsync(authority.DirectoryUri, cancellationToken).ConfigureAwait(false);
        if (info.ExternalAccountRequired && !authority.HasExternalAccountBinding)
        {
            throw new InvalidOperationException(
                $"{authority.Name} now requires External Account Binding, and none is saved for it. " +
                $"Remove it and add it again with EAB credentials from your {authority.Name} account.");
        }

        var lines = new List<string>
        {
            $"{authority.Name} ({authority.Id}) answered at {authority.DirectoryUri}.",
            info.ExternalAccountRequired
                ? "External Account Binding: required, and saved."
                : $"External Account Binding: not required{(authority.HasExternalAccountBinding ? ", but saved, and used when the account is created" : string.Empty)}.",
            info.SupportsRenewalInfo
                ? "Renewal timing: the CA suggests it (ARI)."
                : "Renewal timing: the CA does not suggest it, so SSLense renews the configured number of days before expiry, and no earlier than a third of the lifetime before.",
            authority.CaaIdentities is { Count: > 0 } caa
                ? $"CAA: checked before each order, for {string.Join(", ", caa)}."
                : "CAA: not checked, because the CA publishes no CAA identities. The CA still checks CAA itself.",
            info.Profiles is { Count: > 0 } profiles
                ? $"Profiles, for --profile: {string.Join("; ", profiles.Select(profile => profile.Value.Length == 0 ? profile.Key : $"{profile.Key} ({profile.Value})"))}."
                : "Profiles: none offered, so certificates use the CA's default.",
            authority.IsTest
                ? "Certificates from it are not trusted by browsers."
                : "Certificates from it are trusted, so issuing asks for confirmation (--accept-production-risk)."
        };
        return string.Join(Environment.NewLine, lines);
    }

    public async Task RemoveAsync(string id, CancellationToken cancellationToken = default)
    {
        // Waits for any issue from this CA to save its certificate, so the check below sees it.
        var trimmed = id?.Trim().ToLowerInvariant() ?? string.Empty;
        if (CertificateAuthorities.IsBuiltIn(trimmed))
        {
            throw new InvalidOperationException($"'{trimmed}' is built in and cannot be removed.");
        }

        await using var removal = await _authorityLock.AcquireRemovalAsync(trimmed, cancellationToken).ConfigureAwait(false);
        var authority = await registry.GetAsync(trimmed, cancellationToken).ConfigureAwait(false);
        if (authority.IsBuiltIn)
        {
            throw new InvalidOperationException($"'{authority.Id}' is built in and cannot be removed.");
        }

        var users = UsedBy(authority.Id, await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false));
        if (users.Count > 0)
        {
            throw new InvalidOperationException(
                $"{authority.Name} cannot be removed, because these certificates renew with it: {string.Join(", ", users)}. " +
                "Move them to another CA with 'SSLense.Cli issue --ca <id> --force', or remove them, first.");
        }

        await configStore.UpdateAsync(
                config => config with { CertificateAuthorities = config.CertificateAuthorities.Where(value => value.Id != authority.Id).ToArray() },
                cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Accepts Base64url, as CAs show it, or standard Base64; stores Base64url without padding, as EAB uses it.</summary>
    internal static string NormalizeHmacKey(string? value)
    {
        var key = value?.Trim() ?? string.Empty;
        if (key.Length == 0)
        {
            return key;
        }

        var normalized = key.Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var base64 = normalized.Replace('-', '+').Replace('_', '/');
        try
        {
            if (Convert.FromBase64String(base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=')).Length == 0)
            {
                throw new FormatException();
            }
        }
        catch (FormatException)
        {
            throw new ArgumentException("The EAB HMAC key is not valid Base64url. Copy it again from the CA's account page.");
        }

        return normalized;
    }

    private static IReadOnlyList<string> UsedBy(string id, IReadOnlyList<ManagedCertificate> certificates) =>
        certificates
            .Where(certificate => certificate.Source == CertificateSource.Acme && string.Equals(certificate.AuthorityId, id, StringComparison.OrdinalIgnoreCase))
            .SelectMany(certificate => certificate.AllSiteNames())
            .ToArray();

    private static CertificateAuthorityOverview Overview(CertificateAuthority authority, IReadOnlyList<ManagedCertificate> certificates) =>
        new(
            authority.Id,
            authority.Name,
            authority.DirectoryUri,
            authority.IsTest,
            authority.IsBuiltIn,
            authority.HasExternalAccountBinding,
            authority.CaaIdentities ?? [],
            UsedBy(authority.Id, certificates));

    private string Protect(string value)
    {
        var plaintext = Encoding.UTF8.GetBytes(value);
        try
        {
            return Convert.ToBase64String(protector.Protect(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static string Slug(string name)
    {
        var slug = NonIdCharacters().Replace(name.ToLowerInvariant(), "-").Trim('-');
        return slug.Length > 40 ? slug[..40].Trim('-') : slug;
    }

    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NonIdCharacters();
}

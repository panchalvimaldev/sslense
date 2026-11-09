using System.Text.RegularExpressions;

namespace SSLense.Core.Acme;

/// <summary>
/// An ACME certificate authority SSLense can issue from. The two Let's Encrypt profiles are built in;
/// others are configured by the administrator and stored in config.json.
/// </summary>
/// <param name="Id">Stable identifier stored with each certificate; lowercase letters, digits, and hyphens.</param>
/// <param name="IsTest">
/// True for test endpoints whose certificates browsers do not trust. Every other profile is treated as
/// production and needs an explicit acknowledgement before its first use.
/// </param>
/// <param name="EabKeyId">External Account Binding key ID, for CAs that require one.</param>
/// <param name="ProtectedEabHmacKey">
/// DPAPI-protected EAB HMAC key; used when the ACME account is created, and kept so a lost account key can be replaced.
/// </param>
/// <param name="ProductionAcknowledged">No longer used: every issue from a non-test CA confirms it (docs/design/certificate-sources.md, 9.4).</param>
/// <param name="CaaIdentities">
/// The domains this CA looks for in CAA records, from its directory or given by the administrator. Null or empty when
/// unknown, and then CAA is not checked.
/// </param>
public sealed record CertificateAuthority(
    string Id,
    string Name,
    Uri DirectoryUri,
    bool IsTest,
    string? EabKeyId = null,
    string? ProtectedEabHmacKey = null,
    bool ProductionAcknowledged = false,
    IReadOnlyList<string>? CaaIdentities = null)
{
    public bool IsBuiltIn => CertificateAuthorities.IsBuiltIn(Id);

    public bool HasExternalAccountBinding => !string.IsNullOrEmpty(EabKeyId) && !string.IsNullOrEmpty(ProtectedEabHmacKey);
}

/// <summary>A certificate authority SSLense knows the address of. EAB and CAA come from its directory when it is added.</summary>
public sealed record CertificateAuthorityPreset(string Id, string Name, Uri DirectoryUri, bool IsTest);

public static partial class CertificateAuthorities
{
    public const string LetsEncryptId = "letsencrypt";
    public const string LetsEncryptStagingId = "letsencrypt-staging";

    public static CertificateAuthority LetsEncrypt { get; } = new(
        LetsEncryptId,
        "Let's Encrypt production",
        new Uri("https://acme-v02.api.letsencrypt.org/directory"),
        IsTest: false,
        CaaIdentities: ["letsencrypt.org"]);

    public static CertificateAuthority LetsEncryptStaging { get; } = new(
        LetsEncryptStagingId,
        "Let's Encrypt staging",
        new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"),
        IsTest: true,
        CaaIdentities: ["letsencrypt.org"]);

    public static IReadOnlyList<CertificateAuthority> BuiltIn { get; } = [LetsEncryptStaging, LetsEncrypt];

    /// <summary>
    /// Checked against each CA's directory on November 9, 2026. Sectigo OV and EV are left out: they need organisation
    /// checks outside ACME.
    /// </summary>
    public static IReadOnlyList<CertificateAuthorityPreset> Presets { get; } =
    [
        new("zerossl", "ZeroSSL", new Uri("https://acme.zerossl.com/v2/DV90"), IsTest: false),
        new("google", "Google Trust Services", new Uri("https://dv.acme-v02.api.pki.goog/directory"), IsTest: false),
        new("google-test", "Google Trust Services test", new Uri("https://dv.acme-v02.test-api.pki.goog/directory"), IsTest: true),
        new("sslcom", "SSL.com", new Uri("https://acme.ssl.com/sslcom-dv-ecc"), IsTest: false),
        new("sectigo", "Sectigo DV", new Uri("https://acme.sectigo.com/v2/DV"), IsTest: false)
    ];

    public static bool IsBuiltIn(string id) => id is LetsEncryptId or LetsEncryptStagingId;

    /// <summary>Maps the schema 1 environment (0 = staging, 1 = production) to its built-in profile.</summary>
    public static string FromLegacyEnvironment(int environment) => environment == 1 ? LetsEncryptId : LetsEncryptStagingId;

    /// <summary>
    /// The short word used in messages such as "the staging certificate for ...". Built-in profiles keep the
    /// wording SSLense has always used; other profiles use their ID.
    /// </summary>
    public static string Label(string authorityId) => authorityId switch
    {
        LetsEncryptStagingId => "staging",
        LetsEncryptId => "production",
        _ => authorityId
    };

    public static bool IsValidId(string id) => ValidId().IsMatch(id);

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")]
    private static partial Regex ValidId();
}

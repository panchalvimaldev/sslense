namespace SSLense.Core.Acme;

/// <summary>The certificate's key, chosen at issue and kept at renewal. See docs/design/key-and-order-options.md.</summary>
public enum CertificateKeyType
{
    EcdsaP256 = 0,
    EcdsaP384 = 1,
    Rsa2048 = 2,
    Rsa3072 = 3,
    Rsa4096 = 4
}

/// <summary>How an order differs from the CA's defaults.</summary>
/// <param name="PreferredChain">The root the chain should end at, as the CA names it; the default chain when the CA offers none to it.</param>
/// <param name="Profile">An ACME profile the CA lists in its directory, such as Let's Encrypt's <c>shortlived</c>.</param>
public sealed record AcmeOrderOptions(
    CertificateKeyType KeyType = CertificateKeyType.EcdsaP256,
    string? PreferredChain = null,
    string? Profile = null)
{
    public static AcmeOrderOptions Default { get; } = new();

    public bool IsDefault => this == Default;
}

public static class CertificateKeyTypes
{
    /// <summary>The names the CLI and the app use, in the order they are offered.</summary>
    public static IReadOnlyList<(CertificateKeyType Type, string Name, string Label)> All { get; } =
    [
        (CertificateKeyType.EcdsaP256, "ecdsa-p256", "ECDSA P-256 (recommended)"),
        (CertificateKeyType.EcdsaP384, "ecdsa-p384", "ECDSA P-384"),
        (CertificateKeyType.Rsa2048, "rsa-2048", "RSA 2048, for older clients"),
        (CertificateKeyType.Rsa3072, "rsa-3072", "RSA 3072"),
        (CertificateKeyType.Rsa4096, "rsa-4096", "RSA 4096")
    ];

    public static string Name(CertificateKeyType type) => All.First(value => value.Type == type).Name;

    public static CertificateKeyType Parse(string name) =>
        All.FirstOrDefault(value => string.Equals(value.Name, name.Trim(), StringComparison.OrdinalIgnoreCase)) is { Name: not null } match
            ? match.Type
            : throw new ArgumentException($"'{name}' is not a key type. Use one of: {string.Join(", ", All.Select(value => value.Name))}.");
}

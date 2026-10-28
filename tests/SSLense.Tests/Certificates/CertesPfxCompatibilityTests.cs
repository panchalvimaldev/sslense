using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certes;
using Certes.Pkcs;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>
/// Issuance builds the PFX with Certes (BouncyCastle) and imports it with X509CertificateLoader, which
/// enforces stricter PKCS#12 limits than the constructor it replaced in .NET 9. This guards that pairing
/// offline, because otherwise only a live ACME issuance would reveal an incompatibility.
/// </summary>
public sealed class CertesPfxCompatibilityTests
{
    [Fact]
    public void LoadPkcs12_AcceptsPfxBuiltByCertesWithItsDefaultEncryption()
    {
        // Same key algorithm as CertesAcmeProtocolClient.FinalizeAsync.
        var certesKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(certesKey.ToPem());
        var request = new CertificateRequest("CN=example.com", ecdsa, HashAlgorithmName.SHA256);
        using var issued = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var pfx = new PfxBuilder(issued.RawData, certesKey) { FullChain = false }
            .Build("SSLense: example.com", password);
        using var loaded = X509CertificateLoader.LoadPkcs12(pfx, password, X509KeyStorageFlags.EphemeralKeySet);

        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(issued.Thumbprint, loaded.Thumbprint);
    }
}

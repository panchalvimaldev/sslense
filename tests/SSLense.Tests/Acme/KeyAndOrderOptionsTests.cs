using System.Net;
using System.Security.Cryptography;
using System.Text;
using SSLense.Core.Acme;
using Xunit;

namespace SSLense.Tests.Acme;

/// <summary>Key types, preferred chains, and profiles (docs/design/key-and-order-options.md).</summary>
public sealed class KeyAndOrderOptionsTests
{
    [Theory]
    [InlineData(CertificateKeyType.EcdsaP256, "ecdsa", 256)]
    [InlineData(CertificateKeyType.EcdsaP384, "ecdsa", 384)]
    [InlineData(CertificateKeyType.Rsa2048, "rsa", 2048)]
    [InlineData(CertificateKeyType.Rsa3072, "rsa", 3072)]
    [InlineData(CertificateKeyType.Rsa4096, "rsa", 4096)]
    public void EachKeyType_CreatesThatKey(CertificateKeyType type, string family, int size)
    {
        var pem = CertesAcmeProtocolClient.NewCertificateKey(type).ToPem();

        using AsymmetricAlgorithm key = family == "rsa" ? RSA.Create() : ECDsa.Create();
        key.ImportFromPem(pem);
        Assert.Equal(size, key.KeySize);
    }

    [Theory]
    [InlineData("rsa-3072", CertificateKeyType.Rsa3072)]
    [InlineData(" ECDSA-P384 ", CertificateKeyType.EcdsaP384)]
    public void KeyTypeNames_AreParsedWithoutRegardToCase(string name, CertificateKeyType expected) =>
        Assert.Equal(expected, CertificateKeyTypes.Parse(name));

    [Fact]
    public void AnUnknownKeyType_ListsTheChoices()
    {
        var exception = Assert.Throws<ArgumentException>(() => CertificateKeyTypes.Parse("ecdsa-p521"));

        Assert.Contains("rsa-4096", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDefaults_AreRecognisedAsDefault_AndBlankValuesCountAsNone()
    {
        Assert.True(new AcmeIssueRequest("Shop", [], "ops@example.com", PreferredChain: " ", Profile: "").OrderOptions.IsDefault);
        Assert.False(new AcmeIssueRequest("Shop", [], "ops@example.com", KeyType: CertificateKeyType.Rsa2048).OrderOptions.IsDefault);
        Assert.Equal("ISRG Root X1", new AcmeIssueRequest("Shop", [], "ops@example.com", PreferredChain: " ISRG Root X1 ").OrderOptions.PreferredChain);
    }

    [Fact]
    public async Task TheDirectoryReader_ReadsTheProfilesTheCaOffers()
    {
        const string directory = """
            {
              "newNonce": "https://ca.example/nonce", "newAccount": "https://ca.example/account", "newOrder": "https://ca.example/order",
              "meta": { "profiles": { "classic": "The same as today", "shortlived": "Valid for about six days" } }
            }
            """;
        var reader = new AcmeDirectoryReader(new HttpClient(new FixedResponse(directory)));

        var info = await reader.ReadAsync(new Uri("https://ca.example/directory"), CancellationToken.None);

        Assert.Equal(["classic", "shortlived"], info.Profiles!.Keys.Order());
        Assert.Equal("Valid for about six days", info.Profiles["shortlived"]);
    }

    private sealed class FixedResponse(string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
    }
}

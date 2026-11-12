using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Tests.DnsValidation;
using Xunit;

namespace SSLense.Tests.Acme;

/// <summary>Other ACME certificate authorities (docs/design/certificate-sources.md, section 9).</summary>
public sealed class CertificateAuthorityServiceTests
{
    private const string HmacKey = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MI0rU2Tu";
    private readonly FakeConfigStore _config = new();
    private readonly FakeDirectory _directory = new();
    private readonly Mock<IManagedCertificateStore> _managed = new();

    public CertificateAuthorityServiceTests() =>
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);

    private CertificateAuthorityService Service() =>
        new(_config, _managed.Object, new CertificateAuthorityRegistry(_config), _directory, new XorProtector());

    // ---- Reading a directory ----

    [Fact]
    public void Directory_ReadsEabRequirement_CaaIdentities_AndAri()
    {
        var info = AcmeDirectoryReader.Parse("""
            {"newNonce":"n","newAccount":"a","newOrder":"o","renewalInfo":"r",
             "meta":{"externalAccountRequired":true,"caaIdentities":["Sectigo.com","comodoca.com"],"termsOfService":"https://ca/tos"}}
            """, new Uri("https://ca.example/directory"));

        Assert.True(info.ExternalAccountRequired);
        Assert.Equal(["sectigo.com", "comodoca.com"], info.CaaIdentities);
        Assert.True(info.SupportsRenewalInfo);
        Assert.Equal("https://ca/tos", info.TermsOfService);
    }

    [Fact]
    public void Directory_WithoutMeta_NeedsNoEab_AndHasNoCaa()
    {
        var info = AcmeDirectoryReader.Parse("""{"newNonce":"n","newAccount":"a","newOrder":"o"}""", new Uri("https://ca.example/directory"));

        Assert.False(info.ExternalAccountRequired);
        Assert.Empty(info.CaaIdentities);
        Assert.False(info.SupportsRenewalInfo);
    }

    [Theory]
    [InlineData("""{"hello":"world"}""")]
    [InlineData("<html>not json</html>")]
    public void Directory_SomethingElse_IsRefusedWithAClearMessage(string json) =>
        Assert.Contains("ACME directory", Assert.Throws<InvalidOperationException>(() =>
            AcmeDirectoryReader.Parse(json, new Uri("https://ca.example/directory"))).Message, StringComparison.Ordinal);

    // ---- Adding ----

    [Fact]
    public async Task Add_PresetThatRequiresEab_WithoutIt_IsRefused_AndSavesNothing()
    {
        _directory.Info = new AcmeDirectoryInfo(true, ["sectigo.com"], true, null);

        var message = (await Assert.ThrowsAsync<ArgumentException>(() => Service().AddAsync(new CertificateAuthorityRequest("zerossl")))).Message;

        Assert.Contains("External Account Binding", message, StringComparison.Ordinal);
        Assert.Empty(_config.Config.CertificateAuthorities);
    }

    [Fact]
    public async Task Add_PresetWithEab_SavesTheHmacKeyEncrypted_AndTheDirectorysCaaIdentities()
    {
        _directory.Info = new AcmeDirectoryInfo(true, ["sectigo.com", "comodoca.com"], true, null);

        var added = await Service().AddAsync(new CertificateAuthorityRequest("zerossl", EabKeyId: "kid-1", EabHmacKey: HmacKey));

        var saved = Assert.Single(_config.Config.CertificateAuthorities);
        Assert.Equal("zerossl", saved.Id);
        Assert.Equal(new Uri("https://acme.zerossl.com/v2/DV90"), saved.DirectoryUri);
        Assert.False(saved.IsTest);
        Assert.Equal("kid-1", saved.EabKeyId);
        Assert.DoesNotContain(HmacKey, saved.ProtectedEabHmacKey!, StringComparison.Ordinal);
        Assert.Equal(HmacKey, Encoding.UTF8.GetString(new XorProtector().Unprotect(Convert.FromBase64String(saved.ProtectedEabHmacKey!))));
        Assert.Equal(["sectigo.com", "comodoca.com"], saved.CaaIdentities);
        Assert.True(added.HasExternalAccountBinding);
        Assert.Equal(new Uri("https://acme.zerossl.com/v2/DV90"), _directory.Read.Single());
    }

    [Fact]
    public async Task Add_CustomCa_TakesItsIdFromTheName_AndACaaDomainOverride()
    {
        _directory.Info = new AcmeDirectoryInfo(false, [], false, null);

        var added = await Service().AddAsync(new CertificateAuthorityRequest(
            Name: "Internal CA", DirectoryUrl: "https://acme.internal.example/directory", IsTest: true, CaaDomain: "Internal.Example."));

        Assert.Equal("internal-ca", added.Id);
        Assert.True(added.IsTest);
        Assert.Equal(["internal.example"], added.CaaIdentities);
        Assert.False(added.HasExternalAccountBinding);
    }

    [Theory]
    [InlineData(null, "http://acme.example/directory", null, null)]
    [InlineData(null, "https://acme.example/directory", "kid", null)]
    [InlineData(null, "https://acme.example/directory", "kid", "not base64 !")]
    [InlineData("letsencrypt", "https://acme.example/directory", null, null)]
    [InlineData("Not An Id!", "https://acme.example/directory", null, null)]
    public async Task Add_InvalidInput_IsRefusedBeforeTheDirectoryIsRead(string? id, string url, string? keyId, string? hmac)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Service().AddAsync(
            new CertificateAuthorityRequest(Id: id, Name: "Example", DirectoryUrl: url, EabKeyId: keyId, EabHmacKey: hmac)));

        Assert.Empty(_directory.Read);
        Assert.Empty(_config.Config.CertificateAuthorities);
    }

    [Fact]
    public async Task Add_UnknownPreset_ListsThePresets()
    {
        var message = (await Assert.ThrowsAsync<ArgumentException>(() => Service().AddAsync(new CertificateAuthorityRequest("letsencrypt-plus")))).Message;

        Assert.Contains("zerossl", message, StringComparison.Ordinal);
        Assert.Contains("google-test", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Add_TheSameIdTwice_IsRefused()
    {
        _directory.Info = new AcmeDirectoryInfo(false, ["ssl.com"], true, null);
        await Service().AddAsync(new CertificateAuthorityRequest("sslcom"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().AddAsync(new CertificateAuthorityRequest("sslcom")));
        Assert.Single(_config.Config.CertificateAuthorities);
    }

    [Theory]
    [InlineData("zWNDZM6eQGHWpSRTPal5eIUYFTu7EajV", "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajV")]
    [InlineData("ab+c/d==", "ab-c_d")]
    [InlineData("  ab-c_d  ", "ab-c_d")]
    public void HmacKey_AcceptsBase64urlOrBase64_AndStoresBase64url(string input, string stored) =>
        Assert.Equal(stored, CertificateAuthorityService.NormalizeHmacKey(input));

    // ---- Testing and removing ----

    [Fact]
    public async Task Test_ReportsWhatTheDirectorySays_WithoutCreatingAnything()
    {
        _directory.Info = new AcmeDirectoryInfo(false, ["pki.goog"], true, null);
        await Service().AddAsync(new CertificateAuthorityRequest("google-test"));

        var report = await Service().TestAsync("google-test");

        Assert.Contains("answered", report, StringComparison.Ordinal);
        Assert.Contains("ARI", report, StringComparison.Ordinal);
        Assert.Contains("pki.goog", report, StringComparison.Ordinal);
        Assert.Contains("not trusted by browsers", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Test_ACaThatNowRequiresEab_SaysToAddItAgain()
    {
        _directory.Info = new AcmeDirectoryInfo(false, ["ssl.com"], true, null);
        await Service().AddAsync(new CertificateAuthorityRequest("sslcom"));
        _directory.Info = new AcmeDirectoryInfo(true, ["ssl.com"], true, null);

        Assert.Contains("now requires External Account Binding", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service().TestAsync("sslcom"))).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Remove_ACaACertificateRenewsWith_IsRefused_AndNamesTheSites()
    {
        _directory.Info = new AcmeDirectoryInfo(false, ["ssl.com"], true, null);
        await Service().AddAsync(new CertificateAuthorityRequest("sslcom"));
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new ManagedCertificate("Shop", ["shop.example.com"], "a@example.com", "AA", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), AuthorityId: "sslcom")
        ]);

        Assert.Contains("Shop", (await Assert.ThrowsAsync<InvalidOperationException>(() => Service().RemoveAsync("sslcom"))).Message, StringComparison.Ordinal);
        Assert.Single(_config.Config.CertificateAuthorities);
        Assert.Equal(["Shop"], (await Service().ListAsync()).Single(value => value.Id == "sslcom").UsedBy);
    }

    [Fact]
    public async Task Remove_AnUnusedCa_RemovesIt_AndBuiltInOnesCannotBe()
    {
        _directory.Info = new AcmeDirectoryInfo(false, ["ssl.com"], true, null);
        await Service().AddAsync(new CertificateAuthorityRequest("sslcom"));

        await Service().RemoveAsync("sslcom");

        Assert.Empty(_config.Config.CertificateAuthorities);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().RemoveAsync("letsencrypt"));
    }

    [Fact]
    public async Task List_ShowsLetsEncryptFirst_ThenAddedOnes()
    {
        _directory.Info = new AcmeDirectoryInfo(false, ["ssl.com"], true, null);
        await Service().AddAsync(new CertificateAuthorityRequest("sslcom"));

        var list = await Service().ListAsync();

        Assert.Equal(["letsencrypt-staging", "letsencrypt", "sslcom"], list.Select(value => value.Id));
        Assert.Equal(["letsencrypt.org"], list[0].CaaIdentities);
    }

    private sealed class FakeDirectory : IAcmeDirectoryReader
    {
        public AcmeDirectoryInfo Info { get; set; } = new(false, [], false, null);

        public List<Uri> Read { get; } = [];

        public Task<AcmeDirectoryInfo> ReadAsync(Uri directoryUri, CancellationToken cancellationToken)
        {
            Read.Add(directoryUri);
            return Task.FromResult(Info);
        }
    }

    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Select(value => (byte)(value ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }
}

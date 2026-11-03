using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class DnsProviderServiceTests
{
    private const string Token = "plain-cloudflare-token";
    private static readonly string ZoneId = new('a', 32);
    private readonly FakeDnsProvider _provider = new();
    private readonly FakeDnsLookup _lookup = new();
    private readonly FakeConfigStore _config = new();
    private readonly Mock<IManagedCertificateStore> _managed = new();

    public DnsProviderServiceTests()
    {
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
    }

    [Fact]
    public async Task Add_VerifiesThenSavesTheTokenEncrypted()
    {
        await Service().AddAsync(Request());

        var saved = Assert.Single(_config.Config.DnsProviders);
        Assert.Equal("example.com", saved.ZoneName);
        Assert.Equal(["verify Main"], _provider.Calls);
        Assert.DoesNotContain(Token, saved.ProtectedToken, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, Encoding.UTF8.GetString(Convert.FromBase64String(saved.ProtectedToken)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Add_TokenRejected_SavesNothing()
    {
        _provider.FailVerify = new InvalidOperationException("rejected");

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().AddAsync(Request()));

        Assert.Empty(_config.Config.DnsProviders);
    }

    [Theory]
    [InlineData("", "example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Token)]
    [InlineData("Main", "com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Token)]
    [InlineData("Main", "*.example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Token)]
    [InlineData("Main", "example.com", "too-short", Token)]
    [InlineData("Main", "example.com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", " ")]
    public async Task Add_InvalidInput_IsRefusedBeforeContactingTheProvider(string name, string zone, string zoneId, string token)
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Service().AddAsync(new DnsProviderRequest(name, DnsProviderType.Cloudflare, zone, zoneId, token)));

        Assert.Empty(_provider.Calls);
    }

    [Fact]
    public async Task Add_DuplicateNameOrZone_IsRefused()
    {
        await Service().AddAsync(Request());

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().AddAsync(Request() with { ZoneName = "other.net" }));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().AddAsync(Request() with { Name = "Other" }));
    }

    [Fact]
    public async Task List_NeverIncludesTheToken()
    {
        await Service().AddAsync(Request());

        var overview = Assert.Single(await Service().ListAsync());

        Assert.Equal(new DnsProviderOverview("Main", DnsProviderType.Cloudflare, "example.com", ZoneId), overview);
    }

    [Fact]
    public async Task Test_AddsAndRemovesATemporaryRecord()
    {
        await Service().AddAsync(Request());
        _provider.Calls.Clear();

        var message = await Service().TestAsync("main");

        Assert.Contains("_sslense-test.example.com", message, StringComparison.Ordinal);
        Assert.Equal(3, _provider.Calls.Count);
        Assert.StartsWith("add _sslense-test.example.com ", _provider.Calls[1], StringComparison.Ordinal);
        Assert.StartsWith("remove _sslense-test.example.com ", _provider.Calls[2], StringComparison.Ordinal);
        Assert.Empty(_provider.Records);
    }

    [Fact]
    public async Task Test_UnknownProvider_ListsTheAvailableOnes()
    {
        await Service().AddAsync(Request());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().TestAsync("Nope"));

        Assert.Contains("Available: Main", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UpdateToken_VerifiesTheNewToken_ThenSavesItEncrypted_AndKeepsTheRest()
    {
        await Service().AddAsync(Request());
        var before = Assert.Single(_config.Config.DnsProviders);
        _provider.Calls.Clear();

        await Service().UpdateTokenAsync("main", " new-token ");

        var after = Assert.Single(_config.Config.DnsProviders);
        Assert.NotEqual(before.ProtectedToken, after.ProtectedToken);
        Assert.Equal(before with { ProtectedToken = after.ProtectedToken }, after);
        Assert.DoesNotContain("new-token", Encoding.UTF8.GetString(Convert.FromBase64String(after.ProtectedToken)), StringComparison.Ordinal);
        Assert.Equal(["verify Main"], _provider.Calls);
    }

    [Fact]
    public async Task UpdateToken_Rejected_KeepsTheOldToken()
    {
        await Service().AddAsync(Request());
        var before = Assert.Single(_config.Config.DnsProviders);
        _provider.FailVerify = new InvalidOperationException("rejected");

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().UpdateTokenAsync("Main", "bad-token"));

        Assert.Equal(before, Assert.Single(_config.Config.DnsProviders));
    }

    [Fact]
    public async Task UpdateToken_WorksWhileACertificateRenewsThroughTheProvider()
    {
        await Service().AddAsync(Request());
        Managed(Certificate(ValidationMethod.Dns01Provider));

        await Service().UpdateTokenAsync("Main", "new-token");

        Assert.Single(_config.Config.DnsProviders);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task UpdateToken_Empty_IsRefusedBeforeContactingTheProvider(string token)
    {
        await Service().AddAsync(Request());
        _provider.Calls.Clear();

        await Assert.ThrowsAsync<ArgumentException>(() => Service().UpdateTokenAsync("Main", token));

        Assert.Empty(_provider.Calls);
    }

    [Fact]
    public async Task UpdateToken_UnknownProvider_ListsTheAvailableOnes()
    {
        await Service().AddAsync(Request());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().UpdateTokenAsync("Nope", "new-token"));

        Assert.Contains("Available: Main", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Remove_Unused_Removes()
    {
        await Service().AddAsync(Request());

        await Service().RemoveAsync("Main");

        Assert.Empty(_config.Config.DnsProviders);
    }

    [Fact]
    public async Task Remove_ACertificateRenewsThroughIt_IsRefused()
    {
        await Service().AddAsync(Request());
        Managed(Certificate(ValidationMethod.Dns01Provider));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => Service().RemoveAsync("Main"));

        Assert.Contains("Shop", exception.Message, StringComparison.Ordinal);
        Assert.Single(_config.Config.DnsProviders);
    }

    [Fact]
    public async Task Remove_ACertificateDelegatedToIt_IsRefused()
    {
        await Service().AddAsync(Request());
        _lookup.Cnames["_acme-challenge.shop.other.net"] = "shop.acme.example.com";
        Managed(Certificate(ValidationMethod.Dns01Provider) with { Hosts = ["shop.other.net"] });

        await Assert.ThrowsAsync<InvalidOperationException>(() => Service().RemoveAsync("Main"));
    }

    [Theory]
    [InlineData(ValidationMethod.Http01)]
    [InlineData(ValidationMethod.Dns01Manual)]
    public async Task Remove_CertificatesNotUsingAProvider_DoNotBlockIt(ValidationMethod method)
    {
        await Service().AddAsync(Request());
        Managed(Certificate(method));

        await Service().RemoveAsync("Main");

        Assert.Empty(_config.Config.DnsProviders);
    }

    private void Managed(ManagedCertificate certificate) =>
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([certificate]);

    private DnsProviderService Service() => new(_config, _managed.Object, new XorProtector(), [_provider], _lookup);

    private static DnsProviderRequest Request() =>
        new("Main", DnsProviderType.Cloudflare, "Example.com.", ZoneId, Token);

    private static ManagedCertificate Certificate(ValidationMethod method) => new(
        "Shop",
        ["shop.example.com"],
        "admin@example.com",
        "AABB",
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow.AddDays(60),
        ValidationMethod: method);

    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Select(value => (byte)(value ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }
}

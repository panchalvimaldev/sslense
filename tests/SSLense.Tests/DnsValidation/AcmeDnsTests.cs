using System.Net;
using System.Text;
using System.Text.Json;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

/// <summary>DNS validation through an acme-dns account (docs/design/acme-dns.md).</summary>
public sealed class AcmeDnsTests
{
    private const string Server = "https://acme-dns.example.net";
    private const string FullDomain = "d420c923-bbd7-4056-ab64-c3ca54c9b3cf.acme-dns.example.net";
    private static readonly string Value1 = new('a', 43), Value2 = new('b', 43), Value3 = new('c', 43);

    private readonly FakeAcmeDnsServer _server = new();
    private readonly FakeConfigStore _config = new();
    private readonly FakeDnsLookup _lookup = new();
    private readonly XorProtector _protector = new();

    private AcmeDnsClient Client() => new(new HttpClient(_server));

    private AcmeDnsProvider Provider() => new(Client(), _protector);

    private DnsProviderService Service() => new(
        _config,
        Mock.Of<IManagedCertificateStore>(),
        _protector,
        [Provider()],
        _lookup,
        propagation: new DnsPropagationChecker(_lookup, new DnsPropagationOptions
        {
            Timeout = TimeSpan.FromMilliseconds(200),
            PollInterval = TimeSpan.FromMilliseconds(20),
            SettleDelay = TimeSpan.Zero,
            UncheckedWait = TimeSpan.Zero
        }),
        acmeDns: Client());

    private Task<DnsProviderOverview> RegisterAsync(string domain = "Example.com") =>
        Service().AddAcmeDnsAsync(new AcmeDnsProviderRequest("Shop acme-dns", domain, Server));

    // ---- The client ----

    [Fact]
    public async Task Client_Register_ReturnsTheAccount_AndSendsAllowedNetworks()
    {
        var account = await Client().RegisterAsync(new Uri(Server), ["203.0.113.10/32"], CancellationToken.None);

        Assert.Equal(FullDomain, account.FullDomain);
        Assert.Equal("user-1", account.Username);
        Assert.Equal(["203.0.113.10/32"], _server.LastAllowFrom!);
        Assert.StartsWith("SSLense/", _server.LastUserAgent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Client_Update_WithAWrongPassword_SaysTheCredentialsWereRefused()
    {
        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Client().UpdateAsync(new Uri(Server), "user-1", "wrong", "d420c923", Value1, CancellationToken.None))).Message;

        Assert.Contains("refused the account's username or password", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://acme-dns.example.net", "https://acme-dns.example.net/update")]
    [InlineData("https://proxy.example.net/acme-dns", "https://proxy.example.net/acme-dns/update")]
    [InlineData("https://proxy.example.net/acme-dns/", "https://proxy.example.net/acme-dns/update")]
    public void Client_EndpointsGoBelowTheServersPath(string server, string expected) =>
        Assert.Equal(expected, AcmeDnsClient.Endpoint(new Uri(server), "update").AbsoluteUri);

    // ---- The provider ----

    [Fact]
    public async Task Provider_Add_UpdatesTheAccount_AndRemoveChangesNothing()
    {
        var profile = (await RegisterAsync()).Name;
        var saved = _config.Config.DnsProviders.Single(value => value.Name == profile);

        await Provider().AddTxtRecordAsync(saved, FullDomain, Value1, CancellationToken.None);
        await Provider().RemoveTxtRecordAsync(saved, FullDomain, Value1, CancellationToken.None);

        Assert.Equal([Value1], _server.Values);
    }

    [Fact]
    public async Task Provider_OnlyItsOwnNameAndRealValues()
    {
        await RegisterAsync();
        var saved = _config.Config.DnsProviders.Single();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Provider().AddTxtRecordAsync(saved, "_acme-challenge.example.com", Value1, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Provider().AddTxtRecordAsync(saved, FullDomain, "too-short", CancellationToken.None));
        Assert.Empty(_server.Values);
    }

    // ---- Adding an account ----

    [Fact]
    public async Task Register_SavesTheAccountForItsDomain_WithThePasswordEncrypted_AndShowsTheCname()
    {
        var added = await RegisterAsync("*.Example.com.");

        var saved = Assert.Single(_config.Config.DnsProviders);
        Assert.Equal(DnsProviderType.AcmeDns, saved.Provider);
        Assert.Equal(FullDomain, saved.ZoneName);
        Assert.Equal("example.com", saved.AcmeDnsDomain);
        Assert.Equal("user-1", saved.AcmeDnsUsername);
        Assert.DoesNotContain(FakeAcmeDnsServer.Password, saved.ProtectedToken, StringComparison.Ordinal);
        Assert.Equal($"_acme-challenge.example.com  CNAME  {FullDomain}", added.AcmeDnsCname);
    }

    [Fact]
    public async Task Import_UsesAnExistingAccount_AfterAHealthCheck_WithoutRegistering()
    {
        await Service().AddAcmeDnsAsync(new AcmeDnsProviderRequest(
            "Imported", "example.com", Server,
            Import: new AcmeDnsAccount("user-9", "imported-password", "abc", "ABC.acme-dns.example.net.")));

        var saved = Assert.Single(_config.Config.DnsProviders);
        Assert.Equal("abc.acme-dns.example.net", saved.ZoneName);
        Assert.Equal(0, _server.Registrations);
        Assert.Equal(1, _server.HealthChecks);
    }

    [Theory]
    [InlineData("example.com", "http://acme-dns.example.net", null)]
    [InlineData("not a domain", Server, null)]
    [InlineData("example.com", Server, "not-a-network")]
    public async Task Add_InvalidInput_IsRefusedBeforeContactingTheServer(string domain, string server, string? allowFrom)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => Service().AddAcmeDnsAsync(
            new AcmeDnsProviderRequest("Shop", domain, server, allowFrom is null ? null : [allowFrom])));

        Assert.Equal(0, _server.Registrations);
    }

    [Fact]
    public async Task Add_ASecondAccountForTheSameDomain_IsRefused()
    {
        await RegisterAsync();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service().AddAcmeDnsAsync(new AcmeDnsProviderRequest("Another", "example.com", Server)));

        Assert.Single(_config.Config.DnsProviders);
    }

    [Fact]
    public async Task Add_AnAcmeDnsProviderThroughTheTokenPath_IsRefused() =>
        await Assert.ThrowsAsync<ArgumentException>(() => Service().AddAsync(
            new DnsProviderRequest("Shop", DnsProviderType.AcmeDns, "example.com", null, "token")));

    // ---- Testing ----

    [Fact]
    public async Task Test_WithoutTheCname_SaysWhichRecordToCreate()
    {
        await RegisterAsync();

        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() => Service().TestAsync("Shop acme-dns"))).Message;

        Assert.Contains($"_acme-challenge.example.com  CNAME  {FullDomain}", message, StringComparison.Ordinal);
        Assert.Empty(_server.Values);
    }

    [Fact]
    public async Task Test_WithTheCname_UpdatesTheAccount_AndWaitsForItsNameServers()
    {
        await RegisterAsync();
        _lookup.Cnames["_acme-challenge.example.com"] = FullDomain;
        _lookup.Answer = (_, name) => name == FullDomain ? _server.Values : [];

        var message = await Service().TestAsync("Shop acme-dns");

        Assert.Contains("points to the account", message, StringComparison.Ordinal);
        Assert.Equal(43, Assert.Single(_server.Values).Length);
    }

    // ---- Before each order, and daily ----

    private DnsChallengeService Challenges() => new(
        _config,
        [Provider()],
        _lookup,
        new FakeDnsChallengeJournal(),
        new DnsPropagationChecker(_lookup));

    [Fact]
    public async Task BeforeOrder_AMissingCname_IsReportedWithTheRecordToCreate()
    {
        await RegisterAsync();

        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() => Challenges().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["*.example.com", "example.com"], CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None))).Message;

        Assert.Contains("CNAME", message, StringComparison.Ordinal);
        Assert.Contains(FullDomain, message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BeforeOrder_ANameAndItsWildcard_FitInOneAccount()
    {
        await RegisterAsync();
        _lookup.Cnames["_acme-challenge.example.com"] = FullDomain;

        await Challenges().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["*.example.com", "example.com"], CertificateAuthorities.LetsEncryptStagingId, CancellationToken.None);

        Assert.Equal(1, _server.HealthChecks);
    }

    [Fact]
    public async Task BeforeOrder_ThreeValuesForOneAccount_AreRefused_BeforeAnyUpdate()
    {
        await RegisterAsync();
        foreach (var name in new[] { "example.com", "shop.example.com", "blog.example.com" })
        {
            _lookup.Cnames[$"_acme-challenge.{name}"] = FullDomain;
        }

        var message = (await Assert.ThrowsAsync<InvalidOperationException>(() => Challenges().CheckBeforeOrderAsync(
            ValidationMethod.Dns01Provider, ["example.com", "shop.example.com", "blog.example.com"], CertificateAuthorities.LetsEncryptStagingId,
            CancellationToken.None))).Message;

        Assert.Contains("keeps only two", message, StringComparison.Ordinal);
        Assert.Empty(_server.Values);
    }

    [Fact]
    public async Task Server_KeepsOnlyTheTwoNewestValues_AsAcmeDnsDoes()
    {
        await RegisterAsync();
        var saved = _config.Config.DnsProviders.Single();

        foreach (var value in new[] { Value1, Value2, Value3 })
        {
            await Provider().AddTxtRecordAsync(saved, FullDomain, value, CancellationToken.None);
        }

        Assert.Equal([Value2, Value3], _server.Values);
    }

    [Fact]
    public async Task Config_KeepsTheAccount()
    {
        var files = new InMemoryFileSystem();
        var store = new JsonConfigStore(files, @"C:\data\config.json");
        var profile = new DnsProviderProfile(
            "Shop acme-dns", DnsProviderType.AcmeDns, FullDomain, null, "protected",
            AcmeDnsServer: new Uri(Server), AcmeDnsUsername: "user-1", AcmeDnsSubdomain: "d420c923", AcmeDnsDomain: "example.com");

        await store.SaveAsync(new AppConfig { DnsProviders = [profile] });

        Assert.Equal(profile, Assert.Single((await store.LoadAsync()).DnsProviders));
    }

    /// <summary>Behaves like acme-dns: accounts, credentials checked, 43-character values, the two newest kept.</summary>
    private sealed class FakeAcmeDnsServer : HttpMessageHandler
    {
        public const string Password = "server-password-1";

        public List<string> Values { get; } = [];

        public int Registrations { get; private set; }

        public int HealthChecks { get; private set; }

        public string[]? LastAllowFrom { get; private set; }

        public string? LastUserAgent { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastUserAgent = request.Headers.UserAgent.ToString();
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            switch (request.RequestUri!.AbsolutePath)
            {
                case "/register":
                    Registrations++;
                    LastAllowFrom = body.Length == 0 ? null : JsonDocument.Parse(body).RootElement.GetProperty("allowfrom").EnumerateArray().Select(value => value.GetString()!).ToArray();
                    return Json(HttpStatusCode.Created, new { username = "user-1", password = Password, subdomain = "d420c923", fulldomain = FullDomain, allowfrom = LastAllowFrom ?? [] });
                case "/update":
                    if (request.Headers.GetValues("X-Api-User").Single() != "user-1" || request.Headers.GetValues("X-Api-Key").Single() != Password)
                    {
                        return Json(HttpStatusCode.Unauthorized, new { error = "unauthorized" });
                    }

                    var txt = JsonDocument.Parse(body).RootElement.GetProperty("txt").GetString()!;
                    if (txt.Length != 43)
                    {
                        return Json(HttpStatusCode.BadRequest, new { error = "bad_txt" });
                    }

                    Values.Add(txt);
                    if (Values.Count > 2)
                    {
                        Values.RemoveAt(0);
                    }

                    return Json(HttpStatusCode.OK, new { txt });
                case "/health":
                    HealthChecks++;
                    return new HttpResponseMessage(HttpStatusCode.OK);
                default:
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
        }

        private static HttpResponseMessage Json(HttpStatusCode status, object value) =>
            new(status) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
    }

    private sealed class XorProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Select(value => (byte)(value ^ 0x5A))];

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SSLense.Core.Acme;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

/// <summary>
/// The built-in DNS providers (docs/design/dns-providers.md), against a fake service that records each request. They are
/// labelled untested until each has run on a real account; these tests pin the requests to each service's documented API.
/// </summary>
public sealed class BuiltInDnsProviderTests
{
    private const string Record = "_acme-challenge.www.example.com";

    [Fact]
    public void SignatureV4_MatchesAwsPublishedExample()
    {
        // AWS Signature Version 4 test suite, "get-vanilla".
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.amazonaws.com/");
        AwsSignatureV4.Sign(request, string.Empty, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service",
            new DateTimeOffset(2015, 8, 30, 12, 36, 0, TimeSpan.Zero));

        Assert.Equal("20150830T123600Z", request.Headers.GetValues("x-amz-date").Single());
        Assert.Equal(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, " +
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            request.Headers.GetValues("Authorization").Single());
    }

    [Fact]
    public async Task Route53_AddsToTheRecordSet_AndDeletesItWithTheLastValue()
    {
        var service = new FakeService(request => request.Method == HttpMethod.Get
            ? Xml("""<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>_acme-challenge.www.example.com.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>"other"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>""")
            : Xml("<ChangeResourceRecordSetsResponse/>"));
        var provider = new Route53DnsProvider(service.Client, Protector) { Clock = () => new DateTimeOffset(2026, 11, 19, 0, 0, 0, TimeSpan.Zero) };
        var profile = Profile(DnsProviderType.Route53, "Z0123456789", "AKIDTEST:secret");

        await provider.AddTxtRecordAsync(profile, Record, "new", CancellationToken.None);
        await provider.RemoveTxtRecordAsync(profile, Record, "other", CancellationToken.None);

        var add = service.Requests[1];
        Assert.Equal("POST https://route53.amazonaws.com/2013-04-01/hostedzone/Z0123456789/rrset", add.Line);
        Assert.Contains("<Action>UPSERT</Action>", add.Body, StringComparison.Ordinal);
        Assert.Contains("<Value>\"other\"</Value>", add.Body, StringComparison.Ordinal);
        Assert.Contains("<Value>\"new\"</Value>", add.Body, StringComparison.Ordinal);
        Assert.StartsWith("AWS4-HMAC-SHA256 Credential=AKIDTEST/20261119/us-east-1/route53/aws4_request", add.Authorization, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", add.Authorization, StringComparison.Ordinal);
        Assert.Contains("<Action>DELETE</Action>", service.Requests[3].Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AzureDns_SignsIn_ThenWritesTheWholeRecordSet()
    {
        var existing = false;
        var service = new FakeService(request => request.RequestUri!.Host == "login.microsoftonline.com"
            ? Json("""{"access_token":"azure-token"}""")
            : request.Method == HttpMethod.Get
                ? existing ? Json("""{"properties":{"TXTRecords":[{"value":["other"]}]}}""") : new HttpResponseMessage(HttpStatusCode.NotFound)
                : Json("{}"));
        var provider = new AzureDnsProvider(service.Client, Protector);
        var profile = Profile(DnsProviderType.AzureDns, "11111111-1111-1111-1111-111111111111/dns-rg",
            "22222222-2222-2222-2222-222222222222:33333333-3333-3333-3333-333333333333:client-secret");

        await provider.AddTxtRecordAsync(profile, Record, "new", CancellationToken.None);
        existing = true;
        await provider.AddTxtRecordAsync(profile, Record, "new", CancellationToken.None);

        var signIn = service.Requests[0];
        Assert.Equal("POST https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/oauth2/v2.0/token", signIn.Line);
        Assert.Contains("grant_type=client_credentials", signIn.Body, StringComparison.Ordinal);
        Assert.Contains("scope=https%3A%2F%2Fmanagement.azure.com%2F.default", signIn.Body, StringComparison.Ordinal);
        var put = service.Requests.First(request => request.Method == "PUT");
        Assert.Equal(
            "PUT https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/dns-rg/providers/Microsoft.Network/dnsZones/example.com/TXT/_acme-challenge.www?api-version=2018-05-01",
            put.Line);
        Assert.Equal("Bearer azure-token", put.Authorization);
        Assert.Contains("\"value\":[\"new\"]", put.Body, StringComparison.Ordinal);
        Assert.Equal(2, service.Requests.Count(request => request.Method == "PUT"));
        Assert.Contains("\"value\":[\"other\"]", service.Requests.Last(request => request.Method == "PUT").Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GoogleCloudDns_SignsAJwtWithTheServiceAccount_AndReplacesTheRecordSetInOneChange()
    {
        using var key = RSA.Create(2048);
        var json = JsonSerializer.Serialize(new { client_email = "sslense@project.iam.gserviceaccount.com", private_key = key.ExportPkcs8PrivateKeyPem(), project_id = "my-project" });
        var service = new FakeService(request => request.RequestUri!.Host == "oauth2.googleapis.com"
            ? Json("""{"access_token":"google-token"}""")
            : request.Method == HttpMethod.Get
                ? Json("""{"rrsets":[{"name":"_acme-challenge.www.example.com.","type":"TXT","ttl":300,"rrdatas":["\"other\""]}]}""")
                : Json("{}"));
        var provider = new GoogleCloudDnsProvider(service.Client, Protector);

        await provider.AddTxtRecordAsync(Profile(DnsProviderType.GoogleCloudDns, "example-com", json), Record, "new", CancellationToken.None);

        var assertion = Uri.UnescapeDataString(service.Requests[0].Body.Split("assertion=")[1]);
        var parts = assertion.Split('.');
        Assert.True(key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Base64Url(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        using var claims = JsonDocument.Parse(Base64Url(parts[1]));
        Assert.Equal("sslense@project.iam.gserviceaccount.com", claims.RootElement.GetProperty("iss").GetString());
        Assert.Equal("https://www.googleapis.com/auth/ndev.clouddns.readwrite", claims.RootElement.GetProperty("scope").GetString());
        var change = service.Requests[3];
        Assert.Equal("POST https://dns.googleapis.com/dns/v1/projects/my-project/managedZones/example-com/changes", change.Line);
        using var body = JsonDocument.Parse(change.Body);
        Assert.Equal(["\"other\""], body.RootElement.GetProperty("deletions")[0].GetProperty("rrdatas").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(["\"other\"", "\"new\""], body.RootElement.GetProperty("additions")[0].GetProperty("rrdatas").EnumerateArray().Select(value => value.GetString()));
        Assert.Equal(300, body.RootElement.GetProperty("additions")[0].GetProperty("ttl").GetInt32());
    }

    [Fact]
    public async Task DigitalOcean_AddsARecord_AndRemovesOnlyTheOneWithTheValue()
    {
        var service = new FakeService(request => request.Method == HttpMethod.Get
            ? Json("""{"domain_records":[{"id":11,"data":"other"},{"id":12,"data":"new"}]}""")
            : Json("{}"));
        var provider = new DigitalOceanDnsProvider(service.Client, Protector);
        var profile = Profile(DnsProviderType.DigitalOcean, null, "do-token");

        await provider.AddTxtRecordAsync(profile, Record, "third", CancellationToken.None);
        await provider.RemoveTxtRecordAsync(profile, Record, "new", CancellationToken.None);

        Assert.Equal("POST https://api.digitalocean.com/v2/domains/example.com/records", service.Requests[1].Line);
        Assert.Contains("\"name\":\"_acme-challenge.www\"", service.Requests[1].Body, StringComparison.Ordinal);
        Assert.Equal("Bearer do-token", service.Requests[1].Authorization);
        Assert.Equal("DELETE https://api.digitalocean.com/v2/domains/example.com/records/12", service.Requests[3].Line);
    }

    [Fact]
    public async Task Hetzner_AddsAndRemovesRecordsInTheRecordSet()
    {
        var service = new FakeService(_ => Json("{}"));
        var provider = new HetznerDnsProvider(service.Client, Protector);
        var profile = Profile(DnsProviderType.Hetzner, null, "hetzner-token");

        await provider.AddTxtRecordAsync(profile, Record, "new", CancellationToken.None);
        await provider.RemoveTxtRecordAsync(profile, Record, "new", CancellationToken.None);

        Assert.Equal("POST https://api.hetzner.cloud/v1/zones/example.com/rrsets/_acme-challenge.www/TXT/actions/add_records", service.Requests[0].Line);
        Assert.Contains("\"value\":\"\\u0022new\\u0022\"", service.Requests[0].Body, StringComparison.Ordinal);
        Assert.Equal("POST https://api.hetzner.cloud/v1/zones/example.com/rrsets/_acme-challenge.www/TXT/actions/remove_records", service.Requests[1].Line);
    }

    [Fact]
    public async Task ARefusal_NamesTheServiceAndPermission_WithoutTheSecret()
    {
        var service = new FakeService(_ => new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("Forbidden: token secret-token not allowed") });
        var provider = new DigitalOceanDnsProvider(service.Client, Protector);

        var exception = await Assert.ThrowsAsync<SSLense.Core.Errors.SslenseException>(() =>
            provider.VerifyAccessAsync(Profile(DnsProviderType.DigitalOcean, null, "do-token"), CancellationToken.None));

        Assert.Equal("SSL3039", exception.Code);
        Assert.Contains("DigitalOcean could not read the domain", exception.Message, StringComparison.Ordinal);
        Assert.Contains("read and write access to Domains", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("do-token", exception.Message, StringComparison.Ordinal);
    }

    private static readonly ISecretProtector Protector = new PrefixProtector();

    private static DnsProviderProfile Profile(DnsProviderType type, string? zoneId, string secret) =>
        new("test", type, "example.com", zoneId, Convert.ToBase64String(Protector.Protect(Encoding.UTF8.GetBytes(secret))));

    private static HttpResponseMessage Json(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Xml(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/xml") };

    private static byte[] Base64Url(string value) =>
        Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight(value.Length + (4 - value.Length % 4) % 4, '='));

    private sealed record Sent(string Method, string Line, string Body, string? Authorization);

    private sealed class FakeService(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<Sent> Requests { get; } = [];

        public HttpClient Client => new(this);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            var authorization = request.Headers.TryGetValues("Authorization", out var values) ? values.Single() : null;
            Requests.Add(new Sent(request.Method.Method, $"{request.Method} {request.RequestUri}", body, authorization));
            return answer(request);
        }
    }

    private sealed class PrefixProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [1, .. plaintext];

        public byte[] Unprotect(byte[] protectedData) => protectedData[1..];
    }
}

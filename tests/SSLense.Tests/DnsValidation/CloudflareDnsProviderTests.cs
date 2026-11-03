using System.Net;
using System.Text;
using SSLense.Core.Acme;
using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class CloudflareDnsProviderTests
{
    private const string Token = "plain-cloudflare-token";
    private const string ZoneId = "0123456789abcdef0123456789abcdef";
    private const string RecordName = "_acme-challenge.example.com";
    private const string Success = """{"success":true,"errors":[],"result":{}}""";
    private readonly RecordingHandler _handler = new();

    [Fact]
    public async Task Add_SendsTheRecordWithTheTokenOnTheRequestOnly()
    {
        _handler.Respond(HttpStatusCode.OK, Success);
        using var client = new HttpClient(_handler);

        await Provider(client).AddTxtRecordAsync(Profile(), RecordName, "value", CancellationToken.None);

        var request = Assert.Single(_handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal($"https://api.cloudflare.com/client/v4/zones/{ZoneId}/dns_records", request.Url);
        Assert.Equal($"Bearer {Token}", request.Authorization);
        Assert.Contains("\"type\":\"TXT\"", request.Body, StringComparison.Ordinal);
        Assert.Contains($"\"name\":\"{RecordName}\"", request.Body, StringComparison.Ordinal);
        Assert.Contains("\"content\":\"value\"", request.Body, StringComparison.Ordinal);
        Assert.Null(client.DefaultRequestHeaders.Authorization);
    }

    [Fact]
    public async Task Add_AnIdenticalRecordAlreadyThere_Succeeds()
    {
        _handler.Respond(
            HttpStatusCode.BadRequest,
            """{"success":false,"errors":[{"code":81058,"message":"An identical record already exists."}],"result":null}""");
        using var client = new HttpClient(_handler);

        await Provider(client).AddTxtRecordAsync(Profile(), RecordName, "value", CancellationToken.None);
    }

    [Fact]
    public async Task Add_Rejected_ExplainsThePermissionWithoutTheToken()
    {
        _handler.Respond(
            HttpStatusCode.Forbidden,
            """{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}""");
        using var client = new HttpClient(_handler);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Provider(client).AddTxtRecordAsync(Profile(), RecordName, "value", CancellationToken.None));

        Assert.Contains("HTTP 403", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Authentication error", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Zone > DNS > Edit", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Token, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Remove_DeletesOnlyTheExactValue_IncludingAQuotedOne()
    {
        _handler.Respond(HttpStatusCode.OK, """
            {"success":true,"errors":[],"result":[
              {"id":"keep1","content":"someone-elses-value"},
              {"id":"keep2","content":"VALUE"},
              {"id":"delete1","content":"value"},
              {"id":"delete2","content":"\"value\""}
            ]}
            """);
        _handler.Respond(HttpStatusCode.OK, Success);
        _handler.Respond(HttpStatusCode.OK, Success);
        using var client = new HttpClient(_handler);

        await Provider(client).RemoveTxtRecordAsync(Profile(), RecordName, "value", CancellationToken.None);

        Assert.Equal(
            [
                $"GET https://api.cloudflare.com/client/v4/zones/{ZoneId}/dns_records?type=TXT&per_page=100&name={RecordName}",
                $"DELETE https://api.cloudflare.com/client/v4/zones/{ZoneId}/dns_records/delete1",
                $"DELETE https://api.cloudflare.com/client/v4/zones/{ZoneId}/dns_records/delete2"
            ],
            _handler.Requests.Select(request => $"{request.Method} {request.Url}"));
    }

    [Fact]
    public async Task Remove_NothingThere_Succeeds()
    {
        _handler.Respond(HttpStatusCode.OK, """{"success":true,"errors":[],"result":[]}""");
        using var client = new HttpClient(_handler);

        await Provider(client).RemoveTxtRecordAsync(Profile(), RecordName, "value", CancellationToken.None);

        Assert.Single(_handler.Requests);
    }

    [Fact]
    public async Task Verify_OnlyReads()
    {
        _handler.Respond(HttpStatusCode.OK, """{"success":true,"errors":[],"result":[]}""");
        using var client = new HttpClient(_handler);

        await Provider(client).VerifyAccessAsync(Profile(), CancellationToken.None);

        Assert.Equal(HttpMethod.Get, Assert.Single(_handler.Requests).Method);
    }

    [Fact]
    public async Task Verify_NotJson_FailsWithAClearMessage()
    {
        _handler.Respond(HttpStatusCode.BadGateway, "<html>Bad gateway</html>");
        using var client = new HttpClient(_handler);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Provider(client).VerifyAccessAsync(Profile(), CancellationToken.None));

        Assert.Contains("HTTP 502", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UndecryptableToken_SaysToAddTheProviderAgain()
    {
        using var client = new HttpClient(_handler);
        var provider = new CloudflareDnsProvider(client, new PrefixProtector());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            provider.VerifyAccessAsync(Profile() with { ProtectedToken = "not base64!" }, CancellationToken.None));

        Assert.Contains("add it again", exception.Message, StringComparison.Ordinal);
        Assert.Empty(_handler.Requests);
    }

    private static CloudflareDnsProvider Provider(HttpClient client) => new(client, new PrefixProtector());

    private static DnsProviderProfile Profile() => new(
        "Main",
        DnsProviderType.Cloudflare,
        "example.com",
        ZoneId,
        Convert.ToBase64String(new PrefixProtector().Protect(Encoding.UTF8.GetBytes(Token))));

    private sealed class PrefixProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [1, .. plaintext];

        public byte[] Unprotect(byte[] protectedData) => protectedData[1..];
    }

    private sealed record SentRequest(HttpMethod Method, string Url, string? Authorization, string Body);

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Queue<(HttpStatusCode Status, string Body)> _responses = new();

        public List<SentRequest> Requests { get; } = [];

        public void Respond(HttpStatusCode status, string body) => _responses.Enqueue((status, body));

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(new SentRequest(
                request.Method,
                request.RequestUri!.ToString(),
                request.Headers.Authorization?.ToString(),
                request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken)));
            var (status, body) = _responses.Dequeue();
            return new HttpResponseMessage(status) { Content = new StringContent(body) };
        }
    }
}

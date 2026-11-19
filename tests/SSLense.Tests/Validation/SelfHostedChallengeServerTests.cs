using System.Net;
using System.Net.Sockets;
using SSLense.Core.Acme;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Validation;

/// <summary>SSLense answering HTTP-01 itself (docs/design/self-hosted-http-validation.md), on a localhost port.</summary>
public sealed class SelfHostedChallengeServerTests : IDisposable
{
    private readonly int _port = FreePort();
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly SelfHostedChallengeServer _server;

    public SelfHostedChallengeServerTests() =>
        _server = new SelfHostedChallengeServer($"http://localhost:{_port}/.well-known/acme-challenge/");

    [Fact]
    public async Task AChallenge_IsAnsweredWhileItIsServed_AndNothingElseIs()
    {
        await using (await _server.ServeAsync(new AcmeHttpChallenge("shop.example.com", "token-1", "token-1.thumbprint"), CancellationToken.None))
        {
            Assert.Equal("token-1.thumbprint", await _http.GetStringAsync(Url("token-1")));
            Assert.Equal(HttpStatusCode.NotFound, (await _http.GetAsync(Url("other"))).StatusCode);
        }

        // Stopped once nothing is served: nothing answers. A fresh client, so no pooled connection is reused.
        using var fresh = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        await Assert.ThrowsAnyAsync<Exception>(() => fresh.GetStringAsync(Url("token-1")));
    }

    [Fact]
    public async Task TwoChallengesAtOnce_EachIsAnswered_UntilItIsReleased()
    {
        var first = await _server.ServeAsync(new AcmeHttpChallenge("a.example.com", "a", "a.key"), CancellationToken.None);
        await using (await _server.ServeAsync(new AcmeHttpChallenge("b.example.com", "b", "b.key"), CancellationToken.None))
        {
            await first.DisposeAsync();
            await first.DisposeAsync();

            Assert.Equal(HttpStatusCode.NotFound, (await _http.GetAsync(Url("a"))).StatusCode);
            Assert.Equal("b.key", await _http.GetStringAsync(Url("b")));
        }
    }

    [Fact]
    public async Task ThePortCanBeChecked_WithoutKeepingItOpen()
    {
        Assert.Null(_server.CheckAvailable());

        using var blocker = new SelfHostedChallengeServer($"http://localhost:{_port}/.well-known/acme-challenge/");
        var serving = await blocker.ServeAsync(new AcmeHttpChallenge("x", "x", "x"), CancellationToken.None);
        var problem = _server.CheckAvailable();
        await serving.DisposeAsync();

        Assert.NotNull(problem);
        Assert.StartsWith("SSL1028: ", problem, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        _server.Dispose();
        _http.Dispose();
    }

    private Uri Url(string token) => new($"http://localhost:{_port}/.well-known/acme-challenge/{token}");

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

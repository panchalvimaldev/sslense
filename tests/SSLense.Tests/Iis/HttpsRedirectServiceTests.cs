using System.Net;
using Moq;
using SSLense.Core.Errors;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Iis;

/// <summary>The HTTP-to-HTTPS redirect helper (docs/design/https-redirect.md).</summary>
public sealed class HttpsRedirectServiceTests
{
    private readonly Mock<IIisService> _iis = new();
    private readonly List<bool> _set = [];

    public HttpsRedirectServiceTests()
    {
        _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new IisSite(1, "Shop", "Started", @"C:\inetpub\shop",
            [
                new IisBinding("http", "*", 80, "shop.example.com", null, null, false),
                new IisBinding("https", "*", 443, "shop.example.com", "AA", "My", true)
            ]),
            new IisSite(2, "Plain", "Started", @"C:\inetpub\plain", [new IisBinding("http", "*", 80, "plain.example.com", null, null, false)])
        ]);
        _iis.Setup(value => value.GetHttpsRedirectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(HttpsRedirectState.Off);
        _iis.Setup(value => value.SetHttpsRedirectAsync(It.IsAny<string>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<string, bool, CancellationToken>((_, enabled, _) => _set.Add(enabled))
            .Returns(Task.CompletedTask);
    }

    [Fact]
    public async Task Enabling_AddsTheRule_AndConfirmsTheSiteRedirectsButValidationDoesNot()
    {
        var service = Service(path => path.StartsWith("/.well-known/", StringComparison.Ordinal) ? HttpStatusCode.NotFound : HttpStatusCode.MovedPermanently);

        var message = await service.EnableAsync("Shop/www.example.com");

        Assert.Equal([true], _set);
        Assert.Contains("confirmed for shop.example.com", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARedirectedChallengePath_RemovesTheRuleAgain()
    {
        var service = Service(_ => HttpStatusCode.MovedPermanently);

        var exception = await Assert.ThrowsAsync<SslenseException>(() => service.EnableAsync("Shop"));

        Assert.Equal("SSL1031", exception.Code);
        Assert.Equal([true, false], _set);
    }

    [Fact]
    public async Task WithoutUrlRewrite_OrWithoutHttps_NothingIsChanged()
    {
        Assert.Equal("SSL1030", (await Assert.ThrowsAsync<SslenseException>(() => Service(_ => HttpStatusCode.OK).EnableAsync("Plain"))).Code);

        _iis.Setup(value => value.GetHttpsRedirectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(HttpsRedirectState.UrlRewriteMissing);
        Assert.Equal("SSL1029", (await Assert.ThrowsAsync<SslenseException>(() => Service(_ => HttpStatusCode.OK).EnableAsync("Shop"))).Code);
        Assert.Empty(_set);
    }

    [Fact]
    public async Task Disabling_RemovesOnlyARuleThatIsThere()
    {
        await Service(_ => HttpStatusCode.OK).DisableAsync("Shop");
        Assert.Empty(_set);

        _iis.Setup(value => value.GetHttpsRedirectAsync("Shop", It.IsAny<CancellationToken>())).ReturnsAsync(HttpsRedirectState.On);
        await Service(_ => HttpStatusCode.OK).DisableAsync("Shop");
        Assert.Equal([false], _set);
    }

    private HttpsRedirectService Service(Func<string, HttpStatusCode> answer) => new(_iis.Object, new FakeSite(answer));

    private sealed class FakeSite(Func<string, HttpStatusCode> answer) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(answer(request.RequestUri!.AbsolutePath)));
    }
}

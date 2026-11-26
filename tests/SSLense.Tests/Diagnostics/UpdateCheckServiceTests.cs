using System.Net;
using System.Text;
using Moq;
using SSLense.Core.Config;
using SSLense.Core.Diagnostics;
using Xunit;

namespace SSLense.Tests.Diagnostics;

/// <summary>The new-version notice (docs/design/version-notice.md).</summary>
public sealed class UpdateCheckServiceTests
{
    private const string Releases = """
        [
          {"tag_name":"v0.26.0","html_url":"https://github.com/x/releases/tag/v0.26.0","draft":true,"prerelease":false},
          {"tag_name":"v0.25.1","html_url":"https://github.com/x/releases/tag/v0.25.1","draft":false,"prerelease":true},
          {"tag_name":"v0.24.0","html_url":"https://github.com/x/releases/tag/v0.24.0","draft":false,"prerelease":true},
          {"tag_name":"nightly","html_url":"https://github.com/x/releases/tag/nightly","draft":false,"prerelease":true}
        ]
        """;

    [Fact]
    public async Task ANewerRelease_IsReported_IgnoringDraftsAndOddTags()
    {
        var handler = new Answer(HttpStatusCode.OK, Releases);
        var update = await Service(handler, "0.24.0").CheckAsync();

        Assert.NotNull(update);
        Assert.Equal("0.25.1", update.LatestVersion);
        Assert.True(update.IsPrerelease);
        Assert.Equal("https://github.com/x/releases/tag/v0.25.1", update.ReleaseUrl.ToString());
        Assert.StartsWith("SSLense/0.24.0", handler.UserAgent, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("0.25.1")]
    [InlineData("0.30.0")]
    public async Task TheCurrentOrANewerVersion_HasNothingToReport(string current) =>
        Assert.Null(await Service(new Answer(HttpStatusCode.OK, Releases), current).CheckAsync());

    [Fact]
    public async Task WhenTurnedOff_GitHubIsNotAsked()
    {
        var handler = new Answer(HttpStatusCode.OK, Releases);

        Assert.Null(await Service(handler, "0.1.0", enabled: false).CheckAsync());
        Assert.Equal(0, handler.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WhetherTheCheckIsOn_IsReported_SoOffIsNotMistakenForUpToDate(bool enabled)
    {
        // Found in the combined test: 'version' said "No newer release was found, or the check is off" either way.
        Assert.Equal(enabled, await Service(new Answer(HttpStatusCode.OK, Releases), "0.1.0", enabled).IsOnAsync());
    }

    [Fact]
    public async Task AnUnreachableOrOddAnswer_IsNeverAnError()
    {
        Assert.Null(await Service(new Answer(HttpStatusCode.Forbidden, "rate limited"), "0.1.0").CheckAsync());
        Assert.Null(await Service(new Answer(HttpStatusCode.OK, "{\"message\":\"moved\"}"), "0.1.0").CheckAsync());
        Assert.Null(await Service(new Answer(null, string.Empty), "0.1.0").CheckAsync());
    }

    private static UpdateCheckService Service(HttpMessageHandler handler, string current, bool enabled = true) =>
        new(Mock.Of<IConfigStore>(value => value.LoadAsync(It.IsAny<CancellationToken>()) == Task.FromResult(new AppConfig { CheckForUpdates = enabled })),
            handler, current);

    private sealed class Answer(HttpStatusCode? status, string body) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        public string UserAgent { get; private set; } = string.Empty;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            UserAgent = request.Headers.UserAgent.ToString();
            return status is { } code
                ? Task.FromResult(new HttpResponseMessage(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") })
                : Task.FromException<HttpResponseMessage>(new HttpRequestException("No route to host."));
        }
    }
}

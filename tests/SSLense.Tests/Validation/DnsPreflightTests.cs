using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using SSLense.Tests.DnsValidation;
using Xunit;

namespace SSLense.Tests.Validation;

public sealed class DnsPreflightTests
{
    private readonly FakeDnsChecks _dns = new();
    private readonly Mock<IIisService> _iis = new();
    private readonly Mock<IFileSystem> _files = new(MockBehavior.Strict);

    public DnsPreflightTests()
    {
        _iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new IisSite(1, "Shop", "Started", null, [
                new IisBinding("https", "*", 443, "shop.example.com", null, null, true),
                new IisBinding("http", "*", 8080, "example.com", null, null, false),
                new IisBinding("ftp", "*", 21, "ftp.example.com", null, null, false)
            ])]);
    }

    [Fact]
    public async Task HostsOnAnyHttpPort_PassWithoutPort80OrAFolder_AndTheNamesAreChecked()
    {
        var results = await Check(["shop.example.com", "example.com"], ["*.example.com", "example.com"], ValidationMethod.Dns01Provider);

        Assert.All(results.Where(check => check.Name != "Administrator"), check => Assert.True(check.Succeeded, check.Message));
        Assert.Equal(["Dns01Provider *.example.com,example.com letsencrypt-staging"], _dns.Checked);
        _files.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task WithoutNames_TheHostsAreChecked()
    {
        await Check(["shop.example.com"], null, ValidationMethod.Dns01Manual);

        Assert.Equal(["Dns01Manual shop.example.com letsencrypt-staging"], _dns.Checked);
    }

    [Fact]
    public async Task InvalidNames_FailWithoutCheckingDns()
    {
        var results = await Check(["shop.example.com"], ["*.com"], ValidationMethod.Dns01Provider);

        Assert.False(Assert.Single(results, check => check.Name == "Certificate names").Succeeded);
        Assert.Empty(_dns.Checked);
    }

    [Theory]
    [InlineData("other.example.com", "Add an IIS HTTP or HTTPS binding")]
    [InlineData("ftp.example.com", "Add an IIS HTTP or HTTPS binding")]
    [InlineData("*.example.com", "real host names")]
    public async Task AHostThatCannotBeBound_Fails(string host, string message)
    {
        var results = await Check([host], ["*.example.com"], ValidationMethod.Dns01Provider);

        var check = Assert.Single(results, value => value.Name == $"IIS binding: {host}");
        Assert.False(check.Succeeded);
        Assert.Contains(message, check.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AHostTheNamesDoNotCover_Fails()
    {
        var results = await Check(["example.com"], ["*.example.com"], ValidationMethod.Dns01Provider);

        Assert.Contains("do not cover", Assert.Single(results, value => value.Name == "IIS binding: example.com").Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(typeof(InvalidOperationException))]
    [InlineData(typeof(HttpRequestException))]
    public async Task ADnsProblem_IsAFailedCheckNotAnException(Type exceptionType)
    {
        _dns.Fail = (Exception)Activator.CreateInstance(exceptionType, "No DNS provider manages it.")!;

        var results = await Check(["shop.example.com"], null, ValidationMethod.Dns01Provider);

        var check = Assert.Single(results, value => value.Name == "DNS validation");
        Assert.False(check.Succeeded);
        Assert.Equal("No DNS provider manages it.", check.Message);
    }

    private async Task<IReadOnlyList<PreflightCheck>> Check(string[] hosts, string[]? names, ValidationMethod method)
    {
        using var service = new PreflightService(_iis.Object, _files.Object, _dns);
        return await service.CheckDnsAsync(new DnsPreflightRequest("Shop", hosts, names, method, CertificateAuthorities.LetsEncryptStagingId));
    }
}

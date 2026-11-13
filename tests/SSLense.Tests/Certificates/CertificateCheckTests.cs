using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Logs;
using SSLense.Core.Reminders;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Check, on a certificate's screen and as 'check --site': is the expected certificate served now?</summary>
public sealed class CertificateCheckTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly Mock<IServedCertificateCheck> _served = new(MockBehavior.Strict);

    [Fact]
    public async Task AServedCertificate_Passes()
    {
        var record = Record("Main/www.domain2.co.uk", "www.domain2.co.uk");
        _served.Setup(value => value.CheckAsync(record, It.Is<IisSite>(site => site.Name == "Main"), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        var result = await Service(record, Site("Main", "Started")).CheckServedAsync("Main/www.domain2.co.uk");

        Assert.True(result.Passed);
        Assert.Equal("https://www.domain2.co.uk serves the expected certificate.", result.Message);
    }

    [Fact]
    public async Task AnotherCertificateServed_IsReported()
    {
        var record = Record("Main", "www.domain1.co.uk");
        _served.Setup(value => value.CheckAsync(record, It.IsAny<IisSite>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync("www.domain1.co.uk serves another certificate. Check the site's HTTPS binding in IIS.");

        var result = await Service(record, Site("Main", "Started")).CheckServedAsync("Main");

        Assert.False(result.Passed);
        Assert.Contains("serves another certificate", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AStoppedSite_IsReported_WithoutConnecting()
    {
        var record = Record("Main", "www.domain1.co.uk");

        var result = await Service(record, Site("Main", "Stopped")).CheckServedAsync("Main");

        Assert.False(result.Passed);
        Assert.Contains("is stopped", result.Message, StringComparison.Ordinal);
        _served.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ACertificateWithNoSite_HasNothingToCheck()
    {
        var record = Record("RDP", "rdp.example.com") with { NoSite = true };

        var result = await Service(record).CheckServedAsync("RDP");

        Assert.True(result.Passed);
        _served.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task EverySiteSharingTheCertificate_IsChecked_WithItsOwnHostNames()
    {
        var record = Record("Shop", "shop.example.com") with { AdditionalTargets = [new CertificateTarget("Blog", ["blog.example.com"])] };
        var checkedHosts = new List<string>();
        _served.Setup(value => value.CheckAsync(It.IsAny<ManagedCertificate>(), It.IsAny<IisSite>(), It.IsAny<CancellationToken>()))
            .Callback<ManagedCertificate, IisSite, CancellationToken>((certificate, site, _) => checkedHosts.Add($"{site.Name}:{string.Join(",", certificate.Hosts)}"))
            .ReturnsAsync((string?)null);

        var result = await Service(record, Site("Shop", "Started"), Site("Blog", "Started")).CheckServedAsync("Shop");

        Assert.True(result.Passed);
        Assert.Equal(["Shop:shop.example.com", "Blog:blog.example.com"], checkedHosts);
        Assert.StartsWith("All 2 host names", result.Message, StringComparison.Ordinal);
    }

    private CertificateManagementService Service(ManagedCertificate record, params IisSite[] sites)
    {
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([record]);
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(sites);
        return new CertificateManagementService(managed.Object, Mock.Of<ICertificateStore>(), iis.Object, Mock.Of<ILogService>(), servedCheck: _served.Object);
    }

    private static IisSite Site(string name, string state) => new(1, name, state, null, []);

    private static ManagedCertificate Record(string name, string host) =>
        new(name, [host], string.Empty, "AA01", Now.AddDays(-10), Now.AddDays(80), Source: CertificateSource.Imported);
}

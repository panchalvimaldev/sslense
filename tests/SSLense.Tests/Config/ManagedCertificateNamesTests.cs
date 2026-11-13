using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

/// <summary>Several certificates on one IIS site (docs/design/multiple-certificates-per-site.md).</summary>
public sealed class ManagedCertificateNamesTests
{
    private static readonly ManagedCertificate First = Record("Main", "www.domain1.co.uk");
    private static readonly ManagedCertificate Second = Record("Main/www.domain2.co.uk", "www.domain2.co.uk");

    [Theory]
    [InlineData("Main", "Main")]
    [InlineData(" Main/www.domain2.co.uk ", "Main")]
    [InlineData("Default Web Site", "Default Web Site")]
    public void TheSite_IsThePartBeforeTheFirstSlash(string name, string site) =>
        Assert.Equal(site, ManagedCertificateNames.IisSiteOf(name));

    [Fact]
    public void Resolve_NewHostsOnAnUnmanagedSite_UseTheSiteName() =>
        Assert.Equal("Main", ManagedCertificateNames.Resolve([], "Main", ["www.domain1.co.uk"]));

    [Fact]
    public void Resolve_HostsOfACertificate_NameThatCertificate()
    {
        Assert.Equal("Main", ManagedCertificateNames.Resolve([First, Second], "main", ["WWW.domain1.co.uk"]));
        Assert.Equal("Main/www.domain2.co.uk", ManagedCertificateNames.Resolve([First, Second], "Main", ["www.domain2.co.uk"]));
    }

    [Fact]
    public void Resolve_NewHostsOnAManagedSite_NameASecondCertificateAfterTheFirstHost() =>
        Assert.Equal("Main/www.domain3.co.uk",
            ManagedCertificateNames.Resolve([First, Second], "Main", ["www.domain3.co.uk", "domain3.co.uk"]));

    [Fact]
    public void Resolve_HostsOfTwoCertificates_AreRefused()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            ManagedCertificateNames.Resolve([First, Second], "Main", ["www.domain1.co.uk", "www.domain2.co.uk"]));

        Assert.Contains("'Main/www.domain2.co.uk'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Resolve_OtherSitesAndCertificatesWithNoSite_DoNotCount()
    {
        ManagedCertificate[] records = [Record("Blog", "www.domain1.co.uk"), Record("Main", "www.domain1.co.uk") with { SiteName = "RDP", NoSite = true }];

        Assert.Equal("Main", ManagedCertificateNames.Resolve(records, "Main", ["www.domain1.co.uk"]));
    }

    [Fact]
    public void HostsOfAnotherCertificateOnTheSite_AreTaken()
    {
        var exception = Assert.Throws<InvalidOperationException>(() =>
            ManagedCertificateNames.ThrowIfHostsTaken([First, Second], "Main", ["www.domain1.co.uk", "www.domain2.co.uk"]));

        Assert.Contains("'Main/www.domain2.co.uk'", exception.Message, StringComparison.Ordinal);
        ManagedCertificateNames.ThrowIfHostsTaken([First, Second], "Main", ["www.domain1.co.uk", "domain1.co.uk"]);
    }

    [Fact]
    public async Task CertificatesOnOneSite_ShareTheSitesLock_AndOtherSitesDoNot()
    {
        var paths = new List<string>();
        var files = new Mock<IFileSystem>();
        files.Setup(value => value.AcquireExclusiveFileLockAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((path, _) => paths.Add(path))
            .ReturnsAsync(Mock.Of<IAsyncDisposable>());
        var locks = new CertificateOperationLock(files.Object);

        await locks.AcquireAsync("Main");
        await locks.AcquireAsync("main/www.domain2.co.uk");
        await locks.AcquireAsync("Blog");

        Assert.Equal(paths[0], paths[1]);
        Assert.NotEqual(paths[0], paths[2]);
    }

    [Fact]
    public async Task AcquiringAll_TakesASitesLockOnce()
    {
        var taken = new List<string>();
        var locks = new Mock<ICertificateOperationLock>();
        locks.Setup(value => value.AcquireAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((name, _) => taken.Add(name))
            .ReturnsAsync(Mock.Of<IAsyncDisposable>());

        await using (await locks.Object.AcquireAllAsync(["Main", "Main/www.domain2.co.uk", "Blog"]))
        {
            Assert.Equal(["Blog", "Main"], taken);
        }
    }

    [Fact]
    public void Issue_ASecondCertificateOnASite_IsRefused_UntilPhase2()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => AcmeService.ThrowIfOtherCertificateOnSite(
            Request("Main/www.domain2.co.uk", "www.domain2.co.uk"), Second, [First, Second]));

        Assert.Contains("Other providers", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Issue_ForHostsOfAnotherCertificateOnTheSite_IsRefused()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => AcmeService.ThrowIfOtherCertificateOnSite(
            Request("Main", "www.domain1.co.uk", "www.domain2.co.uk"), First, [First, Second]));

        Assert.Contains("'Main/www.domain2.co.uk'", exception.Message, StringComparison.Ordinal);
        AcmeService.ThrowIfOtherCertificateOnSite(Request("Main", "www.domain1.co.uk"), First, [First, Second]);
    }

    [Fact]
    public void Issue_ANewCertificateWithNoSite_CannotUseASlash_ButOneNamedSoBeforeKeepsRenewing()
    {
        var request = Request("Mail/SMTP", "mail.example.com") with { NoSite = true };

        Assert.Throws<InvalidOperationException>(() => AcmeService.ThrowIfOtherCertificateOnSite(request, null, []));
        var existing = Record("Mail/SMTP", "mail.example.com") with { NoSite = true };
        AcmeService.ThrowIfOtherCertificateOnSite(request, existing, [existing]);
    }

    private static AcmeIssueRequest Request(string name, params string[] hosts) => new(name, hosts, "ops@example.com");

    private static ManagedCertificate Record(string name, params string[] hosts) =>
        new(name, hosts, string.Empty, Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(300),
            Source: CertificateSource.Imported);
}

using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Logs;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Stop managing: SSLense forgets the certificate and leaves IIS and the certificate store as they are.</summary>
public sealed class StopManagingTests
{
    private readonly Mock<IManagedCertificateStore> _managed = new();
    private readonly Mock<IIisService> _iis = new(MockBehavior.Strict);
    private readonly Mock<ICertificateStore> _certificates = new(MockBehavior.Strict);
    private readonly Mock<ICertificateOperationLock> _lock = new();
    private readonly List<string> _locked = [];

    private static ManagedCertificate Record(string site = "Shop", bool noSite = false, CertificateSource source = CertificateSource.Acme,
        params CertificateTarget[] others) => new(
        site,
        ["shop.example.com"],
        "admin@example.com",
        "AABB",
        DateTimeOffset.UtcNow.AddDays(-5),
        new DateTimeOffset(2027, 2, 1, 0, 0, 0, TimeSpan.Zero),
        Source: source,
        NoSite: noSite,
        AdditionalTargets: others.Length > 0 ? others : null);

    private CertificateManagementService Service(ManagedCertificate record)
    {
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([record]);
        _lock.Setup(value => value.AcquireAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((site, _) => _locked.Add(site))
            .ReturnsAsync(Mock.Of<IAsyncDisposable>());
        return new CertificateManagementService(_managed.Object, _certificates.Object, _iis.Object, Mock.Of<ILogService>(), operationLock: _lock.Object);
    }

    [Theory]
    [InlineData(CertificateSource.Acme)]
    [InlineData(CertificateSource.Imported)]
    public async Task StopManaging_RemovesOnlyTheRecord_AndLeavesIisAndTheStoreAlone(CertificateSource source)
    {
        var service = Service(Record(source: source));

        var message = await service.StopManagingAsync("Shop");

        _managed.Verify(value => value.RemoveAsync("Shop", It.IsAny<CancellationToken>()), Times.Once);
        _managed.Verify(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()), Times.Never);
        _iis.VerifyNoOtherCalls();
        _certificates.VerifyNoOtherCalls();
        Assert.Contains("'Shop' were not changed", message, StringComparison.Ordinal);
        Assert.Contains("2027-02-01", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StopManaging_SharedCertificate_KeepsEverySite_AndWaitsForEachSitesLock()
    {
        var service = Service(Record(others: new CertificateTarget("Blog", ["blog.example.com"])));

        var message = await service.StopManagingAsync("shop");

        Assert.Contains("sites 'Shop', 'Blog'", message, StringComparison.Ordinal);
        Assert.Equal(["Blog", "Shop"], _locked.Order(StringComparer.Ordinal));
        _managed.Verify(value => value.RemoveAsync("Shop", It.IsAny<CancellationToken>()), Times.Once);
        _iis.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task StopManaging_OnASiteSharingTheCertificate_IsRefused_AndPointsToShareRemove()
    {
        var service = Service(Record(others: new CertificateTarget("Blog", ["blog.example.com"])));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.StopManagingAsync("Blog"));

        Assert.Contains("share remove --site \"Blog\"", exception.Message, StringComparison.Ordinal);
        Assert.Contains("unmanage --site \"Shop\"", exception.Message, StringComparison.Ordinal);
        _managed.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task StopManaging_FurtherCertificateOnASite_UsesItsRecordName()
    {
        var service = Service(Record(site: "Shop/api.example.com"));

        var message = await service.StopManagingAsync("Shop/api.example.com");

        _managed.Verify(value => value.RemoveAsync("Shop/api.example.com", It.IsAny<CancellationToken>()), Times.Once);
        Assert.Contains("IIS site 'Shop'", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StopManaging_NoSiteCertificate_SaysItStaysInTheStore()
    {
        var service = Service(Record(site: "RDP", noSite: true));

        var message = await service.StopManagingAsync("RDP");

        Assert.Contains("stays in LocalMachine\\My", message, StringComparison.Ordinal);
        _iis.VerifyNoOtherCalls();
        _certificates.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task StopManaging_UnknownName_IsRefused()
    {
        var service = Service(Record());

        await Assert.ThrowsAnyAsync<Exception>(() => service.StopManagingAsync("Nowhere"));

        _managed.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}

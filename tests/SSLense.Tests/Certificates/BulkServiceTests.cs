using Moq;
using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Bulk operations (docs/design/bulk-operations.md).</summary>
public sealed class BulkServiceTests : IDisposable
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), $"sslense-bulk-{Guid.NewGuid():N}.csv");
    private readonly Mock<IImportedCertificateService> _imported = new();
    private readonly Mock<IAcmeService> _acme = new();
    private readonly Mock<IPreflightService> _preflight = new();
    private readonly List<AcmeIssueRequest> _issued = [];

    public BulkServiceTests()
    {
        _acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), It.IsAny<IProgress<ProgressEvent>>(), It.IsAny<CancellationToken>()))
            .Callback<AcmeIssueRequest, IProgress<ProgressEvent>?, CancellationToken>((request, _, _) =>
            {
                if (request.SiteName == "Broken") throw new InvalidOperationException("No such site.");
                _issued.Add(request);
            })
            .ReturnsAsync((AcmeIssueRequest request, IProgress<ProgressEvent>? _, CancellationToken _) =>
                new AcmeIssueResult("pem", null, request.Hosts, "AA", NotAfter: DateTimeOffset.UtcNow.AddDays(90), Name: request.SiteName));
    }

    [Theory]
    [InlineData("Shop,shop.example.com,http", new[] { "Shop", "shop.example.com", "http" })]
    [InlineData("\"Main, old\",\"a.example.com;b.example.com\",dns", new[] { "Main, old", "a.example.com;b.example.com", "dns" })]
    [InlineData("\"He said \"\"hi\"\"\",x", new[] { "He said \"hi\"", "x" })]
    public void ALine_IsSplitIntoItsFields(string line, string[] fields) => Assert.Equal(fields, BulkService.ParseLine(line));

    [Fact]
    public async Task EachRowIsIssued_AndAFailedRowStopsNothingElse()
    {
        await File.WriteAllLinesAsync(_file,
        [
            "# Certificates for the new servers",
            "hosts,site,validation,names,email",
            "shop.example.com;www.shop.example.com,Shop,http,,ops@example.com",
            "blog.example.com,Broken,http,,ops@example.com",
            "api.example.com,Api,dns,*.example.com example.com,",
            "x.example.com,Odd,dns-manual,,ops@example.com"
        ]);

        var results = await Service().IssueFromCsvAsync(_file, dryRun: false);

        Assert.Equal([true, false, true, false], results.Select(result => result.Succeeded));
        Assert.Equal(["Shop", "Api"], _issued.Select(request => request.SiteName));
        Assert.Equal(["shop.example.com", "www.shop.example.com"], _issued[0].Hosts);
        Assert.Equal(ValidationMethod.Dns01Provider, _issued[1].ValidationMethod);
        Assert.Equal(["*.example.com", "example.com"], _issued[1].CertificateNames);
        Assert.Equal("default@example.com", _issued[1].Email);
        Assert.Equal(CertificateAuthorities.LetsEncryptStagingId, _issued[1].AuthorityId);
        Assert.Contains("SSL9999: No such site.", results[1].Message, StringComparison.Ordinal);
        Assert.Contains("SSL6029", results[3].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ADryRun_OnlyChecks()
    {
        await File.WriteAllLinesAsync(_file, ["Shop,shop.example.com,http-self"]);
        _preflight.Setup(value => value.CheckAsync("Shop", It.IsAny<IReadOnlyList<string>>(), true, It.IsAny<CancellationToken>()))
            .ReturnsAsync([new PreflightCheck("Port 80", false, "SSL1028: port 80 is taken.")]);

        var result = Assert.Single(await Service().IssueFromCsvAsync(_file, dryRun: true));

        Assert.False(result.Succeeded);
        Assert.Contains("Port 80: SSL1028", result.Message, StringComparison.Ordinal);
        Assert.Empty(_issued);
    }

    [Fact]
    public async Task WatchingAll_TakesEachUnmanagedCertificateOncePerSite()
    {
        var expires = DateTimeOffset.UtcNow.AddDays(200);
        _imported.Setup(value => value.DiscoverAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new DiscoveredBinding("Shop", "example.com", 443, "AA", "Sectigo", expires, false),
            new DiscoveredBinding("Shop", "www.example.com", 443, "aa", "Sectigo", expires, false),
            new DiscoveredBinding("Blog", "blog.example.com", 443, "BB", "Sectigo", expires, true),
            new DiscoveredBinding("Legacy", "old.example.com", 443, null, null, null, false),
            new DiscoveredBinding("Admin", "admin.example.com", 443, "CC", "Sectigo", expires, false)
        ]);
        _imported.Setup(value => value.AdoptAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string site, string? thumbprint, CancellationToken _) =>
                new ManagedCertificate(site, [], "", thumbprint!, DateTimeOffset.UtcNow, expires, Source: CertificateSource.Imported));

        var results = await Service().WatchAllAsync();

        Assert.Equal(2, results.Count);
        _imported.Verify(value => value.AdoptAsync("Shop", "AA", It.IsAny<CancellationToken>()), Times.Once);
        _imported.Verify(value => value.AdoptAsync("Admin", "CC", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task WatchingAll_SkipsACertificateOnlyOnAnotherPort_InsteadOfFailingIt()
    {
        // Found in the combined test: Tick all and 'bulk watch' tried such bindings and reported SSL4001 failures.
        var expires = DateTimeOffset.UtcNow.AddDays(200);
        _imported.Setup(value => value.DiscoverAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            new DiscoveredBinding("Port8443", "p8443.example.com", 8443, "DD", "Sectigo", expires, false, NeedsPort443: true)
        ]);
        var progress = new List<string>();

        var results = await Service().WatchAllAsync(new SynchronousProgress(value => progress.Add(value.Message)));

        Assert.Empty(results);
        Assert.Contains(progress, line => line.Contains("Skipping Port8443", StringComparison.Ordinal) && line.Contains("port 443", StringComparison.Ordinal));
        _imported.Verify(value => value.AdoptAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private sealed class SynchronousProgress(Action<ProgressEvent> report) : IProgress<ProgressEvent>
    {
        public void Report(ProgressEvent value) => report(value);
    }

    public void Dispose() => File.Delete(_file);

    private BulkService Service() => new(_imported.Object, _acme.Object, _preflight.Object,
        Mock.Of<ISettingsService>(value => value.GetAsync(It.IsAny<CancellationToken>()) == Task.FromResult(new AppConfig { DefaultEmail = "default@example.com" })));
}

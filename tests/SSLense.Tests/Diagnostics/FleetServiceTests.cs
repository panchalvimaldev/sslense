using Moq;
using SSLense.Core.Config;
using SSLense.Core.Diagnostics;
using SSLense.Core.Errors;
using SSLense.Core.Renewal;
using SSLense.Tests.DnsValidation;
using Xunit;

namespace SSLense.Tests.Diagnostics;

/// <summary>Fleet reports in a shared folder (docs/design/fleet.md).</summary>
public sealed class FleetServiceTests
{
    private const string Folder = @"\\files\sslense-fleet";

    private readonly InMemoryFileSystem _files = new() { ExistingDirectories = new HashSet<string>([Folder], StringComparer.OrdinalIgnoreCase) };
    private readonly FakeConfigStore _config = new();
    private readonly Mock<IRenewalService> _renewal = new();

    public FleetServiceTests()
    {
        _renewal.Setup(value => value.GetStatusAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new ManagedCertificateStatus("Shop", ["shop.example.com"], DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(60), 60, "AABB",
                DateTimeOffset.UtcNow, false, "SSL2001: The CA refused the order.", ConsecutiveFailures: 2)
        ]);
    }

    private FleetService Service(string server) => new(_config, _renewal.Object, _files) { ServerName = server };

    [Fact]
    public async Task EachServerWritesItsReport_AndAnyServerReadsThemAll()
    {
        await Service("WEB1").SetFolderAsync(Folder + "\\");
        await Service("WEB1").WriteReportAsync(true, null);
        await Service("WEB2").WriteReportAsync(false, "Renewal failed for Shop.");

        var servers = await Service("WEB1").ReadAsync();

        Assert.Equal(["WEB1", "WEB2"], servers.Select(server => server.Server));
        Assert.All(servers, server => Assert.False(server.Stale));
        var certificate = Assert.Single(servers[1].Report!.Certificates);
        Assert.Equal("Shop", certificate.Name);
        Assert.False(certificate.LastRenewalSucceeded);
        Assert.Equal(2, certificate.ConsecutiveFailures);
        Assert.False(servers[1].Report!.LastCycleSucceeded);
        Assert.DoesNotContain("AABB", _files.Files[$@"{Folder}\WEB1.json"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task AServerThatStoppedReporting_IsStale_AndADamagedReportIsNamed()
    {
        await Service("WEB1").SetFolderAsync(Folder);
        await Service("WEB1").WriteReportAsync();
        _files.Files[$@"{Folder}\WEB1.json"] = _files.Files[$@"{Folder}\WEB1.json"].Replace(
            DateTimeOffset.UtcNow.Year.ToString(System.Globalization.CultureInfo.InvariantCulture), "2020", StringComparison.Ordinal);
        _files.Files[$@"{Folder}\WEB3.json"] = "{ not json";

        var servers = await Service("WEB1").ReadAsync();

        Assert.True(servers.Single(server => server.Server == "WEB1").Stale);
        Assert.Contains("could not be read", servers.Single(server => server.Server == "WEB3").Problem, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutAFolder_NothingIsWritten_AndAnUnreachableFolderIsRefused()
    {
        Assert.Null(await Service("WEB1").WriteReportAsync());
        Assert.Empty(_files.Files);

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => Service("WEB1").SetFolderAsync(@"\\files\elsewhere"));
        Assert.StartsWith(ErrorCodes.FleetFolderInvalid.Code, exception.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<SslenseException>(() => Service("WEB1").ReadAsync());
    }
}

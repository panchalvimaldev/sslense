using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Reminders;
using SSLense.Core.Validation;
using SSLense.Tests.DnsValidation;
using Xunit;

namespace SSLense.Tests.Reminders;

public sealed class RenewalReadinessCheckTests
{
    private static readonly DateTimeOffset Now = new(2026, 12, 1, 9, 0, 0, TimeSpan.Zero);
    private readonly Mock<IPreflightService> _preflight = new(MockBehavior.Strict);
    private readonly Mock<ICertificateOperationLock> _lock = new();
    private readonly FakeDnsChecks _dns = new();

    public RenewalReadinessCheckTests()
    {
        _lock.Setup(value => value.TryAcquire(It.IsAny<string>())).Returns(Mock.Of<IAsyncDisposable>());
    }

    [Fact]
    public async Task FailedChecks_AreReportedWithWhatFailed()
    {
        Preflight(new PreflightCheck("Administrator", true, "SSLense is elevated."),
            new PreflightCheck("HTTP binding: api.example.com", false, "Add an IIS HTTP binding on port 80 for this host."));

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Equal(
            "'HTTP binding: api.example.com' failed: Add an IIS HTTP binding on port 80 for this host.",
            result.Problems["Api"]);
        Assert.Empty(result.Passed);
    }

    [Fact]
    public async Task AllChecksPassing_IsRecordedAsPassed()
    {
        Preflight(new PreflightCheck("Administrator", true, "SSLense is elevated."));

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Equal(["Api"], result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task CertificateFarFromRenewal_IsNotChecked()
    {
        var result = await Check(Automatic(), renewsInDays: 31);

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task RenewalAlreadyPastDue_IsStillChecked()
    {
        Preflight(new PreflightCheck("Administrator", true, "SSLense is elevated."));

        Assert.Single((await Check(Automatic(), renewsInDays: -2)).Passed);
    }

    [Fact]
    public async Task ImportedAndMutedCertificates_AreNotChecked()
    {
        var imported = Automatic() with { Source = CertificateSource.Imported };
        var muted = Automatic() with { SiteName = "Muted", Reminders = ReminderMode.Off };

        var result = await new RenewalReadinessCheck(_preflight.Object, _lock.Object, _dns).CheckAsync(
            [imported, muted],
            new Dictionary<string, DateTimeOffset> { ["Api"] = Now, ["Muted"] = Now },
            Now);

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task SiteWithAnOperationInProgress_IsSkipped()
    {
        _lock.Setup(value => value.TryAcquire("Api")).Returns((IAsyncDisposable?)null);

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Empty(result.Passed);
        Assert.Empty(result.Problems);
    }

    [Fact]
    public async Task ManualDnsCertificate_IsNotChecked()
    {
        var result = await Check(Automatic() with { ValidationMethod = ValidationMethod.Dns01Manual }, renewsInDays: 10);

        Assert.Empty(result.Problems);
        Assert.Empty(result.Passed);
        Assert.Empty(_dns.Checked);
        _preflight.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task DnsCertificate_RunsTheDnsChecksOnItsCertificateNames_NotTheHttpChecks()
    {
        var result = await Check(
            Automatic() with { ValidationMethod = ValidationMethod.Dns01Provider, CertificateNames = ["*.example.com"], AuthorityId = "letsencrypt" },
            renewsInDays: 10);

        Assert.Equal(["Api"], result.Passed);
        Assert.Equal(["Dns01Provider *.example.com letsencrypt"], _dns.Checked);
        _preflight.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task DnsCertificate_AFinding_IsReportedAsAProblem()
    {
        _dns.Fail = new InvalidOperationException("The CAA records do not allow it.");

        var result = await Check(Automatic() with { ValidationMethod = ValidationMethod.Dns01Provider }, renewsInDays: 10);

        Assert.Equal("The CAA records do not allow it.", result.Problems["Api"]);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task DnsCertificate_ANetworkFailure_IsAnErrorNotAProblem()
    {
        _dns.Fail = new HttpRequestException("Cloudflare cannot be reached");

        var result = await Check(Automatic() with { ValidationMethod = ValidationMethod.Dns01Provider }, renewsInDays: 10);

        Assert.Empty(result.Problems);
        Assert.Contains("Cloudflare cannot be reached", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CheckThatCannotRun_IsAnErrorAndOthersContinue()
    {
        _preflight.Setup(value => value.CheckAsync("Api", It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("IIS cannot be read"));

        var result = await Check(Automatic(), renewsInDays: 10);

        Assert.Contains("IIS cannot be read", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    private Task<ProactiveCheckResult> Check(ManagedCertificate certificate, int renewsInDays) =>
        new RenewalReadinessCheck(_preflight.Object, _lock.Object, _dns).CheckAsync(
            [certificate],
            new Dictionary<string, DateTimeOffset> { [certificate.SiteName] = Now.AddDays(renewsInDays) },
            Now);

    private void Preflight(params PreflightCheck[] checks) =>
        _preflight.Setup(value => value.CheckAsync("Api", It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(checks);

    private static ManagedCertificate Automatic() => new(
        "Api", ["api.example.com"], "admin@example.com", "CCDD", Now.AddDays(-50), Now.AddDays(40));
}

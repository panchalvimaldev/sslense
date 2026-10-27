using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Renewal;
using SSLense.Core.Notifications;
using Xunit;

namespace SSLense.Tests.Renewal;

public sealed class RenewalServiceTests
{
    [Fact]
    public async Task RenewAsync_NotDueWithoutForce_SkipsIssuance()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(60))]);
        var config = new Mock<IConfigStore>(MockBehavior.Strict);
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { RenewalThresholdDays = 30 });
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        var service = CreateService(managed, config, acme);

        var results = await service.RenewAsync(new RenewalRequest(All: true));

        var result = Assert.Single(results);
        Assert.False(result.Attempted);
        Assert.True(result.Succeeded);
        acme.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RenewAsync_Due_SwapsBindingBeforeRemovingUnusedOldCertificate()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        var config = MockConfig();
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.Is<AcmeIssueRequest>(request => request.Force && request.SiteName == "My Site"),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult(
                "certificate.pem",
                "certificate.pfx",
                ["example.com"],
                "NEW"));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [
                    new IisBinding("https", "*", 443, "example.com", "NEW", "My", true)
                ])
            ]);
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message => message.Kind == NotificationKind.ExpiryWarning),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("notification offline"));
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalSuccess),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("notification offline"));
        var service = CreateService(managed, config, acme, iis, certificateStore, notifier: notifier);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true)));

        Assert.True(result.Succeeded);
        Assert.Equal("NEW", result.NewThumbprint);
        certificateStore.VerifyAll();
        notifier.VerifyAll();
    }

    [Fact]
    public async Task RenewAsync_OldCertificateStillUsedByIis_DoesNotRemoveIt()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.IsAny<AcmeIssueRequest>(),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("pem", "pfx", ["example.com"], "NEW"));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                new IisSite(2, "Other Site", "Started", null, [
                    new IisBinding("https", "*", 443, "other.example.com", "OLD", "My", true)
                ])
            ]);
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        var service = CreateService(managed, MockConfig(), acme, iis, certificateStore);

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true)));

        Assert.True(result.Succeeded);
        Assert.Contains("retained", result.Message, StringComparison.OrdinalIgnoreCase);
        certificateStore.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RenewAsync_ServiceMode_RetriesThreeTimesWithBackoffAndRecordsFailure()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([CreateCertificate(DateTimeOffset.UtcNow.AddDays(5))]);
        managed.Setup(value => value.RecordRenewalFailureAsync(
                "My Site",
                It.IsAny<DateTimeOffset>(),
                "ACME unavailable",
                CancellationToken.None))
            .Returns(Task.CompletedTask);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);
        acme.Setup(value => value.IssueAsync(
                It.IsAny<AcmeIssueRequest>(),
                null,
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("ACME unavailable"));
        var delay = new Mock<IRenewalDelay>(MockBehavior.Strict);
        delay.Setup(value => value.WaitAsync(TimeSpan.FromHours(1), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        delay.Setup(value => value.WaitAsync(TimeSpan.FromHours(2), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var notifier = new Mock<INotifier>(MockBehavior.Strict);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message => message.Kind == NotificationKind.ExpiryWarning),
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        notifier.Setup(value => value.NotifyAsync(
                It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalFailure),
                CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = CreateService(managed, MockConfig(), acme, delay: delay, notifier: notifier);

        var result = Assert.Single(await service.RenewAsync(
            new RenewalRequest(All: true, RetryFailures: true)));

        Assert.False(result.Succeeded);
        acme.Verify(value => value.IssueAsync(
            It.IsAny<AcmeIssueRequest>(), null, It.IsAny<CancellationToken>()), Times.Exactly(3));
        managed.Verify(value => value.RecordRenewalFailureAsync(
            "My Site", It.IsAny<DateTimeOffset>(), "ACME unavailable", CancellationToken.None), Times.Exactly(3));
        delay.VerifyAll();
        notifier.VerifyAll();
    }

    private static RenewalService CreateService(
        Mock<IManagedCertificateStore> managed,
        Mock<IConfigStore> config,
        Mock<IAcmeService> acme,
        Mock<IIisService>? iis = null,
        Mock<ICertificateStore>? certificateStore = null,
        Mock<IRenewalDelay>? delay = null,
        Mock<INotifier>? notifier = null) =>
        new(
            managed.Object,
            config.Object,
            acme.Object,
            (iis ?? new Mock<IIisService>(MockBehavior.Strict)).Object,
            (certificateStore ?? new Mock<ICertificateStore>(MockBehavior.Strict)).Object,
            (delay ?? new Mock<IRenewalDelay>(MockBehavior.Strict)).Object,
            (notifier ?? new Mock<INotifier>()).Object);

    private static Mock<IConfigStore> MockConfig()
    {
        var config = new Mock<IConfigStore>(MockBehavior.Strict);
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AppConfig { RenewalThresholdDays = 30 });
        return config;
    }

    private static ManagedCertificate CreateCertificate(DateTimeOffset expires) => new(
        "My Site",
        ["example.com"],
        "admin@example.com",
        "OLD",
        DateTimeOffset.UtcNow.AddDays(-60),
        expires);
}

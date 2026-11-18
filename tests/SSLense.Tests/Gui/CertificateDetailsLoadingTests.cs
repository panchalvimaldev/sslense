using System.Windows.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.Diagnostics;
using SSLense.Core.Iis;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;
using SSLense.Gui.ViewModels;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>The details always belong to the certificate shown, however slowly they load.</summary>
public sealed class CertificateDetailsLoadingTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly Mock<ICertificateManagementService> _management = new();

    [Fact]
    public void ASlowLoadOfThePreviousCertificate_DoesNotOverwriteTheOneShown() => GuiThread.Run(() =>
    {
        var slowA = new TaskCompletionSource<CertificateDetails>();
        _management.Setup(value => value.GetDetailsAsync("A", It.IsAny<CancellationToken>())).Returns(slowA.Task);
        _management.Setup(value => value.GetDetailsAsync("B", It.IsAny<CancellationToken>())).ReturnsAsync(Detail("B", "BBBB"));
        var details = Details();

        var loadingA = details.ShowAsync(Row("A", "AAAA"));
        var loadingB = details.ShowAsync(Row("B", "BBBB"));
        WaitFor(() => loadingB.IsCompleted);
        slowA.SetResult(Detail("A", "AAAA"));
        WaitFor(() => loadingA.IsCompleted);

        Assert.Equal("B", details.SelectedSite);
        Assert.Equal("BBBB", details.Thumbprint);
        Assert.Equal("b.example.com", details.Hosts);
        Assert.False(details.IsBusy);
    });

    [Fact]
    public void RefreshingTheList_ReadsTheSelectedCertificatesDetailsAgain() => GuiThread.Run(() =>
    {
        var thumbprint = "OLD";
        _management.Setup(value => value.GetDetailsAsync("A", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Detail("A", thumbprint));
        var renewal = new Mock<IRenewalService>();
        renewal.Setup(value => value.GetStatusAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => [Status("A", thumbprint)]);
        var dashboard = new DashboardViewModel(renewal.Object, Mock.Of<IHealthCheckService>(), NullLogger<DashboardViewModel>.Instance,
            Mock.Of<INavigationService>(), Details());

        var select = dashboard.SelectAsync("A");
        WaitFor(() => select.IsCompleted && dashboard.Details.Thumbprint == "OLD" && !dashboard.Details.IsBusy);

        // Renewed by Renew all due, the service, or the CLI.
        thumbprint = "NEW";
        var refresh = dashboard.RefreshCommand.ExecuteAsync(null);
        WaitFor(() => refresh.IsCompleted && !dashboard.Details.IsBusy);

        Assert.Equal("NEW", dashboard.Details.Thumbprint);
        Assert.Equal("A", dashboard.Details.SelectedSite);
    });

    private CertificateDetailsViewModel Details() => new(
        _management.Object,
        Mock.Of<IRenewalService>(),
        NullLogger<CertificateDetailsViewModel>.Instance,
        Mock.Of<INavigationService>(),
        Mock.Of<IReminderService>(),
        Mock.Of<ICertificateSharingService>(),
        Mock.Of<IIisService>(),
        Mock.Of<IDeploymentService>(),
        new InstallRenewalViewModel(Mock.Of<IImportedCertificateService>(), Mock.Of<IPendingRequestStore>(),
            Mock.Of<INavigationService>(), NullLogger<InstallRenewalViewModel>.Instance));

    private static string Host(string site) => $"{site.ToLowerInvariant()}.example.com";

    private static CertificateDetails Detail(string site, string thumbprint) =>
        new(site, [Host(site)], thumbprint, "Test CA", Now.AddDays(-10), Now.AddDays(80), [site], []);

    private static ManagedCertificateStatus Status(string site, string thumbprint) =>
        new(site, [Host(site)], Now.AddDays(-10), Now.AddDays(80), 80, thumbprint, null, null, null);

    private static CertificateRowViewModel Row(string site, string thumbprint) => new(Status(site, thumbprint));

    private static void WaitFor(Func<bool> condition)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!condition() && DateTime.UtcNow < until)
        {
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.Background);
            Thread.Sleep(10);
        }

        Assert.True(condition(), "Timed out waiting for the view models.");
    }
}

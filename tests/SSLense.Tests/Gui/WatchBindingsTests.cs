using System.Windows.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Gui.ViewModels;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>Add certificate › Already in IIS: watching the ticked bindings.</summary>
public sealed class WatchBindingsTests
{
    private static readonly DateTimeOffset Expires = DateTimeOffset.UtcNow.AddDays(200);

    [Fact]
    public void TickingTwoBindingsOfOneCertificate_WatchesItOnce_AndReportsNoFailure() => GuiThread.Run(() =>
    {
        var service = new Mock<IImportedCertificateService>();
        var adopted = false;
        service.Setup(value => value.DiscoverAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() =>
        [
            new DiscoveredBinding("Shop", "example.com", 443, "AABB", "Sectigo", Expires, adopted),
            new DiscoveredBinding("Shop", "www.example.com", 443, "AABB", "Sectigo", Expires, adopted),
            new DiscoveredBinding("Blog", "blog.example.com", 443, "CCDD", "Sectigo", Expires, adopted)
        ]);
        service.Setup(value => value.AdoptAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string site, string? thumbprint, CancellationToken _) =>
            {
                adopted = true;
                return new ManagedCertificate(site, site == "Shop" ? ["example.com", "www.example.com"] : ["blog.example.com"],
                    string.Empty, thumbprint!, DateTimeOffset.UtcNow, Expires, Source: CertificateSource.Imported);
            });
        var watch = new OtherProvidersViewModel(service.Object,
            Mock.Of<IPendingRequestStore>(value => value.GetAllAsync(It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<PendingCertificateRequest>>(Array.Empty<PendingCertificateRequest>())),
            Mock.Of<IIisService>(value => value.GetSitesAsync(It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<IisSite>>(Array.Empty<IisSite>())),
            NullLogger<OtherProvidersViewModel>.Instance);
        var loading = watch.InitializeAsync();
        WaitFor(() => loading.IsCompleted && watch.Bindings.Count == 3);
        foreach (var row in watch.Bindings) row.IsChecked = true;

        var adopting = watch.AdoptCheckedCommand.ExecuteAsync(null);
        WaitFor(() => adopting.IsCompleted);

        service.Verify(value => value.AdoptAsync("Shop", "AABB", It.IsAny<CancellationToken>()), Times.Once);
        service.Verify(value => value.AdoptAsync("Blog", "CCDD", It.IsAny<CancellationToken>()), Times.Once);
        Assert.Null(watch.ErrorMessage);
        Assert.Contains("example.com, www.example.com", watch.ResultMessage, StringComparison.Ordinal);
    });

    private static void WaitFor(Func<bool> condition)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!condition() && DateTime.UtcNow < until)
        {
            Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.Background);
            Thread.Sleep(10);
        }

        Assert.True(condition(), "Timed out waiting for the view model.");
    }
}

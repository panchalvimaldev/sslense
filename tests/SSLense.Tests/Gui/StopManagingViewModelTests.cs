using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.Iis;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;
using SSLense.Gui.ViewModels;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>⋯ › Stop managing, keep it in IIS (docs/design/gui-redesign.md, step 4).</summary>
public sealed class StopManagingViewModelTests
{
    private readonly Mock<ICertificateManagementService> _management = new();

    [Fact]
    public async Task StopManaging_AsksCore_ThenClearsTheCertificate_AndReportsWhatHappened()
    {
        _management.Setup(value => value.StopManagingAsync("Main/www.domain3.co.uk", It.IsAny<CancellationToken>()))
            .ReturnsAsync("SSLense no longer manages the certificate.");
        var details = Details();
        string? reported = null;
        details.CertificatesChanged += message => reported = message;
        await details.ShowAsync(Domain3());

        Assert.True(details.UnmanageCommand.CanExecute(null));
        await details.UnmanageCommand.ExecuteAsync(null);

        _management.Verify(value => value.StopManagingAsync("Main/www.domain3.co.uk", It.IsAny<CancellationToken>()), Times.Once);
        _management.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.Equal("SSLense no longer manages the certificate.", reported);
        Assert.Null(details.SelectedSite);
    }

    [Fact]
    public async Task StopManaging_WhenCoreRefuses_KeepsTheCertificate_AndShowsWhy()
    {
        _management.Setup(value => value.StopManagingAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Use share remove."));
        var details = Details();
        var changed = false;
        details.CertificatesChanged += _ => changed = true;
        await details.ShowAsync(Domain3());

        await details.UnmanageCommand.ExecuteAsync(null);

        Assert.Equal("Use share remove.", details.ErrorMessage);
        Assert.Equal("Main/www.domain3.co.uk", details.SelectedSite);
        Assert.False(changed);
    }

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

    private static CertificateRowViewModel Domain3() =>
        new(new ManagedCertificateStatus("Main/www.domain3.co.uk", ["www.domain3.co.uk"], DateTimeOffset.UtcNow.AddDays(-356),
            DateTimeOffset.UtcNow.AddDays(9), 9, "AA03", null, null, null, Source: CertificateSource.Imported));
}

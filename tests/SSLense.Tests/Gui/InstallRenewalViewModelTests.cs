using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Renewal;
using SSLense.Gui.ViewModels;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>The Install renewal dialog (docs/design/gui-redesign.md, step 2).</summary>
public sealed class InstallRenewalViewModelTests : IDisposable
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly Mock<IImportedCertificateService> _service = new();
    private readonly Mock<IPendingRequestStore> _pending = new();
    private readonly Mock<INavigationService> _navigation = new();
    private readonly string _file = Path.GetTempFileName();

    public InstallRenewalViewModelTests() => File.WriteAllBytes(_file, [1, 2, 3]);

    public void Dispose() => File.Delete(_file);

    [Fact]
    public async Task Opening_WithoutARequest_AsksForAPfx_AndNeedsAFileToContinue()
    {
        var dialog = Dialog();

        await dialog.OpenAsync(Domain3());

        Assert.True(dialog.IsOpen);
        Assert.True(dialog.UsePfx);
        Assert.False(dialog.HasPendingRequest);
        Assert.Equal(InstallRenewalViewModel.ChooseStep, dialog.Step);
        Assert.False(dialog.NextCommand.CanExecute(null));
        dialog.PfxPath = _file;
        Assert.True(dialog.NextCommand.CanExecute(null));
    }

    [Fact]
    public async Task Opening_WithTheCertificatesRequest_AsksForTheProvidersCertificate()
    {
        _pending.Setup(value => value.GetAsync("Main/www.domain3.co.uk", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PendingCertificateRequest("Main/www.domain3.co.uk", ["www.domain3.co.uk"], "key", "RSA2048", "csr", Now));
        var dialog = Dialog();

        await dialog.OpenAsync(Domain3());

        Assert.True(dialog.HasPendingRequest);
        Assert.False(dialog.UsePfx);
    }

    [Fact]
    public async Task APfx_IsInstalledForTheSite_WithThisCertificatesHostNames_SoOnlyItIsReplaced()
    {
        _service.Setup(value => value.ImportPfxAsync("Main", It.IsAny<IReadOnlyList<string>>(), It.IsAny<byte[]>(), "secret", false,
                It.IsAny<IProgress<ProgressEvent>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result());
        var dialog = Dialog();
        var installed = 0;
        dialog.Installed += () => installed++;
        await dialog.OpenAsync(Domain3());
        dialog.PfxPath = _file;
        dialog.PfxPassword = "secret";
        dialog.NextCommand.Execute(null);

        await dialog.InstallCommand.ExecuteAsync(null);

        _service.Verify(value => value.ImportPfxAsync("Main", It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "www.domain3.co.uk" })),
            It.IsAny<byte[]>(), "secret", false, It.IsAny<IProgress<ProgressEvent>>(), It.IsAny<CancellationToken>()));
        Assert.Equal(InstallRenewalViewModel.DoneStep, dialog.Step);
        Assert.Equal(1, installed);
        Assert.Empty(dialog.PfxPassword);
        Assert.Contains("valid until", dialog.ResultText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheProvidersCertificate_CompletesTheRequest_ForThisCertificatesName()
    {
        _pending.Setup(value => value.GetAsync("Main/www.domain3.co.uk", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new PendingCertificateRequest("Main/www.domain3.co.uk", ["www.domain3.co.uk"], "key", "RSA2048", "csr", Now));
        _service.Setup(value => value.CompleteRequestAsync("Main/www.domain3.co.uk", It.IsAny<byte[]>(), null, false,
                It.IsAny<IProgress<ProgressEvent>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Result());
        var dialog = Dialog();
        await dialog.OpenAsync(Domain3());
        dialog.CertificatePath = _file;

        await dialog.InstallCommand.ExecuteAsync(null);

        Assert.Equal(InstallRenewalViewModel.DoneStep, dialog.Step);
    }

    [Fact]
    public async Task AFailure_IsShown_AndNothingIsReportedInstalled()
    {
        _service.Setup(value => value.ImportPfxAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<byte[]>(), It.IsAny<string>(), false,
                It.IsAny<IProgress<ProgressEvent>>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("The PFX password is wrong."));
        var dialog = Dialog();
        var installed = 0;
        dialog.Installed += () => installed++;
        await dialog.OpenAsync(Domain3());
        dialog.PfxPath = _file;
        dialog.NextCommand.Execute(null);

        await dialog.InstallCommand.ExecuteAsync(null);

        Assert.Equal("The PFX password is wrong.", dialog.ErrorMessage);
        Assert.Equal(InstallRenewalViewModel.ConfirmStep, dialog.Step);
        Assert.Equal(0, installed);
    }

    [Fact]
    public async Task CreateARequest_ClosesTheDialog_AndOpensTheRequestForThisCertificate()
    {
        var dialog = Dialog();
        await dialog.OpenAsync(Domain3());

        dialog.CreateRequestCommand.Execute(null);

        Assert.False(dialog.IsOpen);
        _navigation.Verify(value => value.Navigate("Certificate request", "Main/www.domain3.co.uk"));
    }

    private InstallRenewalViewModel Dialog() =>
        new(_service.Object, _pending.Object, _navigation.Object, NullLogger<InstallRenewalViewModel>.Instance);

    private static CertificateRowViewModel Domain3() =>
        new(new ManagedCertificateStatus("Main/www.domain3.co.uk", ["www.domain3.co.uk"], Now.AddDays(-356), Now.AddDays(9), 9, "AA03",
            null, null, null, Source: CertificateSource.Imported));

    private static ImportResult Result() =>
        new(new ManagedCertificate("Main/www.domain3.co.uk", ["www.domain3.co.uk"], string.Empty, "BB03", Now, Now.AddDays(365),
            Source: CertificateSource.Imported), []);
}

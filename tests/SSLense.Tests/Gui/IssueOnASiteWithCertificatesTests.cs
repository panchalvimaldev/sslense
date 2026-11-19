using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using SSLense.Gui.ViewModels;
using Xunit;

namespace SSLense.Tests.Gui;

/// <summary>
/// Add certificate › Free and automatic on a site that already has certificates
/// (docs/design/multiple-certificates-per-site.md, section 9.4).
/// </summary>
public sealed class IssueOnASiteWithCertificatesTests
{
    private static readonly DateTimeOffset Expires = new(2026, 11, 27, 12, 0, 0, TimeSpan.Zero);

    private static readonly IisSite Main = new(1, "Main", "Started", @"C:\inetpub\main",
    [
        new IisBinding("http", "*", 80, "www.domain1.co.uk", null, null, false),
        new IisBinding("http", "*", 80, "www.domain2.co.uk", null, null, false),
        new IisBinding("http", "*", 80, "www.domain3.co.uk", null, null, false)
    ]);

    private static readonly CertificateAuthorityOverview Staging = new(CertificateAuthorities.LetsEncryptStagingId, "Let's Encrypt staging",
        new Uri("https://acme-staging-v02.api.letsencrypt.org/directory"), true, true, false, ["letsencrypt.org"], []);

    private static ManagedCertificate Record(string name, string host, CertificateSource source) =>
        new(name, [host], "ops@example.com", "AA", Expires.AddDays(-300), Expires, Source: source);

    [Fact]
    public async Task OnASiteWithTwoCertificates_TheirHostNamesAreMarked_AndOnlyTheNewOneIsTicked()
    {
        var wizard = await Open(
            Record("Main", "www.domain1.co.uk", CertificateSource.Acme),
            Record("Main/www.domain2.co.uk", "www.domain2.co.uk", CertificateSource.Imported));

        Assert.Equal("Managed as Main", Host(wizard, "www.domain1.co.uk").Owner);
        Assert.Equal("Managed as Main/www.domain2.co.uk, bought", Host(wizard, "www.domain2.co.uk").Owner);
        Assert.Equal(string.Empty, Host(wizard, "www.domain3.co.uk").Owner);
        Assert.Equal(["www.domain3.co.uk"], wizard.Hosts.Where(host => host.IsSelected).Select(host => host.Host));
        Assert.Equal("Adds a certificate to IIS site Main, managed as Main/www.domain3.co.uk. The site's other certificates stay as they are.", wizard.Outcome);
        Assert.True(wizard.NextCommand.CanExecute(null));
    }

    [Fact]
    public async Task TheHostNamesOfABoughtCertificate_SayItIsReplaced()
    {
        var wizard = await Open(
            Record("Main", "www.domain1.co.uk", CertificateSource.Acme),
            Record("Main/www.domain2.co.uk", "www.domain2.co.uk", CertificateSource.Imported));

        Host(wizard, "www.domain3.co.uk").IsSelected = false;
        Host(wizard, "www.domain2.co.uk").IsSelected = true;

        Assert.StartsWith("Replaces the certificate managed as Main/www.domain2.co.uk (bought, expires ", wizard.Outcome, StringComparison.Ordinal);
        Assert.False(wizard.HasOutcomeProblem);
    }

    [Fact]
    public async Task TheHostNamesOfTwoCertificates_CannotGoOn()
    {
        var wizard = await Open(
            Record("Main", "www.domain1.co.uk", CertificateSource.Acme),
            Record("Main/www.domain2.co.uk", "www.domain2.co.uk", CertificateSource.Imported));

        Host(wizard, "www.domain1.co.uk").IsSelected = true;
        Host(wizard, "www.domain2.co.uk").IsSelected = true;

        Assert.True(wizard.HasOutcomeProblem);
        Assert.Contains("belong to 2 certificates", wizard.Outcome, StringComparison.Ordinal);
        Assert.False(wizard.NextCommand.CanExecute(null));
    }

    [Fact]
    public async Task OnASiteWithOneCertificate_EveryReadyHostNameIsTickedAsBefore()
    {
        var wizard = await Open(Record("Main", "www.domain1.co.uk", CertificateSource.Acme));

        Assert.All(wizard.Hosts, host => Assert.True(host.IsSelected));
        Assert.StartsWith("Replaces the certificate managed as Main (renews automatically, expires ", wizard.Outcome, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OnASiteWithNoCertificate_NothingIsMarkedOrExplained()
    {
        var wizard = await Open();

        Assert.All(wizard.Hosts, host => Assert.True(host.IsSelected && !host.HasOwner));
        Assert.False(wizard.HasOutcome);
    }

    [Fact]
    public async Task RenewingASecondCertificateByHand_IssuesUnderItsOwnName()
    {
        var second = Record("Main/www.domain2.co.uk", "www.domain2.co.uk", CertificateSource.Acme) with
        {
            ValidationMethod = ValidationMethod.Dns01Manual,
            AuthorityId = CertificateAuthorities.LetsEncryptStagingId
        };
        AcmeIssueRequest? sent = null;
        var acme = new Mock<IAcmeService>();
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), It.IsAny<IProgress<SSLense.Core.ProgressEvent>>(), It.IsAny<CancellationToken>()))
            .Callback<AcmeIssueRequest, IProgress<SSLense.Core.ProgressEvent>?, CancellationToken>((request, _, _) => sent = request)
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, ["www.domain2.co.uk"], Name: second.SiteName));
        var wizard = await Open(acme.Object, [Record("Main", "www.domain1.co.uk", CertificateSource.Acme), second], second.SiteName);

        Assert.True(wizard.IsRenewingByHand);
        Assert.Equal("Main", wizard.SelectedSite!.Name);
        Assert.Equal(["www.domain2.co.uk"], wizard.Hosts.Where(host => host.IsSelected).Select(host => host.Host));
        Assert.False(wizard.HasOutcome);
        wizard.PreflightPassed = true;
        await wizard.IssueCommand.ExecuteAsync(null);

        Assert.Null(wizard.ErrorMessage);
        Assert.Equal("Main/www.domain2.co.uk", sent!.SiteName);
        Assert.Equal(["www.domain2.co.uk"], sent.Hosts);
        Assert.Equal("AA", sent.ExpectedCurrentThumbprint);
    }

    private static HostOptionViewModel Host(IssueCertificateViewModel wizard, string host) => wizard.Hosts.Single(value => value.Host == host);

    private static Task<IssueCertificateViewModel> Open(params ManagedCertificate[] records) => Open(Mock.Of<IAcmeService>(), records);

    private static async Task<IssueCertificateViewModel> Open(IAcmeService acme, ManagedCertificate[] records, string? renewSite = null)
    {
        var wizard = new IssueCertificateViewModel(
            Mock.Of<IIisService>(value => value.GetSitesAsync(It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<IisSite>>(new[] { Main })),
            Mock.Of<IPreflightService>(),
            acme,
            Mock.Of<ISettingsService>(value => value.GetAsync(It.IsAny<CancellationToken>()) == Task.FromResult(new AppConfig())),
            Mock.Of<IImportedCertificateService>(value => value.DiscoverAsync(It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<DiscoveredBinding>>(Array.Empty<DiscoveredBinding>())),
            Mock.Of<IManagedCertificateStore>(value => value.GetAllAsync(It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<ManagedCertificate>>(records)),
            Mock.Of<ICertificateAuthorityService>(value => value.ListAsync(It.IsAny<CancellationToken>()) == Task.FromResult<IReadOnlyList<CertificateAuthorityOverview>>(new[] { Staging })),
            NullLogger<IssueCertificateViewModel>.Instance);
        await wizard.InitializeAsync(renewSite);
        Assert.Null(wizard.ErrorMessage);
        return wizard;
    }
}

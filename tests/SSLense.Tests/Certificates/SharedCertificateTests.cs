using Moq;
using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>The rules in docs/design/shared-certificates.md, sections 3 to 6.</summary>
public sealed class SharedCertificateTests
{
    private const string Old = "OLD";
    private const string New = "AABBCC";

    private static ManagedCertificate Shared(int daysLeft = 60, params CertificateTarget[] others) => new(
        "Shop",
        ["shop.example.com"],
        "admin@example.com",
        Old,
        DateTimeOffset.UtcNow.AddDays(-5),
        DateTimeOffset.UtcNow.AddDays(daysLeft),
        ValidationMethod: ValidationMethod.Dns01Provider,
        CertificateNames: ["*.example.com"],
        AdditionalTargets: others.Length > 0 ? others : [new CertificateTarget("Blog", ["blog.example.com"])]);

    private static IisSite Site(string name, string host, string state = "Started", string? thumbprint = Old) =>
        new(1, name, state, "C:\\inetpub\\site", [new IisBinding("https", "*", 443, host, thumbprint, "My", true)]);

    private static HttpsBindingUndo Undo(string site) => new(site, true, []);

    private static IisBindingException Failure(bool restored = true) =>
        new("The site failed.", restored, new InvalidOperationException("inner"));

    [Fact]
    public void AllTargets_StartsWithTheFirstSite_AndWithTargetsCanPromoteAnother()
    {
        var record = Shared();

        Assert.Equal(["Shop", "Blog"], record.AllSiteNames());
        Assert.True(record.ManagesSite("BLOG"));
        var promoted = record.WithTargets(record.AllTargets().Skip(1).ToArray());
        Assert.Equal("Blog", promoted.SiteName);
        Assert.Equal(["blog.example.com"], promoted.Hosts);
        Assert.False(promoted.IsShared());
    }

    [Fact]
    public async Task AcquireAll_TakesLocksInSortedOrder_WhateverOrderTheSitesAreIn()
    {
        var taken = new List<string>();
        var locks = new Mock<ICertificateOperationLock>();
        locks.Setup(value => value.AcquireAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((site, _) => taken.Add(site))
            .ReturnsAsync(Mock.Of<IAsyncDisposable>());

        await using (await locks.Object.AcquireAllAsync(["Shop", "blog", "BLOG", "Admin"]))
        {
            Assert.Equal(["Admin", "blog", "Shop"], taken);
        }
    }

    [Fact]
    public async Task TryAcquireAll_OneLockHeld_ReleasesTheOthersAndReturnsNull()
    {
        var first = new Mock<IAsyncDisposable>();
        var locks = new Mock<ICertificateOperationLock>();
        locks.Setup(value => value.TryAcquire("Blog")).Returns(first.Object);
        locks.Setup(value => value.TryAcquire("Shop")).Returns((IAsyncDisposable?)null);

        await using var held = locks.Object.TryAcquireAll(["Shop", "Blog"]);

        Assert.Null(held);
        first.Verify(value => value.DisposeAsync(), Times.Once);
    }

    private static CertificateTarget[] TwoTargets() =>
        [new("Shop", ["shop.example.com"]), new("Blog", ["blog.example.com"])];

    [Fact]
    public async Task Transaction_RefusedCertificate_ChangesNoSite()
    {
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.TryCertificateAsync(New, "My", It.IsAny<CancellationToken>())).ThrowsAsync(Failure());

        var exception = await Assert.ThrowsAsync<IisBindingException>(() =>
            SharedBindingTransaction.ApplyAsync(iis.Object, TwoTargets(), New, false, null, CancellationToken.None));

        Assert.True(exception.PreviousBindingsRestored);
    }

    private static Mock<IIisService> TransactionIis(Exception? blogFailure)
    {
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.SwitchHttpsBindingsAsync("Shop", It.IsAny<IReadOnlyList<string>>(), New, "My", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Undo("Shop"));
        var blog = iis.Setup(value => value.SwitchHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), New, "My", It.IsAny<CancellationToken>()));
        if (blogFailure is null)
        {
            blog.ReturnsAsync(Undo("Blog"));
        }
        else
        {
            blog.ThrowsAsync(blogFailure);
        }

        return iis;
    }

    [Fact]
    public async Task Transaction_Failure_PutsBackSitesAlreadyChanged()
    {
        var iis = TransactionIis(Failure());

        var exception = await Assert.ThrowsAsync<IisBindingException>(() =>
            SharedBindingTransaction.ApplyAsync(iis.Object, TwoTargets(), New, false, null, CancellationToken.None));

        Assert.True(exception.PreviousBindingsRestored);
        iis.Verify(value => value.UndoHttpsBindingsAsync(It.Is<HttpsBindingUndo>(undo => undo.SiteName == "Shop"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Transaction_RestoreFails_NamesTheSiteAndSaysSo()
    {
        var iis = TransactionIis(Failure());
        iis.Setup(value => value.UndoHttpsBindingsAsync(It.IsAny<HttpsBindingUndo>(), It.IsAny<CancellationToken>())).ThrowsAsync(Failure(false));

        var exception = await Assert.ThrowsAsync<IisBindingException>(() =>
            SharedBindingTransaction.ApplyAsync(iis.Object, TwoTargets(), New, false, null, CancellationToken.None));

        Assert.False(exception.PreviousBindingsRestored);
        Assert.Contains("'Shop'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Transaction_FailedSiteNotRestored_IsNotReportedAsRestored()
    {
        var iis = TransactionIis(Failure(false));

        var exception = await Assert.ThrowsAsync<IisBindingException>(() =>
            SharedBindingTransaction.ApplyAsync(iis.Object, TwoTargets(), New, false, null, CancellationToken.None));

        Assert.False(exception.PreviousBindingsRestored);
        Assert.Contains("'Blog'", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Transaction_LastDays_LeavesOutOnlyTheFailedSite()
    {
        var iis = TransactionIis(Failure());

        var leftOut = await SharedBindingTransaction.ApplyAsync(iis.Object, TwoTargets(), New, true, null, CancellationToken.None);

        Assert.Equal("Blog", Assert.Single(leftOut).SiteName);
        iis.Verify(value => value.UndoHttpsBindingsAsync(It.IsAny<HttpsBindingUndo>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private sealed class FakeDns : IDnsChallengeService
    {
        public Task CheckBeforeOrderAsync(ValidationMethod method, IReadOnlyList<string> certificateNames, string authorityId, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IAsyncDisposable> PublishAsync(
            ValidationMethod method,
            IReadOnlyList<AcmeDnsChallenge> challenges,
            ManualDnsConfirmation? confirmManual,
            IProgress<ProgressEvent>? progress,
            CancellationToken cancellationToken) =>
            Task.FromResult(Mock.Of<IAsyncDisposable>());

        public Task<IReadOnlyList<string>> CleanUpAbandonedAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>([]);
    }

    private sealed class IssueHarness
    {
        public IssueHarness(ManagedCertificate record, params IisSite[] sites)
        {
            Managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([record]);
            Iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(sites);
            Iis.Setup(value => value.TryCertificateAsync(New, "My", It.IsAny<CancellationToken>()))
                .Callback(() => Steps.Add("trial"))
                .Returns(Task.CompletedTask);
            Iis.Setup(value => value.SwitchHttpsBindingsAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), New, "My", It.IsAny<CancellationToken>()))
                .Callback<string, IReadOnlyList<string>, string, string, CancellationToken>((site, _, _, _, _) => Steps.Add($"switch {site}"))
                .ReturnsAsync((string site, IReadOnlyList<string> _, string _, string _, CancellationToken _) => Undo(site));
            var challenge = new AcmeDnsChallenge("example.com", true, "_acme-challenge.example.com", "value");
            var order = new Mock<IAcmeOrderSession>();
            order.SetupGet(value => value.DnsChallenges).Returns([challenge]);
            using var key = System.Security.Cryptography.RSA.Create(2048);
            using var certificate = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                    "CN=example.com",
                    key,
                    System.Security.Cryptography.HashAlgorithmName.SHA256,
                    System.Security.Cryptography.RSASignaturePadding.Pkcs1)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
            order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new CertificateBundle(certificate.ExportCertificatePem(), [1, 2, 3]));
            Protocol.Setup(value => value.CreateDnsOrderAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(order.Object);
            Store.Setup(value => value.ImportPfxAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstalledCertificate(New, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
            var artifacts = new Mock<ICertificateArtifactStore>();
            artifacts.Setup(value => value.SaveAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, []));
            Service = new AcmeService(
                Iis.Object,
                Protocol.Object,
                Mock.Of<IChallengeHandler>(MockBehavior.Strict),
                Mock.Of<IChallengeProbe>(MockBehavior.Strict),
                artifacts.Object,
                Store.Object,
                Managed.Object,
                dnsChallenges: new FakeDns());
        }

        public List<string> Steps { get; } = [];
        public Mock<IIisService> Iis { get; } = new();
        public Mock<IManagedCertificateStore> Managed { get; } = new();
        public Mock<IAcmeProtocolClient> Protocol { get; } = new();
        public Mock<ICertificateStore> Store { get; } = new();
        public AcmeService Service { get; }

        public void VerifyNothingOrdered() =>
            Protocol.Verify(value => value.CreateDnsOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()), Times.Never);

        public void VerifySavedNothing() =>
            Managed.Verify(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()), Times.Never);

        public ManagedCertificate SavedRecord() =>
            (ManagedCertificate)Managed.Invocations.Single(invocation => invocation.Method.Name == nameof(IManagedCertificateStore.UpsertAsync)).Arguments[0];
    }

    private static AcmeIssueRequest Renewal(string site = "Shop", string[]? names = null) => new(
        site,
        ["shop.example.com"],
        "admin@example.com",
        Force: true,
        ExpectedCurrentThumbprint: Old,
        ValidationMethod: ValidationMethod.Dns01Provider,
        CertificateNames: names ?? ["*.example.com"]);

    [Fact]
    public async Task Issue_MovesEverySite_AfterTheTrial_AndKeepsThemInTheRecord()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));

        var result = await harness.Service.IssueAsync(Renewal());

        Assert.Equal(["trial", "switch Shop", "switch Blog"], harness.Steps);
        Assert.Empty(result.LeftOutSites!);
        var saved = harness.SavedRecord();
        Assert.Equal(New, saved.Thumbprint);
        Assert.Equal("Blog", Assert.Single(saved.AdditionalTargets!).SiteName);
        Assert.False(saved.HasPendingSites());
    }

    [Fact]
    public async Task Issue_DeletedSite_IsLeftOut_AndTheOthersRenew()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"));

        var result = await harness.Service.IssueAsync(Renewal());

        Assert.Equal(["trial", "switch Shop"], harness.Steps);
        Assert.Equal("Blog", Assert.Single(result.LeftOutSites!).SiteName);
        Assert.NotNull(Assert.Single(harness.SavedRecord().AdditionalTargets!).PendingSince);
    }

    [Fact]
    public async Task Issue_RemovedBinding_IsLeftOut_AndTheOthersRenew()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "other.example.com"));

        var result = await harness.Service.IssueAsync(Renewal());

        Assert.Equal(["trial", "switch Shop"], harness.Steps);
        Assert.Contains("blog.example.com", Assert.Single(result.LeftOutSites!).Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Issue_StoppedSite_IsIncluded_WithoutCheckingIt()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com", "Stopped"));

        await harness.Service.IssueAsync(Renewal());

        Assert.Equal(["trial", "switch Shop", "switch Blog"], harness.Steps);
        harness.Iis.Verify(value => value.GetHttpsProblemAsync(It.Is<IisSite>(site => site.Name == "Blog"), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    private static void BlogNotAnswering(IssueHarness harness) =>
        harness.Iis.Setup(value => value.GetHttpsProblemAsync(It.Is<IisSite>(site => site.Name == "Blog"), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync("blog.example.com did not answer.");

    [Fact]
    public async Task Issue_SiteNotAnswering_OrdersNothing_WhileThereIsTime()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        BlogNotAnswering(harness);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(Renewal()));

        Assert.Contains("'Blog'", exception.Message, StringComparison.Ordinal);
        harness.VerifyNothingOrdered();
        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task Issue_SiteNotAnswering_IsLeftOut_InTheLastDays()
    {
        var harness = new IssueHarness(Shared(daysLeft: 6), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        BlogNotAnswering(harness);

        var result = await harness.Service.IssueAsync(Renewal());

        Assert.Equal(["trial", "switch Shop"], harness.Steps);
        Assert.Equal("Blog", Assert.Single(result.LeftOutSites!).SiteName);
    }

    private static void BlogFailsTheSwitch(IssueHarness harness, bool restored = true) =>
        harness.Iis.Setup(value => value.SwitchHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), New, "My", It.IsAny<CancellationToken>()))
            .ThrowsAsync(Failure(restored));

    [Fact]
    public async Task Issue_SiteFailsTheSwitch_PutsEverySiteBack_AndRemovesTheNewCertificate()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        BlogFailsTheSwitch(harness);

        await Assert.ThrowsAsync<IisBindingException>(() => harness.Service.IssueAsync(Renewal()));

        harness.Iis.Verify(value => value.UndoHttpsBindingsAsync(It.Is<HttpsBindingUndo>(undo => undo.SiteName == "Shop"), It.IsAny<CancellationToken>()), Times.Once);
        harness.Store.Verify(value => value.RemoveAsync(New, It.IsAny<CancellationToken>()), Times.Once);
        harness.VerifySavedNothing();
    }

    [Fact]
    public async Task Issue_SiteCannotBeRestored_KeepsTheNewCertificate()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        BlogFailsTheSwitch(harness, restored: false);

        var exception = await Assert.ThrowsAsync<IisBindingException>(() => harness.Service.IssueAsync(Renewal()));

        Assert.False(exception.PreviousBindingsRestored);
        harness.Store.Verify(value => value.RemoveAsync(New, It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Issue_SiteFailsTheSwitch_InTheLastDays_OnlyThatSiteStaysBehind()
    {
        var harness = new IssueHarness(Shared(daysLeft: 6), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        BlogFailsTheSwitch(harness);

        var result = await harness.Service.IssueAsync(Renewal());

        Assert.Equal("Blog", Assert.Single(result.LeftOutSites!).SiteName);
        Assert.NotNull(Assert.Single(harness.SavedRecord().AdditionalTargets!).PendingSince);
        harness.Iis.Verify(value => value.UndoHttpsBindingsAsync(It.IsAny<HttpsBindingUndo>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Issue_TrialRefused_ChangesNoSite_AndRemovesTheNewCertificate()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        harness.Iis.Setup(value => value.TryCertificateAsync(New, "My", It.IsAny<CancellationToken>())).ThrowsAsync(Failure());

        await Assert.ThrowsAsync<IisBindingException>(() => harness.Service.IssueAsync(Renewal()));

        Assert.Empty(harness.Steps);
        harness.Store.Verify(value => value.RemoveAsync(New, It.IsAny<CancellationToken>()), Times.Once);
        harness.VerifySavedNothing();
    }

    [Fact]
    public async Task Issue_NamesThatStopCoveringASite_AreRefusedBeforeAnOrder()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            harness.Service.IssueAsync(Renewal(names: ["shop.example.com"])));

        Assert.Contains("blog.example.com", exception.Message, StringComparison.Ordinal);
        harness.VerifyNothingOrdered();
    }

    [Fact]
    public async Task Issue_OnAnAdditionalSite_IsRefused_AndNamesTheCertificateThatManagesIt()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(Renewal("Blog")));

        Assert.Contains("'Shop'", exception.Message, StringComparison.Ordinal);
        harness.VerifyNothingOrdered();
    }

    [Fact]
    public async Task Issue_SitesChangeWhileWaitingForTheLocks_Stops()
    {
        var harness = new IssueHarness(Shared(), Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));
        harness.Managed.SetupSequence(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([Shared()])
            .ReturnsAsync([Shared(others: new CertificateTarget("Admin", ["admin.example.com"]))]);

        await Assert.ThrowsAsync<CertificateStateChangedException>(() => harness.Service.IssueAsync(Renewal()));

        harness.VerifyNothingOrdered();
    }

    private sealed class SharingHarness
    {
        public SharingHarness(IReadOnlyList<ManagedCertificate> records, params IisSite[] sites)
        {
            Managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(records);
            Iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(sites);
            Store.Setup(value => value.FindByThumbprintAsync(Old, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstalledCertificate(Old, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
            Service = new CertificateSharingService(
                Managed.Object,
                Store.Object,
                Iis.Object,
                new NoOpCertificateOperationLock(),
                new NoOpCertificateTransactionJournal());
        }

        public Mock<IManagedCertificateStore> Managed { get; } = new();
        public Mock<IIisService> Iis { get; } = new();
        public Mock<ICertificateStore> Store { get; } = new();
        public CertificateSharingService Service { get; }

        public void VerifyNothingChanged()
        {
            Iis.Verify(value => value.ConfigureHttpsBindingsAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            Managed.Verify(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        public ManagedCertificate SavedRecord() =>
            (ManagedCertificate)Managed.Invocations.Single(invocation => invocation.Method.Name == nameof(IManagedCertificateStore.UpsertAsync)).Arguments[0];
    }

    private static ManagedCertificate SingleSite(ValidationMethod method = ValidationMethod.Dns01Provider, string site = "Shop", string thumbprint = Old, CertificateSource source = CertificateSource.Acme) => new(
        site,
        [site == "Shop" ? "shop.example.com" : "blog.example.com"],
        "admin@example.com",
        thumbprint,
        DateTimeOffset.UtcNow.AddDays(-5),
        DateTimeOffset.UtcNow.AddDays(60),
        ValidationMethod: method,
        Source: source,
        CertificateNames: method == ValidationMethod.Http01 ? null : ["*.example.com"]);

    [Fact]
    public async Task Add_BindsTheSite_AndRecordsIt()
    {
        var harness = new SharingHarness([SingleSite()], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com", thumbprint: null));

        var bound = await harness.Service.AddSiteAsync("Shop", "Blog", []);

        Assert.Equal(["blog.example.com"], bound);
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, "My", It.IsAny<CancellationToken>()), Times.Once);
        Assert.Equal(["Shop", "Blog"], harness.SavedRecord().AllSiteNames());
    }

    [Fact]
    public async Task Add_FromAnAdditionalSite_FindsTheSameCertificate()
    {
        var harness = new SharingHarness([Shared()], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"), Site("Admin", "admin.example.com", thumbprint: null));

        await harness.Service.AddSiteAsync("Blog", "Admin", []);

        Assert.Equal(["Shop", "Blog", "Admin"], harness.SavedRecord().AllSiteNames());
    }

    [Fact]
    public async Task Add_ToAnHttpCertificate_IsRefused()
    {
        var harness = new SharingHarness([SingleSite(ValidationMethod.Http01)], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.AddSiteAsync("Shop", "Blog", []));

        Assert.Contains("DNS validation", exception.Message, StringComparison.Ordinal);
        harness.VerifyNothingChanged();
    }

    [Fact]
    public async Task Add_AnImportedCertificate_IsRefused()
    {
        var harness = new SharingHarness([SingleSite(source: CertificateSource.Imported)], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.AddSiteAsync("Shop", "Blog", []));

        harness.VerifyNothingChanged();
    }

    [Fact]
    public async Task Add_AHostTheCertificateDoesNotCover_IsRefused()
    {
        var harness = new SharingHarness([SingleSite()], Site("Shop", "shop.example.com"), Site("Blog", "blog.other.net"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.AddSiteAsync("Shop", "Blog", ["blog.other.net"]));

        harness.VerifyNothingChanged();
    }

    [Fact]
    public async Task Add_AHostAlreadyBoundOnAnotherSite_IsRefused()
    {
        var harness = new SharingHarness(
            [SingleSite()],
            Site("Shop", "shop.example.com"),
            Site("Blog", "blog.example.com"),
            Site("Admin", "blog.example.com"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.AddSiteAsync("Shop", "Blog", ["blog.example.com"]));

        Assert.Contains("'Admin'", exception.Message, StringComparison.Ordinal);
        harness.VerifyNothingChanged();
    }

    [Fact]
    public async Task Add_ASiteWithItsOwnCertificate_NeedsReplaceExisting()
    {
        var harness = new SharingHarness(
            [SingleSite(), SingleSite(site: "Blog", thumbprint: "BLOGCERT")],
            Site("Shop", "shop.example.com"),
            Site("Blog", "blog.example.com", thumbprint: "BLOGCERT"));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.AddSiteAsync("Shop", "Blog", []));

        Assert.Contains("--replace-existing", exception.Message, StringComparison.Ordinal);
        harness.VerifyNothingChanged();
    }

    [Theory]
    [InlineData(CertificateSource.Acme, true)]
    [InlineData(CertificateSource.Imported, false)]
    public async Task Add_ReplaceExisting_RemovesTheOldRecord_AndOnlyAnAcmeCertificate(CertificateSource source, bool removed)
    {
        var harness = new SharingHarness(
            [SingleSite(), SingleSite(site: "Blog", thumbprint: "BLOGCERT", source: source)],
            Site("Shop", "shop.example.com"),
            Site("Blog", "blog.example.com", thumbprint: Old));

        await harness.Service.AddSiteAsync("Shop", "Blog", [], replaceExisting: true);

        harness.Managed.Verify(value => value.RemoveAsync("Blog", It.IsAny<CancellationToken>()), Times.Once);
        harness.Store.Verify(value => value.RemoveAsync("BLOGCERT", It.IsAny<CancellationToken>()), removed ? Times.Once() : Times.Never());
    }

    [Fact]
    public async Task Add_RestoredAfterFailure_SavesNothing()
    {
        var harness = new SharingHarness([SingleSite()], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com", thumbprint: null));
        harness.Iis.Setup(value => value.ConfigureHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, "My", It.IsAny<CancellationToken>()))
            .ThrowsAsync(Failure());

        await Assert.ThrowsAsync<IisBindingException>(() => harness.Service.AddSiteAsync("Shop", "Blog", []));

        harness.Managed.Verify(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Remove_AnAdditionalSite_ChangesNoBinding()
    {
        var harness = new SharingHarness([Shared()]);

        var message = await harness.Service.RemoveSiteAsync("Blog");

        Assert.Contains("was not changed", message, StringComparison.Ordinal);
        harness.Managed.Verify(value => value.ReplaceAsync("Shop", It.Is<ManagedCertificate>(record => record.SiteName == "Shop" && !record.IsShared()), It.IsAny<CancellationToken>()), Times.Once);
        Assert.DoesNotContain(harness.Iis.Invocations, invocation => invocation.Method.Name != nameof(IIisService.GetSitesAsync));
    }

    [Fact]
    public async Task Remove_TheFirstSite_PromotesTheNext()
    {
        var harness = new SharingHarness([Shared()]);

        await harness.Service.RemoveSiteAsync("Shop");

        harness.Managed.Verify(value => value.ReplaceAsync("Shop", It.Is<ManagedCertificate>(record => record.SiteName == "Blog" && record.Hosts[0] == "blog.example.com"), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Remove_TheLastSite_IsRefused()
    {
        var harness = new SharingHarness([SingleSite()]);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.RemoveSiteAsync("Shop"));

        Assert.Contains("SSLense.Cli remove", exception.Message, StringComparison.Ordinal);
    }

    private static ManagedCertificate BlogPending() =>
        Shared(others: new CertificateTarget("Blog", ["blog.example.com"], DateTimeOffset.UtcNow.AddDays(-1)));

    [Fact]
    public async Task CatchUp_MovesAPendingSite_AndClearsIt()
    {
        var harness = new SharingHarness([BlogPending()], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com", thumbprint: "PREVIOUS"));

        var moved = await harness.Service.CatchUpAsync("Shop");

        Assert.Equal(["Blog"], moved);
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, "My", It.IsAny<CancellationToken>()), Times.Once);
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync("Shop", It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.False(harness.SavedRecord().HasPendingSites());
    }

    [Fact]
    public async Task CatchUp_StillFailing_StaysPending_AndSavesNothing()
    {
        var harness = new SharingHarness([BlogPending()], Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com", thumbprint: "PREVIOUS"));
        harness.Iis.Setup(value => value.ConfigureHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, "My", It.IsAny<CancellationToken>()))
            .ThrowsAsync(Failure());

        Assert.Empty(await harness.Service.CatchUpAsync("Shop"));

        harness.Managed.Verify(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task CatchUp_ADeletedSite_IsSkippedWithoutTryingIt()
    {
        var harness = new SharingHarness([BlogPending()], Site("Shop", "shop.example.com"));

        Assert.Empty(await harness.Service.CatchUpAsync("Shop"));

        harness.VerifyNothingChanged();
    }

    private static RenewalService Renewals(
        Mock<IManagedCertificateStore> managed,
        Mock<IAcmeService> acme,
        Mock<INotifier> notifier,
        ICertificateSharingService? sharing = null)
    {
        var config = new Mock<IConfigStore>();
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new AppConfig { RenewalThresholdDays = 30 });
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        return new RenewalService(managed.Object, config.Object, acme.Object, iis.Object, Mock.Of<ICertificateStore>(), notifier.Object, sharing: sharing);
    }

    private static Mock<IManagedCertificateStore> StoreWith(params ManagedCertificate[] records)
    {
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(records);
        return managed;
    }

    [Fact]
    public async Task Renew_NamingAnAdditionalSite_RenewsTheSharedCertificate()
    {
        var acme = new Mock<IAcmeService>();
        acme.Setup(value => value.IssueAsync(It.Is<AcmeIssueRequest>(request => request.SiteName == "Shop"), It.IsAny<IProgress<ProgressEvent>?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, [], New));

        var result = Assert.Single(await Renewals(StoreWith(Shared()), acme, new Mock<INotifier>()).RenewAsync(new RenewalRequest(SiteName: "Blog", Force: true)));

        Assert.True(result.Succeeded);
        Assert.Equal(New, result.NewThumbprint);
    }

    [Fact]
    public async Task Renew_ASiteLeftOut_ReportsIt_AndAlwaysNotifies()
    {
        var acme = new Mock<IAcmeService>();
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), It.IsAny<IProgress<ProgressEvent>?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, [], New, LeftOutSites: [new LeftOutSite("Blog", "It failed.")]));
        var notifier = new Mock<INotifier>();

        var result = Assert.Single(await Renewals(StoreWith(Shared()), acme, notifier).RenewAsync(new RenewalRequest(All: true, Force: true, Scheduled: true)));

        Assert.True(result.Succeeded);
        Assert.Contains("'Blog'", result.Message, StringComparison.Ordinal);
        notifier.Verify(value => value.NotifyAsync(It.Is<NotificationMessage>(message => message.Kind == NotificationKind.RenewalFailure), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Renew_APendingSite_CatchesUpEvenWhenNothingIsDue()
    {
        var sharing = new Mock<ICertificateSharingService>();
        sharing.Setup(value => value.CatchUpAsync("Shop", It.IsAny<IProgress<ProgressEvent>?>(), It.IsAny<CancellationToken>())).ReturnsAsync(["Blog"]);
        var acme = new Mock<IAcmeService>(MockBehavior.Strict);

        var results = await Renewals(StoreWith(BlogPending()), acme, new Mock<INotifier>(), sharing.Object).RenewAsync(new RenewalRequest(All: true, Scheduled: true));

        sharing.Verify(value => value.CatchUpAsync("Shop", It.IsAny<IProgress<ProgressEvent>?>(), It.IsAny<CancellationToken>()), Times.Once);
        Assert.False(Assert.Single(results).Attempted);
    }

    [Fact]
    public void RetryDelay_AfterUsingUpACertificate_WaitsADay_UntilCloseToExpiry()
    {
        Assert.Equal(TimeSpan.FromHours(24), RenewalService.GetRetryDelay(1, false, TimeSpan.FromDays(20), usedUpCertificate: true));
        Assert.Equal(TimeSpan.FromHours(1), RenewalService.GetRetryDelay(1, false, TimeSpan.FromDays(1), usedUpCertificate: true));
        Assert.Equal(TimeSpan.FromHours(1), RenewalService.GetRetryDelay(1, false, TimeSpan.FromDays(20)));
    }

    [Fact]
    public async Task Renew_ASharedCertificateThatFailsToBind_RetriesAfterADay()
    {
        var acme = new Mock<IAcmeService>();
        acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), It.IsAny<IProgress<ProgressEvent>?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(Failure());
        var managed = StoreWith(Shared());
        DateTimeOffset? retry = null;
        managed.Setup(value => value.RecordRenewalFailureAsync("Shop", It.IsAny<DateTimeOffset>(), It.IsAny<string>(), It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<string, DateTimeOffset, string, DateTimeOffset, CancellationToken>((_, _, _, next, _) => retry = next)
            .ReturnsAsync((ManagedCertificate?)null);

        await Renewals(managed, acme, new Mock<INotifier>()).RenewAsync(new RenewalRequest(All: true, Force: true));

        Assert.True(retry > DateTimeOffset.UtcNow.AddHours(23));
    }

    [Fact]
    public async Task Recovery_FinishesEverySite_AndKeepsOneLeftOutAsPending()
    {
        var certificate = Shared(others:
        [
            new CertificateTarget("Blog", ["blog.example.com"]),
            new CertificateTarget("Admin", ["admin.example.com"], DateTimeOffset.UtcNow.AddHours(-1)),
            new CertificateTarget("Gone", ["gone.example.com"])
        ]);
        var transaction = new CertificateTransaction(Guid.NewGuid(), certificate, "PREVIOUS", CertificateTransactionStage.CertificateImported, DateTimeOffset.UtcNow);
        var journal = new Mock<ICertificateTransactionJournal>();
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>())).ReturnsAsync([transaction]);
        journal.Setup(value => value.GetAsync(transaction.Id, It.IsAny<CancellationToken>())).ReturnsAsync(transaction);
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.FindByThumbprintAsync(Old, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(Old, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(
        [
            Site("Shop", "shop.example.com"),
            Site("Blog", "blog.example.com", thumbprint: "PREVIOUS"),
            Site("Admin", "admin.example.com", thumbprint: "PREVIOUS")
        ]);
        var managed = new Mock<IManagedCertificateStore>();
        ManagedCertificate? saved = null;
        managed.Setup(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .Callback<ManagedCertificate, CancellationToken>((record, _) => saved = record)
            .Returns(Task.CompletedTask);
        var service = new CertificateRecoveryService(journal.Object, new NoOpCertificateOperationLock(), store.Object, managed.Object, iis.Object);

        var result = Assert.Single(await service.RecoverAsync());

        Assert.True(result.Succeeded);
        iis.Verify(value => value.ConfigureHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, "My", It.IsAny<CancellationToken>()), Times.Once);
        iis.Verify(value => value.ConfigureHttpsBindingsAsync("Shop", It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        iis.Verify(value => value.ConfigureHttpsBindingsAsync("Admin", It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        Assert.Equal(["Admin", "Gone"], saved!.AllTargets().Where(target => target.PendingSince is not null).Select(target => target.SiteName));
        journal.Verify(value => value.CompleteAsync(transaction.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Recovery_ASiteFails_KeepsTheEntryForTheNextStart()
    {
        var transaction = new CertificateTransaction(Guid.NewGuid(), Shared(), "PREVIOUS", CertificateTransactionStage.CertificateImported, DateTimeOffset.UtcNow);
        var journal = new Mock<ICertificateTransactionJournal>();
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>())).ReturnsAsync([transaction]);
        journal.Setup(value => value.GetAsync(transaction.Id, It.IsAny<CancellationToken>())).ReturnsAsync(transaction);
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.FindByThumbprintAsync(Old, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(Old, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com", thumbprint: "PREVIOUS")]);
        iis.Setup(value => value.ConfigureHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, "My", It.IsAny<CancellationToken>())).ThrowsAsync(Failure());
        var managed = new Mock<IManagedCertificateStore>();
        var service = new CertificateRecoveryService(journal.Object, new NoOpCertificateOperationLock(), store.Object, managed.Object, iis.Object);

        Assert.False(Assert.Single(await service.RecoverAsync()).Succeeded);

        journal.Verify(value => value.CompleteAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
        managed.Verify(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ManagementRemove_OnAnAdditionalSite_IsRefused_AndChangesNothing()
    {
        var iis = new Mock<IIisService>();
        var managed = StoreWith(Shared());
        var service = new CertificateManagementService(managed.Object, Mock.Of<ICertificateStore>(), iis.Object, Mock.Of<SSLense.Core.Logs.ILogService>());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.RemoveAsync("Blog"));

        Assert.Contains("share remove", exception.Message, StringComparison.Ordinal);
        Assert.Empty(iis.Invocations);
    }

    [Fact]
    public async Task ManagementRemove_RemovesEverySite_ExceptOneOnAnOlderCertificate()
    {
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"), Site("Admin", "admin.example.com", thumbprint: "PREVIOUS")]);
        var record = Shared(others:
        [
            new CertificateTarget("Blog", ["blog.example.com"]),
            new CertificateTarget("Admin", ["admin.example.com"], DateTimeOffset.UtcNow)
        ]);
        var service = new CertificateManagementService(StoreWith(record).Object, Mock.Of<ICertificateStore>(), iis.Object, Mock.Of<SSLense.Core.Logs.ILogService>());

        await service.RemoveAsync("Shop");

        iis.Verify(value => value.RemoveHttpsBindingsAsync("Shop", It.IsAny<IReadOnlyList<string>>(), Old, It.IsAny<CancellationToken>()), Times.Once);
        iis.Verify(value => value.RemoveHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), Old, It.IsAny<CancellationToken>()), Times.Once);
        iis.Verify(value => value.RemoveHttpsBindingsAsync("Admin", It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public void HandSharingWarning_IgnoresSitesInTheRecord_AndSuggestsShareAdd()
    {
        var record = Shared();
        IisSite[] sites = [Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com"), Site("Other", "other.example.com")];

        var warning = ServedCertificateCheck.DescribeSharing(record, sites, [record]);

        Assert.NotNull(warning);
        Assert.Contains("'Other'", warning, StringComparison.Ordinal);
        Assert.DoesNotContain("'Blog'", warning, StringComparison.Ordinal);
        Assert.Contains("share add", warning, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ServedCheck_ChecksEverySite_AndNamesTheOneWithAProblem()
    {
        var record = Shared();
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([Site("Shop", "shop.example.com"), Site("Blog", "blog.example.com")]);
        var probe = new Mock<ITlsBindingProbe>();
        probe.Setup(value => value.GetServedThumbprintAsync(It.IsAny<string>(), "shop.example.com", 443, It.IsAny<CancellationToken>())).ReturnsAsync(Old);
        probe.Setup(value => value.GetServedThumbprintAsync(It.IsAny<string>(), "blog.example.com", 443, It.IsAny<CancellationToken>())).ReturnsAsync("PREVIOUS");
        var check = new ServedCertificateCheck(iis.Object, probe.Object, Mock.Of<ICertificateStore>(), new NoOpCertificateOperationLock());

        var result = await check.CheckAllAsync([record], DateTimeOffset.UtcNow);

        Assert.Contains("'Blog'", result.Problems["Shop"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Store_SchemaFourFile_ReadsAsNotShared_AndBacksUpOnFirstWrite()
    {
        const string statePath = @"C:\ProgramData\SSLense\managed-certificates.json";
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[statePath] = """
            {
              "schemaVersion": 4,
              "certificates": [
                { "siteName": "Shop", "hosts": [ "shop.example.com" ], "email": "a@example.com", "thumbprint": "AA",
                  "notBefore": "2026-09-01T00:00:00+00:00", "notAfter": "2026-11-30T00:00:00+00:00",
                  "authorityId": "letsencrypt-staging", "id": "11111111-1111-1111-1111-111111111111" }
              ]
            }
            """;
        var store = new JsonManagedCertificateStore(fileSystem, statePath, @"C:\ProgramData\SSLense\managed-certificates.lock");

        var record = Assert.Single(await store.GetAllAsync());
        Assert.False(record.IsShared());
        Assert.False(record.HasPendingSites());

        await store.UpsertAsync(record.WithTargets([.. record.AllTargets(), new CertificateTarget("Blog", ["blog.example.com"])]));

        Assert.True(fileSystem.Files.ContainsKey(statePath + ".v4.bak"));
        var saved = Assert.Single(await store.GetAllAsync());
        Assert.Equal(["Shop", "Blog"], saved.AllSiteNames());
        Assert.Equal(record.Id, saved.Id);
    }

    [Fact]
    public async Task Store_Replace_ChangesTheFirstSite_KeepingTheIdAndReminders()
    {
        const string statePath = @"C:\ProgramData\SSLense\managed-certificates.json";
        var store = new JsonManagedCertificateStore(new InMemoryFileSystem(), statePath, @"C:\ProgramData\SSLense\managed-certificates.lock");
        await store.UpsertAsync(Shared() with { Reminders = ReminderMode.Off });
        var before = Assert.Single(await store.GetAllAsync());

        await store.ReplaceAsync("Shop", before.WithTargets(before.AllTargets().Skip(1).ToArray()));

        var after = Assert.Single(await store.GetAllAsync());
        Assert.Equal("Blog", after.SiteName);
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(ReminderMode.Off, after.Reminders);
    }

    [Fact]
    public async Task ImportedInstall_OnAnAdditionalSite_IsRefused()
    {
        Assert.Contains("'Shop'", (await Assert.ThrowsAsync<InvalidOperationException>(() =>
        {
            ManagedCertificateTargets.ThrowIfAdditionalSite([Shared()], "Blog");
            return Task.CompletedTask;
        })).Message, StringComparison.Ordinal);
        ManagedCertificateTargets.ThrowIfAdditionalSite([Shared()], "Shop");
        ManagedCertificateTargets.ThrowIfAdditionalSite([Shared()], "Unrelated");
    }

    private static Mock<IIisService> IisShowing(params IisSite[] sites)
    {
        var iis = new Mock<IIisService>();
        iis.Setup(service => service.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(sites);
        return iis;
    }

    private static IisSite SiteWithHttps(string name, string host, string? thumbprint) =>
        new(1, name, "Started", null, [new IisBinding("https", "*", 443, host, thumbprint, thumbprint is null ? null : "My", true)]);

    [Fact]
    public async Task Cleanup_KeepsTheOldCertificate_WhenALeftOutSiteShowsNoCertificate()
    {
        // Found on real IIS: the hash comes from HTTP.sys, so a binding that lost its entry looks as if it uses nothing.
        var store = new Mock<ICertificateStore>();

        var message = await ReplacedCertificateCleanup.RemoveIfUnusedAsync(
            IisShowing(SiteWithHttps("Blog", "blog.example.com", null)).Object, store.Object, Old, New, CancellationToken.None, ["Blog"]);

        Assert.Null(message);
        store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Cleanup_NamesOnlyTheSitesNotAlreadyReportedAsLeftOut()
    {
        var store = new Mock<ICertificateStore>();
        var iis = IisShowing(SiteWithHttps("Blog", "blog.example.com", Old), SiteWithHttps("Other", "other.example.com", Old));

        var message = await ReplacedCertificateCleanup.RemoveIfUnusedAsync(iis.Object, store.Object, Old, New, CancellationToken.None, ["Blog"]);

        Assert.Contains("'Other'", message, StringComparison.Ordinal);
        Assert.DoesNotContain("'Blog'", message, StringComparison.Ordinal);
        store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Cleanup_RemovesTheOldCertificate_WhenNothingUsesItAndNoSiteIsLeftOut()
    {
        var store = new Mock<ICertificateStore>();

        var message = await ReplacedCertificateCleanup.RemoveIfUnusedAsync(
            IisShowing(SiteWithHttps("Shop", "shop.example.com", New)).Object, store.Object, Old, New, CancellationToken.None, []);

        Assert.Null(message);
        store.Verify(value => value.RemoveAsync(Old, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Transaction_EndsWithTheSitesNotRestored_SoTheFailedSitesOwnResultDoesNotReadAsCoveringThem()
    {
        var iis = new Mock<IIisService>();
        iis.Setup(service => service.SwitchHttpsBindingsAsync("Shop", It.IsAny<IReadOnlyList<string>>(), New, "My", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new HttpsBindingUndo("Shop", true, []));
        iis.Setup(service => service.SwitchHttpsBindingsAsync("Blog", It.IsAny<IReadOnlyList<string>>(), New, "My", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException("The site's previous bindings were restored and checked.", true, new InvalidOperationException("Failed.")));
        iis.Setup(service => service.UndoHttpsBindingsAsync(It.IsAny<HttpsBindingUndo>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException("Could not restore.", false, new InvalidOperationException("Failed.")));

        var error = await Assert.ThrowsAsync<IisBindingException>(() => SharedBindingTransaction.ApplyAsync(
            iis.Object,
            [new CertificateTarget("Shop", ["shop.example.com"]), new CertificateTarget("Blog", ["blog.example.com"])],
            New,
            leaveOutFailures: false,
            null,
            CancellationToken.None));

        Assert.False(error.PreviousBindingsRestored);
        Assert.EndsWith("these sites could not be confirmed as restored: 'Shop'. Check them in IIS now.", error.Message, StringComparison.Ordinal);
    }
}

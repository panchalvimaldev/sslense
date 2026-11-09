using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using SSLense.Tests.DnsValidation;
using Xunit;

namespace SSLense.Tests.Acme;

/// <summary>A CA cannot be removed while a certificate is being issued from it (docs/design/certificate-sources.md, 9.4).</summary>
public sealed class CertificateAuthorityLockTests : IDisposable
{
    private static readonly TimeSpan Waiting = TimeSpan.FromMilliseconds(700);
    private readonly string _folder = Path.Combine(Path.GetTempPath(), $"sslense-ca-lock-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    // Two instances stand for two processes, such as the service and the CLI.
    private FileCertificateAuthorityLock Process() => new(_folder);

    [Fact]
    public async Task Issues_FromOneCa_DoNotWaitForEachOther()
    {
        await using var first = await Process().AcquireUseAsync("zerossl", CancellationToken.None);

        var second = Process().AcquireUseAsync("zerossl", CancellationToken.None);

        Assert.Same(second, await Task.WhenAny(second, Task.Delay(Waiting)));
        await (await second).DisposeAsync();
    }

    [Fact]
    public async Task Removal_WaitsForAnIssueInProgress_ThenGoesAhead()
    {
        var issue = await Process().AcquireUseAsync("zerossl", CancellationToken.None);

        var removal = Process().AcquireRemovalAsync("zerossl", CancellationToken.None);
        Assert.NotSame(removal, await Task.WhenAny(removal, Task.Delay(Waiting)));

        await issue.DisposeAsync();
        await (await removal.WaitAsync(TimeSpan.FromSeconds(10))).DisposeAsync();
    }

    [Fact]
    public async Task AnIssue_WaitsForARemovalInProgress()
    {
        var removal = await Process().AcquireRemovalAsync("zerossl", CancellationToken.None);

        var issue = Process().AcquireUseAsync("zerossl", CancellationToken.None);
        Assert.NotSame(issue, await Task.WhenAny(issue, Task.Delay(Waiting)));

        await removal.DisposeAsync();
        await (await issue.WaitAsync(TimeSpan.FromSeconds(10))).DisposeAsync();
    }

    [Fact]
    public async Task DifferentCas_DoNotAffectEachOther()
    {
        await using var issue = await Process().AcquireUseAsync("zerossl", CancellationToken.None);

        var removal = Process().AcquireRemovalAsync("sslcom", CancellationToken.None);

        Assert.Same(removal, await Task.WhenAny(removal, Task.Delay(Waiting)));
        await (await removal).DisposeAsync();
    }

    [Fact]
    public async Task Issue_HoldsTheCasLock_BeforeReadingTheCa()
    {
        var authorityLock = new RecordingLock();
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var site = new IisSite(1, "My Site", "Started", @"C:\inetpub\site", [new IisBinding("http", "*", 80, "example.com", null, null, false)]);
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([site]);
        var service = new AcmeService(
            iis.Object,
            Mock.Of<IAcmeProtocolClient>(MockBehavior.Strict),
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            managed.Object,
            authorities: new CertificateAuthorityRegistry(new FakeConfigStore()),
            authorityLock: authorityLock);

        // The CA was removed while this issue waited for the lock: it stops before ordering anything.
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", AuthorityId: "zerossl", AcceptProductionRisk: true)));

        Assert.Equal(["use zerossl", "released zerossl"], authorityLock.Events);
    }

    [Fact]
    public async Task Removal_HoldsTheCasLock_WhileItChecksAndRemoves()
    {
        var authorityLock = new RecordingLock();
        var config = new FakeConfigStore(new AppConfig
        {
            CertificateAuthorities = [new CertificateAuthority("zerossl", "ZeroSSL", new Uri("https://acme.zerossl.com/v2/DV90"), IsTest: false)]
        });
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .Callback(() => Assert.Contains("remove zerossl", authorityLock.Events))
            .ReturnsAsync([]);
        var service = new CertificateAuthorityService(
            config, managed.Object, new CertificateAuthorityRegistry(config), new AcmeDirectoryReader(new HttpClient()), Mock.Of<ISecretProtector>(), authorityLock);

        await service.RemoveAsync("ZeroSSL");

        Assert.Equal(["remove zerossl", "released zerossl"], authorityLock.Events);
        Assert.Empty(config.Config.CertificateAuthorities);
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.RemoveAsync("letsencrypt"));
        Assert.Equal(2, authorityLock.Events.Count);
    }

    private sealed class RecordingLock : ICertificateAuthorityLock
    {
        public List<string> Events { get; } = [];

        public Task<IAsyncDisposable> AcquireUseAsync(string authorityId, CancellationToken cancellationToken) => Hold($"use {authorityId}", authorityId);

        public Task<IAsyncDisposable> AcquireRemovalAsync(string authorityId, CancellationToken cancellationToken) => Hold($"remove {authorityId}", authorityId);

        private Task<IAsyncDisposable> Hold(string name, string authorityId)
        {
            Events.Add(name);
            return Task.FromResult<IAsyncDisposable>(new Release(() => Events.Add($"released {authorityId}")));
        }

        private sealed class Release(Action action) : IAsyncDisposable
        {
            public ValueTask DisposeAsync()
            {
                action();
                return ValueTask.CompletedTask;
            }
        }
    }
}

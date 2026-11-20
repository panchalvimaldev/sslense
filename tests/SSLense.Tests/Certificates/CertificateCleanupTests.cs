using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Clean-up of unused certificates (docs/design/certificate-cleanup.md).</summary>
public sealed class CertificateCleanupTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private readonly List<string> _removed = [];

    private static InstalledCertificate Certificate(string thumbprint, int days, string issuer = "CN=R11, O=Let's Encrypt", params string[] names) =>
        new(thumbprint, Now.AddDays(-30), Now.AddDays(days), true, issuer, names, issuer, $"CN={(names.Length > 0 ? names[0] : thumbprint)}");

    private readonly InstalledCertificate[] _store =
    [
        Certificate("BOUND", -5, names: "shop.example.com"),
        Certificate("HTTPSYS", -5, names: "winrm.example.com"),
        Certificate("MANAGED", -5, names: "blog.example.com"),
        Certificate("EXPIRED", -5, names: "old.example.com"),
        Certificate("STAGING", 60, "CN=(STAGING) Ersatz Edamame E1, O=(STAGING) Let's Encrypt", "test.example.com"),
        Certificate("OLDER", 20, names: "www.example.com"),
        Certificate("NEWER", 80, names: "www.example.com"),
        Certificate("CLIENT", 300),
        Certificate("FTPCERT", -5, names: "ftp.example.com")
    ];

    [Fact]
    public async Task OnlyUnusedCertificatesThatAreExpiredTestOrReplaced_AreCandidates()
    {
        var candidates = await Service().FindAsync();

        Assert.Equal(["EXPIRED", "OLDER", "STAGING"], candidates.Select(candidate => candidate.Thumbprint).Order());
        Assert.StartsWith("Expired on", candidates.Single(candidate => candidate.Thumbprint == "EXPIRED").Reason, StringComparison.Ordinal);
        Assert.Contains("(NEWER, expires", candidates.Single(candidate => candidate.Thumbprint == "OLDER").Reason, StringComparison.Ordinal);
        Assert.Contains("test certificate", candidates.Single(candidate => candidate.Thumbprint == "STAGING").Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Removing_ChecksEachAgain_AndRefusesOneInUse()
    {
        var results = await Service().RemoveAsync(["expired", "BOUND", "STAGING"]);

        Assert.Equal(["EXPIRED", "STAGING"], _removed);
        Assert.StartsWith("SSL4054: BOUND", results[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCertificateKeptForRollback_IsNotACandidate()
    {
        var candidates = await Service(previous: "OLDER").FindAsync();

        Assert.DoesNotContain(candidates, candidate => candidate.Thumbprint == "OLDER");
    }

    private CertificateCleanupService Service(string? previous = null)
    {
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.ListAsync(It.IsAny<CancellationToken>())).ReturnsAsync(_store);
        store.Setup(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<string, CancellationToken>((thumbprint, _) => _removed.Add(thumbprint))
            .Returns(Task.CompletedTask);
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new IisSite(1, "Shop", "Started", null, [new IisBinding("https", "*", 443, "shop.example.com", "BOUND", "My", true)])
        ]);
        iis.Setup(value => value.GetHttpSysCertificateThumbprintsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(["HTTPSYS"]);
        iis.Setup(value => value.GetFtpSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([new FtpSite("Files", ["ftp.example.com"], "FTPCERT")]);
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([
            new ManagedCertificate("Blog", ["blog.example.com"], "", "MANAGED", Now.AddDays(-90), Now.AddDays(-5), PreviousThumbprint: previous)
        ]);
        return new CertificateCleanupService(store.Object, iis.Object, managed.Object);
    }
}

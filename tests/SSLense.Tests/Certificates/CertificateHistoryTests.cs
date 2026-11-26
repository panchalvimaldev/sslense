using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Iis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Certificate history and rollback (docs/design/history-and-rollback.md).</summary>
public sealed class CertificateHistoryTests
{
    private const string HistoryPath = @"C:\data\history.json";
    private static readonly Guid RecordId = Guid.NewGuid();

    private readonly InMemoryFileSystem _files = new();
    private readonly Mock<IManagedCertificateStore> _managed = new();
    private readonly Mock<ICertificateStore> _store = new();
    private readonly Mock<IIisService> _iis = new();
    private ManagedCertificate _record = new(
        "Shop", ["shop.example.com"], "admin@example.com", "CURRENT", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(89),
        Id: RecordId, PreviousThumbprint: "PREVIOUS");

    private ManagedCertificate? _saved;

    public CertificateHistoryTests()
    {
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => [_record]);
        _managed.Setup(value => value.UpdateRecordAsync(RecordId, It.IsAny<Func<ManagedCertificate, ManagedCertificate>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Guid _, Func<ManagedCertificate, ManagedCertificate> change, CancellationToken _) => _saved = change(_record));
        _store.Setup(value => value.OpenAsync("PREVIOUS", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Create(DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(30), "shop.example.com"));
    }

    private JsonCertificateHistoryStore History => new(_files, HistoryPath, @"C:\data\history.lock");

    private CertificateHistoryService Service() => new(_managed.Object, _store.Object, _iis.Object, History);

    [Fact]
    public async Task TheStore_KeepsTheNewestEntriesOfEachCertificate()
    {
        var other = Guid.NewGuid();
        await History.AddAsync(new CertificateHistoryEntry(DateTimeOffset.UtcNow, other, "Blog", CertificateHistoryKind.Issued, "Issued."));
        for (var index = 0; index < JsonCertificateHistoryStore.EntriesPerCertificate + 5; index++)
        {
            await History.AddAsync(new CertificateHistoryEntry(
                DateTimeOffset.UtcNow.AddMinutes(index), RecordId, "Shop", CertificateHistoryKind.RenewalFailed, $"Attempt {index}"));
        }

        var entries = await History.GetAllAsync();

        Assert.Equal(JsonCertificateHistoryStore.EntriesPerCertificate, entries.Count(entry => entry.RecordId == RecordId));
        Assert.DoesNotContain(entries, entry => entry.Message == "Attempt 4");
        Assert.Contains(entries, entry => entry.Message == $"Attempt {JsonCertificateHistoryStore.EntriesPerCertificate + 4}");
        Assert.Single(entries, entry => entry.RecordId == other);
        Assert.Contains("\"kind\": \"RenewalFailed\"", _files.Files[HistoryPath], StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheTimeline_IsNewestFirst_AndOffersTheRollback()
    {
        await History.AddAsync(new CertificateHistoryEntry(DateTimeOffset.UtcNow.AddDays(-60), RecordId, "Shop", CertificateHistoryKind.Issued, "Issued."));
        await History.AddAsync(new CertificateHistoryEntry(DateTimeOffset.UtcNow.AddDays(-1), RecordId, "Old name", CertificateHistoryKind.Renewed, "Renewed."));

        var view = await Service().GetAsync("shop");

        Assert.Equal([CertificateHistoryKind.Renewed, CertificateHistoryKind.Issued], view.Entries.Select(entry => entry.Kind));
        Assert.True(view.Rollback.Available);
        Assert.Equal("PREVIOUS", view.Rollback.Thumbprint);
    }

    [Fact]
    public async Task RollingBack_BindsThePreviousCertificate_SwapsTheRecord_AndHoldsRenewal()
    {
        var message = await Service().RollBackAsync("Shop");

        _iis.Verify(value => value.ConfigureHttpsBindingsAsync("Shop", It.Is<IReadOnlyList<string>>(hosts => hosts.Single() == "shop.example.com"), "PREVIOUS", "My", It.IsAny<CancellationToken>()));
        Assert.NotNull(_saved);
        Assert.Equal("PREVIOUS", _saved.Thumbprint);
        Assert.Equal("CURRENT", _saved.PreviousThumbprint);
        Assert.True(_saved.NextRetryAt > DateTimeOffset.UtcNow.AddDays(6));
        Assert.Contains("roll forward", message, StringComparison.Ordinal);
        var entry = Assert.Single(await History.GetAllAsync());
        Assert.Equal(CertificateHistoryKind.RolledBack, entry.Kind);
        Assert.Equal("CURRENT", entry.ReplacedThumbprint);
    }

    [Fact]
    public async Task GoingBackToTheNewerCertificate_IsRecordedAsRollingForward()
    {
        // After a rollback the kept certificate is the newer one, so the same action now rolls forward.
        _store.Setup(value => value.OpenAsync("PREVIOUS", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Create(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(89), "shop.example.com"));

        await Service().RollBackAsync("Shop");

        var entry = Assert.Single(await History.GetAllAsync());
        Assert.Equal(CertificateHistoryKind.RolledForward, entry.Kind);
        Assert.StartsWith("Rolled forward to certificate PREVIOUS", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RollingBack_WhenTheBindingFails_LeavesTheRecordAlone()
    {
        _iis.Setup(value => value.ConfigureHttpsBindingsAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException("HTTP.sys refused it.", true, new IOException("refused")));

        await Assert.ThrowsAsync<IisBindingException>(() => Service().RollBackAsync("Shop"));

        Assert.Null(_saved);
        Assert.Empty(await History.GetAllAsync());
    }

    [Fact]
    public async Task NoPreviousCertificate_CannotRollBack()
    {
        _record = _record with { PreviousThumbprint = null };

        var exception = await Assert.ThrowsAsync<SslenseException>(() => Service().RollBackAsync("Shop"));

        Assert.Equal(ErrorCodes.RollbackNotAvailable, exception.ErrorCode);
        Assert.False((await Service().GetAsync("Shop")).Rollback.Available);
    }

    [Fact]
    public async Task ARevokedPreviousCertificate_CannotBeRolledBackTo()
    {
        await History.AddAsync(new CertificateHistoryEntry(DateTimeOffset.UtcNow, RecordId, "Shop", CertificateHistoryKind.Revoked, "Revoked.", "previous"));

        var view = await Service().GetAsync("Shop");

        Assert.False(view.Rollback.Available);
        Assert.Contains("revoked", view.Rollback.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APreviousCertificateThatExpiresTomorrow_OrMissesAHost_CannotBeRolledBackTo()
    {
        _store.Setup(value => value.OpenAsync("PREVIOUS", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Create(DateTimeOffset.UtcNow.AddDays(-89), DateTimeOffset.UtcNow.AddHours(12), "shop.example.com"));
        Assert.Contains("too soon", (await Service().GetAsync("Shop")).Rollback.Message, StringComparison.Ordinal);

        _store.Setup(value => value.OpenAsync("PREVIOUS", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => Create(DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(30), "other.example.com"));
        Assert.Contains("does not cover shop.example.com", (await Service().GetAsync("Shop")).Rollback.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AWildcardHost_NeedsAWildcardName()
    {
        using var wildcard = Create(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), "*.example.com");
        using var single = Create(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1), "www.example.com");

        Assert.True(CertificateHistoryService.Covers(wildcard, "*.example.com"));
        Assert.True(CertificateHistoryService.Covers(wildcard, "www.example.com"));
        Assert.False(CertificateHistoryService.Covers(single, "*.example.com"));
    }

    [Theory]
    [InlineData(30, 7.0)]
    [InlineData(10, 1.0)]
    [InlineData(2, null)]
    public void RenewalIsHeld_ForAWeekAtMost_AndNeverTooCloseToExpiry(int daysLeft, double? heldDays)
    {
        var now = DateTimeOffset.UtcNow;

        var hold = CertificateHistoryService.HoldUntil(now, now.AddDays(daysLeft - 90), now.AddDays(daysLeft));

        Assert.Equal(heldDays, hold is { } until ? Math.Round((until - now).TotalDays, 1) : null);
    }

    private static X509Certificate2 Create(DateTimeOffset notBefore, DateTimeOffset notAfter, string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(name);
        request.CertificateExtensions.Add(names.Build());
        return request.CreateSelfSigned(notBefore, notAfter);
    }
}

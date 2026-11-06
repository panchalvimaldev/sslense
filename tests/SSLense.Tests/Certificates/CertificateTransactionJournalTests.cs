using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class CertificateTransactionJournalTests
{
    [Fact]
    public async Task Journal_PersistsStageAndRemovesCompletedTransaction()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sslense-journal-{Guid.NewGuid():N}");
        try
        {
            var journal = new JsonCertificateTransactionJournal(new PhysicalFileSystem(), directory);
            var certificate = new ManagedCertificate(
                "My Site", ["example.com"], "admin@example.com", "AABBCC",
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(45),
                AuthorityId: CertificateAuthorities.LetsEncryptId);

            var transaction = await journal.BeginAsync(certificate, "OLD");
            await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.BindingsUpdated);

            var reloaded = Assert.Single(await journal.GetPendingAsync());
            Assert.Equal(CertificateTransactionStage.BindingsUpdated, reloaded.Stage);
            Assert.Equal(CertificateAuthorities.LetsEncryptId, reloaded.Certificate.AuthorityId);

            await journal.CompleteAsync(transaction.Id);

            Assert.Empty(await journal.GetPendingAsync());
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task UpdateCertificate_KeepsTheStage_AndReplacesTheRecordToSave()
    {
        var journal = new JsonCertificateTransactionJournal(new InMemoryFileSystem(), @"C:\data\transactions");
        var certificate = new ManagedCertificate(
            "Shop", ["shop.example.com"], "admin@example.com", "AABBCC",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(45),
            AdditionalTargets: [new CertificateTarget("Blog", ["blog.example.com"])]);
        var transaction = await journal.BeginAsync(certificate, "OLD");
        await journal.UpdateStageAsync(transaction.Id, CertificateTransactionStage.CertificateImported);
        var pendingSince = DateTimeOffset.UtcNow;

        await journal.UpdateCertificateAsync(
            transaction.Id,
            certificate with { AdditionalTargets = [new CertificateTarget("Blog", ["blog.example.com"], pendingSince)] });

        var reloaded = await journal.GetAsync(transaction.Id);
        Assert.Equal(CertificateTransactionStage.CertificateImported, reloaded!.Stage);
        Assert.Equal("OLD", reloaded.PreviousThumbprint);
        Assert.Equal(pendingSince, Assert.Single(reloaded.Certificate.AdditionalTargets!).PendingSince);
    }
}

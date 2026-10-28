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
                Environment: AcmeEnvironment.Production);

            var transaction = await journal.BeginAsync(certificate, "OLD");
            await journal.UpdateStageAsync(
                transaction.Id,
                CertificateTransactionStage.BindingsUpdated);

            var reloaded = Assert.Single(await journal.GetPendingAsync());
            Assert.Equal(CertificateTransactionStage.BindingsUpdated, reloaded.Stage);
            Assert.Equal(AcmeEnvironment.Production, reloaded.Certificate.Environment);

            await journal.CompleteAsync(transaction.Id);

            Assert.Empty(await journal.GetPendingAsync());
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}

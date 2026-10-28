using Moq;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class CertificateRecoveryServiceTests
{
    [Fact]
    public async Task RecoverAsync_ImportedCertificate_CompletesBindingsAndState()
    {
        var certificate = new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", "AABBCC",
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(44));
        var transaction = new CertificateTransaction(
            Guid.NewGuid(), certificate, "OLD",
            CertificateTransactionStage.CertificateImported, DateTimeOffset.UtcNow);
        var journal = new Mock<ICertificateTransactionJournal>(MockBehavior.Strict);
        journal.Setup(value => value.GetPendingAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([transaction]);
        journal.Setup(value => value.GetAsync(transaction.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(transaction);
        journal.Setup(value => value.UpdateStageAsync(
                transaction.Id, CertificateTransactionStage.BindingsUpdated, CancellationToken.None))
            .Returns(Task.CompletedTask);
        journal.Setup(value => value.UpdateStageAsync(
                transaction.Id, CertificateTransactionStage.StateSaved, CancellationToken.None))
            .Returns(Task.CompletedTask);
        journal.Setup(value => value.CompleteAsync(transaction.Id, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var scope = new Mock<IAsyncDisposable>(MockBehavior.Strict);
        scope.Setup(value => value.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var operationLock = new Mock<ICertificateOperationLock>(MockBehavior.Strict);
        operationLock.Setup(value => value.AcquireAsync("My Site", It.IsAny<CancellationToken>()))
            .ReturnsAsync(scope.Object);
        var store = new Mock<ICertificateStore>(MockBehavior.Strict);
        store.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC", certificate.NotBefore, certificate.NotAfter, true));
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [])]);
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                "My Site",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                "AABBCC",
                "My",
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.UpsertAsync(certificate, CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = new CertificateRecoveryService(
            journal.Object, operationLock.Object, store.Object, managed.Object, iis.Object);

        var messages = await service.RecoverAsync();

        Assert.Single(messages);
        journal.VerifyAll();
        operationLock.VerifyAll();
        scope.VerifyAll();
        store.VerifyAll();
        iis.VerifyAll();
        managed.VerifyAll();
    }
}

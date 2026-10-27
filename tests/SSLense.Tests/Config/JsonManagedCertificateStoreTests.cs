using Moq;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

public sealed class JsonManagedCertificateStoreTests
{
    private const string StatePath = @"C:\ProgramData\SSLense\managed-certificates.json";
    private const string LockPath = @"C:\ProgramData\SSLense\managed-certificates.lock";

    [Fact]
    public async Task UpsertAsync_UsesLockAndPersistsRecordAtomically()
    {
        string? json = null;
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.AcquireExclusiveFileLockAsync(
                LockPath,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NoOpLock());
        fileSystem.Setup(value => value.FileExists(StatePath)).Returns(() => json is not null);
        fileSystem.Setup(value => value.WriteAllTextAtomicAsync(
                StatePath,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, contents, _) => json = contents)
            .Returns(Task.CompletedTask);
        fileSystem.Setup(value => value.ReadAllTextAsync(StatePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => json!);
        var store = new JsonManagedCertificateStore(fileSystem.Object, StatePath, LockPath);
        var certificate = new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", "AABBCC",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));

        await store.UpsertAsync(certificate);
        var saved = Assert.Single(await store.GetAllAsync());

        Assert.Equal(certificate.SiteName, saved.SiteName);
        Assert.Equal(certificate.Hosts, saved.Hosts);
        Assert.Equal(certificate.Email, saved.Email);
        Assert.Equal(certificate.Thumbprint, saved.Thumbprint);
        Assert.Equal(certificate.NotBefore, saved.NotBefore);
        Assert.Equal(certificate.NotAfter, saved.NotAfter);
        Assert.Contains("AABBCC", json, StringComparison.Ordinal);
        fileSystem.Verify(value => value.AcquireExclusiveFileLockAsync(
            LockPath, It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    private sealed class NoOpLock : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

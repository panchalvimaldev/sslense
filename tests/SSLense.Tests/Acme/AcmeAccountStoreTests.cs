using System.Text;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Acme;

public sealed class AcmeAccountStoreTests
{
    [Fact]
    public async Task SaveAndLoad_UsesProtectedPayloadInsteadOfPlaintext()
    {
        const string accountKey = "-----BEGIN EC PRIVATE KEY-----secret-----END EC PRIVATE KEY-----";
        string? savedValue = null;
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.WriteAllTextAtomicAsync(
                AppPaths.AccountKeyFile,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, contents, _) => savedValue = contents)
            .Returns(Task.CompletedTask);
        fileSystem.Setup(value => value.FileExists(AppPaths.AccountKeyFile)).Returns(true);
        fileSystem.Setup(value => value.ReadAllTextAsync(
                AppPaths.AccountKeyFile,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => savedValue!);
        var protector = new Mock<ISecretProtector>(MockBehavior.Strict);
        protector.Setup(value => value.Protect(It.IsAny<byte[]>())).Returns([10, 20, 30]);
        protector.Setup(value => value.Unprotect(It.Is<byte[]>(bytes => bytes.SequenceEqual(new byte[] { 10, 20, 30 }))))
            .Returns(Encoding.UTF8.GetBytes(accountKey));
        var store = new AcmeAccountStore(fileSystem.Object, protector.Object);

        await store.SaveKeyAsync(accountKey, CancellationToken.None);
        var loaded = await store.LoadKeyAsync(CancellationToken.None);

        Assert.Equal(accountKey, loaded);
        Assert.Equal(Convert.ToBase64String(new byte[] { 10, 20, 30 }), savedValue);
        Assert.DoesNotContain("PRIVATE KEY", savedValue, StringComparison.Ordinal);
    }
}

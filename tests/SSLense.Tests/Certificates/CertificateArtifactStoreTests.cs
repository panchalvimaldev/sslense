using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Certificates;

public sealed class CertificateArtifactStoreTests
{
    [Fact]
    public async Task SaveAsync_DefaultOutput_PersistsPemButNotPfx()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sslense-artifacts-{Guid.NewGuid():N}");
        try
        {
            var store = new CertificateArtifactStore(new PhysicalFileSystem(), directory);

            var result = await store.SaveAsync(
                "My Site",
                ["example.com"],
                new CertificateBundle("certificate-pem", [1, 2, 3]),
                null,
                CancellationToken.None);

            Assert.True(File.Exists(result.CertificatePemPath));
            Assert.Null(result.PfxPath);
            Assert.Empty(Directory.GetFiles(directory, "*.pfx", SearchOption.AllDirectories));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task SaveAsync_ExplicitOutput_WritesPemWithoutPersistingPfx()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sslense-export-{Guid.NewGuid():N}");
        try
        {
            var store = new CertificateArtifactStore(new PhysicalFileSystem(), directory);

            var result = await store.SaveAsync(
                "My Site",
                ["example.com"],
                new CertificateBundle("certificate-pem", [1, 2, 3]),
                directory,
                CancellationToken.None);

            Assert.Equal(Path.Combine(directory, "certificate.pem"), result.CertificatePemPath);
            Assert.True(File.Exists(result.CertificatePemPath));
            Assert.Null(result.PfxPath);
            Assert.Empty(Directory.GetFiles(directory, "*.pfx", SearchOption.AllDirectories));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}

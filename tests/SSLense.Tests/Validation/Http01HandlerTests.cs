using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Validation;

public sealed class Http01HandlerTests
{
    [Fact]
    public async Task PrepareAndDispose_WritesChallengeThenRestoresExistingWebConfig()
    {
        var root = Path.Combine(Path.GetTempPath(), $"sslense-test-{Guid.NewGuid():N}");
        var challengeDirectory = Path.Combine(root, ".well-known", "acme-challenge");
        var webConfigPath = Path.Combine(challengeDirectory, "web.config");
        var tokenPath = Path.Combine(challengeDirectory, "token");
        Directory.CreateDirectory(challengeDirectory);
        await File.WriteAllTextAsync(webConfigPath, "original-config");
        var handler = new Http01Handler(new PhysicalFileSystem());

        try
        {
            await using (await handler.PrepareAsync(
                root,
                new AcmeHttpChallenge("example.com", "token", "key-authorization"),
                CancellationToken.None))
            {
                Assert.Equal("key-authorization", await File.ReadAllTextAsync(tokenPath));
                var generatedWebConfig = await File.ReadAllTextAsync(webConfigPath);
                Assert.Contains("SSLenseAcmeChallenge", generatedWebConfig);
                Assert.Contains("fileExtension=\".\" mimeType=\"text/plain\"", generatedWebConfig);
            }

            Assert.False(File.Exists(tokenPath));
            Assert.Equal("original-config", await File.ReadAllTextAsync(webConfigPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

using System.Text;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Config;

public sealed class PhysicalFileSystemTests
{
    [Fact]
    public async Task ReadAllLinesAsync_ReadsFileWhileSharedWriterRemainsOpen()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"sslense-files-{Guid.NewGuid():N}");
        var path = Path.Combine(directory, "sslense-current.log");
        Directory.CreateDirectory(directory);

        try
        {
            await using (var stream = new FileStream(
                             path,
                             FileMode.Create,
                             FileAccess.Write,
                             FileShare.ReadWrite | FileShare.Delete,
                             4096,
                             FileOptions.Asynchronous))
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                await writer.WriteLineAsync("[20:00:00 INF] SSLense is running");
                await writer.FlushAsync();

                var lines = await new PhysicalFileSystem().ReadAllLinesAsync(path, CancellationToken.None);

                Assert.Equal(["[20:00:00 INF] SSLense is running"], lines);
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}

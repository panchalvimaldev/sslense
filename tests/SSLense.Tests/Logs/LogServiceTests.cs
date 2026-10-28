using Moq;
using SSLense.Core.Config;
using SSLense.Core.Logs;
using Xunit;

namespace SSLense.Tests.Logs;

public sealed class LogServiceTests
{
    [Fact]
    public async Task ReadCurrentAsync_SelectsNewestFileAndFiltersLevel()
    {
        var oldFile = Path.Combine(AppPaths.LogDirectory, "sslense-20261026.log");
        var currentFile = Path.Combine(AppPaths.LogDirectory, "sslense-20261027.log");
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        fileSystem.Setup(value => value.GetFiles(AppPaths.LogDirectory, "sslense-*.log"))
            .Returns([oldFile, currentFile]);
        fileSystem.Setup(value => value.ReadAllLinesAsync(currentFile, It.IsAny<CancellationToken>()))
            .ReturnsAsync([
                "[20:00:00 INF] Information",
                "[20:00:01 WRN] Warning",
                "[20:00:02 ERR] Error",
                "[20:00:03 FTL] Fatal"
            ]);
        var service = new LogService(fileSystem.Object);

        var snapshot = await service.ReadCurrentAsync("Error");

        Assert.Equal(currentFile, snapshot.FilePath);
        Assert.Equal(2, snapshot.Lines.Count);
        Assert.All(snapshot.Lines, line =>
            Assert.True(line.Contains(" ERR]", StringComparison.Ordinal) ||
                        line.Contains(" FTL]", StringComparison.Ordinal)));
        fileSystem.VerifyAll();
    }
}

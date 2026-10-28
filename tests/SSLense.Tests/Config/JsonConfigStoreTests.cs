using SSLense.Core.Config;
using Moq;
using Xunit;

namespace SSLense.Tests.Config;

public sealed class JsonConfigStoreTests
{
    private const string ConfigPath = @"C:\ProgramData\SSLense\config.json";
    private const string LockPath = ConfigPath + ".lock";

    [Fact]
    public async Task SaveAsync_UnversionedFile_BacksUpAndStampsCurrentVersion()
    {
        const string legacy = """{ "defaultEmail": "old@example.com", "renewalThresholdDays": 30 }""";
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[ConfigPath] = legacy;
        var store = new JsonConfigStore(fileSystem, ConfigPath);

        var loaded = await store.LoadAsync();
        await store.SaveAsync(loaded with { DefaultEmail = "new@example.com" });

        Assert.Equal(0, loaded.SchemaVersion);
        Assert.Equal(legacy, fileSystem.Files[$"{ConfigPath}.v0.bak"]);
        Assert.Equal(StateSchema.Config, (await store.LoadAsync()).SchemaVersion);
    }

    [Fact]
    public async Task LoadAndSave_NewerSchema_FailWithoutChangingTheFile()
    {
        const string newer = """{ "schemaVersion": 99, "defaultEmail": "admin@example.com" }""";
        var fileSystem = new InMemoryFileSystem();
        fileSystem.Files[ConfigPath] = newer;
        var store = new JsonConfigStore(fileSystem, ConfigPath);

        await Assert.ThrowsAsync<InvalidDataException>(() => store.LoadAsync());
        await Assert.ThrowsAsync<InvalidDataException>(() => store.SaveAsync(new AppConfig()));

        Assert.Equal(newer, fileSystem.Files[ConfigPath]);
    }

    [Fact]
    public async Task LoadAsync_WhenFileDoesNotExist_ReturnsSafeDefaults()
    {
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        SetupLock(fileSystem);
        fileSystem.Setup(system => system.FileExists(ConfigPath)).Returns(false);
        var store = new JsonConfigStore(fileSystem.Object, ConfigPath);

        var config = await store.LoadAsync();

        Assert.True(config.UseStaging);
        Assert.Equal(30, config.RenewalThresholdDays);
        Assert.Null(config.DefaultEmail);
    }

    [Fact]
    public async Task SaveThenLoad_PreservesConfiguration()
    {
        string? persistedJson = null;
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        SetupLock(fileSystem);
        fileSystem.Setup(system => system.FileExists(ConfigPath)).Returns(() => persistedJson is not null);
        fileSystem
            .Setup(system => system.WriteAllTextAtomicAsync(
                ConfigPath,
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, string, CancellationToken>((_, contents, _) => persistedJson = contents)
            .Returns(Task.CompletedTask);
        fileSystem
            .Setup(system => system.ReadAllTextAsync(ConfigPath, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => persistedJson!);
        var store = new JsonConfigStore(fileSystem.Object, ConfigPath);
        var expected = new AppConfig
        {
            DefaultEmail = "admin@example.com",
            UseStaging = true,
            RenewalThresholdDays = 21
        };

        await store.SaveAsync(expected);
        var actual = await store.LoadAsync();

        Assert.Equal(expected with { SchemaVersion = StateSchema.Config }, actual);
        Assert.Contains("\"useStaging\": true", persistedJson, StringComparison.Ordinal);
        fileSystem.VerifyAll();
    }

    [Fact]
    public async Task LoadAsync_WhenJsonIsInvalid_ThrowsClearError()
    {
        var fileSystem = new Mock<IFileSystem>(MockBehavior.Strict);
        SetupLock(fileSystem);
        fileSystem.Setup(system => system.FileExists(ConfigPath)).Returns(true);
        fileSystem
            .Setup(system => system.ReadAllTextAsync(ConfigPath, It.IsAny<CancellationToken>()))
            .ReturnsAsync("not-json");
        var store = new JsonConfigStore(fileSystem.Object, ConfigPath);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => store.LoadAsync());

        Assert.Contains("invalid JSON", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static void SetupLock(Mock<IFileSystem> fileSystem) =>
        fileSystem.Setup(system => system.AcquireExclusiveFileLockAsync(
                LockPath,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NoOpLock());

    private sealed class NoOpLock : IAsyncDisposable
    {
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

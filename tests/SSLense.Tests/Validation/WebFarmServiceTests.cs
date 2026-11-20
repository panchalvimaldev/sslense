using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Validation;

/// <summary>Web farm folders for HTTP validation (docs/design/web-farms.md).</summary>
public sealed class WebFarmServiceTests
{
    private const string StatePath = @"C:\ProgramData\SSLense\managed-certificates.json";
    private const string LockPath = @"C:\ProgramData\SSLense\managed-certificates.lock";

    [Fact]
    public async Task Folders_AreSaved_Deduplicated_AndCleared()
    {
        var files = new InMemoryFileSystem { ExistingDirectories = new HashSet<string>([@"\\web2\c$\inetpub\shop", @"\\web3\c$\inetpub\shop"], StringComparer.OrdinalIgnoreCase) };
        var store = new JsonManagedCertificateStore(files, StatePath, LockPath);
        await store.UpsertAsync(Record());
        var service = new WebFarmService(store, files);

        var saved = await service.SetFoldersAsync("shop", [@"\\web2\c$\inetpub\shop\", @"\\WEB2\c$\inetpub\shop", @" \\web3\c$\inetpub\shop "]);

        Assert.Equal([@"\\web2\c$\inetpub\shop", @"\\web3\c$\inetpub\shop"], saved);
        Assert.Equal(saved, await service.GetFoldersAsync("Shop"));
        Assert.Empty(await service.SetFoldersAsync("Shop", []));
        Assert.Null((await store.GetAllAsync()).Single().FarmFolders);
    }

    [Theory]
    [InlineData(@"inetpub\shop")]
    [InlineData(@"\\web9\c$\inetpub\shop")]
    public async Task ARelativeOrUnreachableFolder_IsRefused(string folder)
    {
        var files = new InMemoryFileSystem { ExistingDirectories = new HashSet<string>([@"\\web2\c$\inetpub\shop"], StringComparer.OrdinalIgnoreCase) };
        var store = new JsonManagedCertificateStore(files, StatePath, LockPath);
        await store.UpsertAsync(Record());

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => new WebFarmService(store, files).SetFoldersAsync("Shop", [folder]));

        Assert.StartsWith(ErrorCodes.FarmFolderInvalid.Code, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACertificateNotValidatedOverHttp_GetsNoFolders()
    {
        var files = new InMemoryFileSystem { ExistingDirectories = new HashSet<string>([@"\\web2\c$\inetpub\shop"], StringComparer.OrdinalIgnoreCase) };
        var store = new JsonManagedCertificateStore(files, StatePath, LockPath);
        await store.UpsertAsync(Record() with { ValidationMethod = ValidationMethod.Dns01Provider });

        await Assert.ThrowsAsync<ArgumentException>(() => new WebFarmService(store, files).SetFoldersAsync("Shop", [@"\\web2\c$\inetpub\shop"]));
    }

    private static ManagedCertificate Record() =>
        new("Shop", ["shop.example.com"], "ops@example.com", "AABB", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60));
}

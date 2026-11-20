using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Config;
using SSLense.Core.DnsValidation;
using SSLense.Core.Errors;
using SSLense.Tests.DnsValidation;
using System.Text;
using Xunit;

namespace SSLense.Tests.Config;

/// <summary>Settings export and import (docs/automation.md).</summary>
public sealed class ConfigTransferTests
{
    private const string FilePath = @"C:\export\settings.json";

    private readonly InMemoryFileSystem _files = new();
    private readonly Mock<IManagedCertificateStore> _managed = new();
    private List<ManagedCertificate> _records = [];

    public ConfigTransferTests()
    {
        _managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => _records);
    }

    /// <summary>Stands in for DPAPI: each server has its own key, so a copy from one cannot be opened on another.</summary>
    private sealed class ServerProtector(byte key) : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Select(value => (byte)(value ^ key))];

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }

    private static string Protected(byte key, string secret) => Convert.ToBase64String([.. Encoding.UTF8.GetBytes(secret).Select(value => (byte)(value ^ key))]);

    private static AppConfig Source => new()
    {
        DefaultEmail = "admin@example.com",
        RenewalThresholdDays = 21,
        CheckForUpdates = false,
        DnsProviders = [new DnsProviderProfile("cloudflare", DnsProviderType.Cloudflare, "example.com", "zone1", Protected(1, "cf-token"))],
        Notifications = new NotificationConfig { Chat = [new ChatNotificationConfig(ChatFormat.Generic, Protected(1, "https://hooks.example.com/abc"), "Ops")] }
    };

    private ConfigTransferService Service(FakeConfigStore store, byte server) => new(store, _managed.Object, new ServerProtector(server), _files);

    [Fact]
    public async Task WithoutAPassword_TheSecretsAreLeftOut_AndOnlyGeneralSettingsImport()
    {
        await Service(new FakeConfigStore(Source), 1).ExportAsync(FilePath, password: null);
        Assert.DoesNotContain("cf-token", _files.Files[FilePath], StringComparison.Ordinal);
        Assert.Contains("\"secrets\": \"removed\"", _files.Files[FilePath], StringComparison.Ordinal);

        var target = new FakeConfigStore(new AppConfig { DnsProviders = [new DnsProviderProfile("local", DnsProviderType.Cloudflare, "example.org", null, Protected(2, "local-token"))] });
        var message = await Service(target, 2).ImportAsync(FilePath, password: null);

        Assert.Equal("admin@example.com", target.Config.DefaultEmail);
        Assert.Equal(21, target.Config.RenewalThresholdDays);
        Assert.False(target.Config.CheckForUpdates);
        Assert.Equal("local", Assert.Single(target.Config.DnsProviders).Name);
        Assert.Contains("without its secrets", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithAPassword_SecretsMoveToTheOtherServer_ProtectedThere()
    {
        await Service(new FakeConfigStore(Source), 1).ExportAsync(FilePath, "correct horse");
        Assert.DoesNotContain(Source.DnsProviders[0].ProtectedToken, _files.Files[FilePath], StringComparison.Ordinal);

        var target = new FakeConfigStore();
        await Service(target, 2).ImportAsync(FilePath, "correct horse");

        Assert.Equal(Protected(2, "cf-token"), Assert.Single(target.Config.DnsProviders).ProtectedToken);
        Assert.Equal(Protected(2, "https://hooks.example.com/abc"), Assert.Single(target.Config.Notifications.Chat).ProtectedUrl);
        Assert.Contains(_files.Files.Keys, path => path.Contains("config.before-import-", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("wrong")]
    public async Task AFileWithSecrets_NeedsItsPassword(string? password)
    {
        await Service(new FakeConfigStore(Source), 1).ExportAsync(FilePath, "correct horse");
        var target = new FakeConfigStore();

        var exception = await Assert.ThrowsAsync<SslenseException>(() => Service(target, 2).ImportAsync(FilePath, password));

        Assert.Equal(ErrorCodes.ConfigPasswordMissingOrWrong, exception.ErrorCode);
        Assert.Null(target.Config.DefaultEmail);
    }

    [Fact]
    public async Task AnImportThatWouldOrphanACertificate_IsRefused()
    {
        await Service(new FakeConfigStore(new AppConfig()), 1).ExportAsync(FilePath, null);
        _records = [new ManagedCertificate("Shop", ["shop.example.com"], "a@example.com", "T", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90), AuthorityId: "zerossl")];
        var target = new FakeConfigStore(new AppConfig { DefaultEmail = "kept@example.com" });

        var exception = await Assert.ThrowsAsync<SslenseException>(() => Service(target, 2).ImportAsync(FilePath, null));

        Assert.Equal(ErrorCodes.ConfigImportRefused, exception.ErrorCode);
        Assert.Equal("kept@example.com", target.Config.DefaultEmail);
    }

    [Fact]
    public async Task NotASettingsFile_IsRefused()
    {
        _files.Files[FilePath] = "{\"hello\": 1}";

        var exception = await Assert.ThrowsAsync<SslenseException>(() => Service(new FakeConfigStore(), 2).ImportAsync(FilePath, null));

        Assert.Equal(ErrorCodes.ConfigFileInvalid, exception.ErrorCode);
    }

    [Fact]
    public async Task TheCertificates_AreWrittenForBulkIssue()
    {
        _records =
        [
            new ManagedCertificate("Shop", ["shop.example.com", "www.shop.example.com"], "a@example.com", "T", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90),
                ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["*.shop.example.com", "shop.example.com"]),
            new ManagedCertificate("Manual", ["manual.example.com"], "a@example.com", "T", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90),
                ValidationMethod: ValidationMethod.Dns01Manual)
        ];

        var message = await Service(new FakeConfigStore(), 1).ExportAsync(FilePath, null, @"C:\export\certificates.csv");

        var lines = _files.Files[@"C:\export\certificates.csv"].Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("site,hosts,validation,names,email,ca,profile,key", lines[0]);
        Assert.Equal("Shop,shop.example.com;www.shop.example.com,dns,*.shop.example.com;shop.example.com,a@example.com,letsencrypt-staging,,ecdsa-p256", lines[1]);
        Assert.Equal(2, lines.Length);
        Assert.Contains("Manual", message, StringComparison.Ordinal);
    }
}

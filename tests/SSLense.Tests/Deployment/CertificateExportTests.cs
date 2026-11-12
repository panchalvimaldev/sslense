using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Deployment;

/// <summary>Export steps (docs/design/certificate-export.md), with real files.</summary>
public sealed class CertificateExportTests : IDisposable
{
    private const string StatePath = @"C:\ProgramData\SSLense\managed-certificates.json";
    private const string LockPath = @"C:\ProgramData\SSLense\managed-certificates.lock";

    private readonly string _root = Path.Combine(Path.GetTempPath(), $"sslense-export-{Guid.NewGuid():N}");
    private readonly X509Certificate2 _certificate;
    private readonly byte[] _pfx;
    private readonly Mock<ICertificateStore> _store = new();

    public CertificateExportTests()
    {
        Directory.CreateDirectory(_root);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256);
        _certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
        _pfx = _certificate.Export(X509ContentType.Pkcs12, "pw");

        // A fresh copy each time, because the exporter disposes what it opens.
        _store.Setup(value => value.OpenAsync(_certificate.Thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadPkcs12(_pfx, "pw", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable));
    }

    public void Dispose()
    {
        _certificate.Dispose();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    [Fact]
    public async Task Pfx_HoldsTheCertificateAndKey_UnderThePassword_AndReplacesAnOlderFile()
    {
        var path = Path.Combine(_root, "out", "shop.pfx");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "old");

        await new CertificateExporter(_store.Object).ExportPfxAsync(_certificate.Thumbprint, path, "s3cret!", CancellationToken.None);

        using var loaded = X509CertificateLoader.LoadPkcs12FromFile(path, "s3cret!", X509KeyStorageFlags.EphemeralKeySet);
        Assert.Equal(_certificate.Thumbprint, loaded.Thumbprint);
        Assert.True(loaded.HasPrivateKey);
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
    }

    [Fact]
    public async Task Pem_WritesAMatchingKey_ReadableOnlyByAdministratorsAndSystem()
    {
        var folder = Path.Combine(_root, "pem");

        await new CertificateExporter(_store.Object).ExportPemAsync(_certificate.Thumbprint, folder, CancellationToken.None);

        Assert.Equal(
            ["cert.pem", "chain.pem", "fullchain.pem", "key.pem"],
            Directory.GetFiles(folder).Select(file => Path.GetFileName(file)!).Order().ToArray());
        using var loaded = X509Certificate2.CreateFromPemFile(Path.Combine(folder, "cert.pem"), Path.Combine(folder, "key.pem"));
        Assert.Equal(_certificate.Thumbprint, loaded.Thumbprint);
        Assert.True(loaded.HasPrivateKey);

        var security = new FileInfo(Path.Combine(folder, "key.pem")).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        var allowed = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .Select(rule => rule.IdentityReference)
            .ToHashSet();
        Assert.True(allowed.SetEquals(
        [
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            WindowsIdentity.GetCurrent().User!
        ]));
    }

    [Fact]
    public async Task CentralStore_WritesOnePfxPerName_WithTheWildcardAsUnderscore()
    {
        var folder = Path.Combine(_root, "ccs");

        await new CertificateExporter(_store.Object).ExportCentralStoreAsync(
            _certificate.Thumbprint, ["*.Example.com", "example.com"], folder, "ccs-pw", CancellationToken.None);

        Assert.Equal(["_.example.com.pfx", "example.com.pfx"], Directory.GetFiles(folder).Select(file => Path.GetFileName(file)!).Order().ToArray());
        using var loaded = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(folder, "_.example.com.pfx"), "ccs-pw", X509KeyStorageFlags.EphemeralKeySet);
        Assert.True(loaded.HasPrivateKey);
    }

    [Fact]
    public async Task ANonExportableKey_SaysHowToGetAnExportableOne()
    {
        // A persisted key that refuses export, as SSLense installs keys by default.
        using var key = CngKey.Create(CngAlgorithm.ECDsaP256, $"sslense-test-{Guid.NewGuid():N}", new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None });
        try
        {
            using var ecdsa = new ECDsaCng(key);
            using var locked = new CertificateRequest("CN=locked.example.com", ecdsa, HashAlgorithmName.SHA256)
                .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
            _store.Setup(value => value.OpenAsync(locked.Thumbprint, It.IsAny<CancellationToken>()))
                .ReturnsAsync(() => X509CertificateLoader.LoadCertificate(locked.RawData).CopyWithPrivateKey(new ECDsaCng(key)));

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => new CertificateExporter(_store.Object)
                .ExportPfxAsync(locked.Thumbprint, Path.Combine(_root, "locked.pfx"), "pw", CancellationToken.None));

            Assert.Contains("--exportable-key", exception.Message, StringComparison.Ordinal);
            Assert.False(File.Exists(Path.Combine(_root, "locked.pfx")));
        }
        finally
        {
            key.Delete();
        }
    }

    [Fact]
    public async Task ExportSteps_NeedAnExportableKey_AFullPath_AndAPassword_WhichIsStoredProtected()
    {
        var store = new JsonManagedCertificateStore(new InMemoryFileSystem(), StatePath, LockPath);
        var exporter = new FakeExporter();
        var service = Service(store, exporter);
        var record = new ManagedCertificate("Shop", ["example.com"], "ops@example.com", "AABB", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60));
        await store.UpsertAsync(record);

        var notExportable = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.ExportPfx, @"D:\Certs\shop.pfx", Password: "pw")));
        Assert.Contains("--exportable-key", notExportable.Message, StringComparison.Ordinal);

        await store.UpsertAsync(record with { ExportableKey = true });
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.ExportPfx, @"certs\shop.pfx", Password: "pw")));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.ExportPfx, @"D:\Certs\shop.pem", Password: "pw")));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.CentralStore, @"\\files\ccs")));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.ExportPem, @"D:\Certs\shop", Password: "pw")));

        var pfx = await service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.ExportPfx, @"D:\Certs\shop.pfx", Password: "pfx-secret"));
        await service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.CentralStore, @"\\files\ccs", Password: "ccs-secret"));
        await service.AddAsync(new DeploymentStepRequest("Shop", DeploymentStepKind.ExportPem, @"D:\Certs\shop"));
        var result = await service.RunAsync("Shop");

        Assert.True(result.Succeeded, result.Message);
        Assert.NotNull(pfx.ProtectedPassword);
        Assert.DoesNotContain("pfx-secret", pfx.ProtectedPassword, StringComparison.Ordinal);
        Assert.Equal(
            [@"pfx AABB D:\Certs\shop.pfx pfx-secret", @"ccs AABB example.com \\files\ccs ccs-secret", @"pem AABB D:\Certs\shop"],
            exporter.Calls);
        Assert.DoesNotContain("secret", result.Message, StringComparison.Ordinal);
    }

    private static DeploymentService Service(JsonManagedCertificateStore store, FakeExporter exporter)
    {
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        return new DeploymentService(
            store,
            new NoKeys(),
            new NoServices(),
            new DnsScriptStore(Path.Combine(Path.GetTempPath(), $"sslense-unused-{Guid.NewGuid():N}"), secure: false),
            new NoRunner(),
            iis.Object,
            Mock.Of<ICertificateStore>(),
            exporter: exporter,
            protector: new ReversingProtector());
    }

    private sealed class NoKeys : IPrivateKeyAccess
    {
        public string ResolveAccount(string account) => account;

        public Task GrantReadAsync(string thumbprint, string account, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class NoServices : IServiceRestarter
    {
        public Task<bool> ExistsAsync(string serviceName, CancellationToken cancellationToken) => Task.FromResult(true);

        public Task RestartAsync(string serviceName, TimeSpan timeout, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class NoRunner : IScriptRunner
    {
        public Task<ScriptRunResult> RunAsync(
            string scriptPath, IReadOnlyList<string> arguments, string? secret, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new ScriptRunResult(0, "", false, TimeSpan.Zero));
    }

    private sealed class FakeExporter : ICertificateExporter
    {
        public List<string> Calls { get; } = [];

        public Task ExportPfxAsync(string thumbprint, string path, string password, CancellationToken cancellationToken)
        {
            Calls.Add($"pfx {thumbprint} {path} {password}");
            return Task.CompletedTask;
        }

        public Task ExportPemAsync(string thumbprint, string folder, CancellationToken cancellationToken)
        {
            Calls.Add($"pem {thumbprint} {folder}");
            return Task.CompletedTask;
        }

        public Task ExportCentralStoreAsync(
            string thumbprint, IReadOnlyList<string> names, string folder, string password, CancellationToken cancellationToken)
        {
            Calls.Add($"ccs {thumbprint} {string.Join(",", names)} {folder} {password}");
            return Task.CompletedTask;
        }
    }

    private sealed class ReversingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => [.. plaintext.Reverse(), 0x5A];

        public byte[] Unprotect(byte[] protectedData) => [.. protectedData[..^1].Reverse()];
    }
}

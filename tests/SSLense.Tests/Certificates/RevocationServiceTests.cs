using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Moq;
using SSLense.Core;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Recovery from a compromised key or account (docs/design/compromise-recovery.md).</summary>
public sealed class RevocationServiceTests : IDisposable
{
    private readonly X509Certificate2 _old = SelfSigned("shop.example.com");
    private readonly List<ManagedCertificate> _managed = [];
    private readonly Mock<IManagedCertificateStore> _store = new();
    private readonly Mock<ICertificateStore> _certificates = new();
    private readonly Mock<IAcmeService> _acme = new();
    private readonly Mock<IAcmeProtocolClient> _protocol = new();
    private readonly Mock<IFileSystem> _files = new();
    private readonly RecordingCaLock _caLock = new();
    private readonly List<string> _steps = [];
    private static readonly CertificateAuthority Staging = CertificateAuthorities.LetsEncryptStaging;

    public RevocationServiceTests()
    {
        _store.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => _managed.ToArray());
        _store.Setup(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .Callback<ManagedCertificate, CancellationToken>((record, _) => { _managed.RemoveAll(value => value.SiteName == record.SiteName); _managed.Add(record); })
            .Returns(Task.CompletedTask);
        _certificates.Setup(value => value.OpenAsync(_old.Thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadCertificate(_old.RawData));
        _acme.Setup(value => value.IssueAsync(It.IsAny<AcmeIssueRequest>(), It.IsAny<IProgress<ProgressEvent>>(), It.IsAny<CancellationToken>()))
            .Callback<AcmeIssueRequest, IProgress<ProgressEvent>?, CancellationToken>((request, _, _) =>
            {
                _steps.Add($"issue reuse={request.ReuseKey} force={request.Force} expected={request.ExpectedCurrentThumbprint}");
                _managed[0] = _managed[0] with { Thumbprint = "NEW", ReuseKey = request.ReuseKey };
            })
            .ReturnsAsync(new AcmeIssueResult("pem", null, ["shop.example.com"], "NEW"));
        _protocol.Setup(value => value.RevokeAsync(It.IsAny<string>(), It.IsAny<CertificateAuthority>(), It.IsAny<byte[]>(), It.IsAny<CertificateRevocationReason>(), It.IsAny<CancellationToken>()))
            .Callback<string, CertificateAuthority, byte[], CertificateRevocationReason, CancellationToken>((_, _, der, reason, _) =>
                _steps.Add($"revoke {X509CertificateLoader.LoadCertificate(der).Thumbprint} {reason}"))
            .Returns(Task.CompletedTask);
    }

    [Fact]
    public async Task RevokeAndReplace_InstallsANewKeyFirst_ThenRevokesTheOldCertificate()
    {
        _managed.Add(Record());

        var result = await Service().RevokeAsync("Shop", CertificateRevocationReason.KeyCompromise, replace: true);

        Assert.Equal([$"issue reuse=False force=True expected={_old.Thumbprint}", $"revoke {_old.Thumbprint} KeyCompromise"], _steps);
        Assert.Equal("NEW", result.NewThumbprint);
        Assert.Contains("new key", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RevokeAndReplace_ACertificateThatReusesItsKey_KeepsReusingTheNewOne()
    {
        _managed.Add(Record() with { ReuseKey = true });

        await Service().RevokeAsync("Shop", CertificateRevocationReason.KeyCompromise, replace: true);

        Assert.StartsWith("issue reuse=False", _steps[0], StringComparison.Ordinal);
        Assert.True(Assert.Single(_managed).ReuseKey);
    }

    [Fact]
    public async Task RevokeOnly_RevokesWithoutReplacing_AndSaysTheSitesStillServeIt()
    {
        _managed.Add(Record());

        var result = await Service().RevokeAsync("Shop", CertificateRevocationReason.CessationOfOperation, replace: false);

        Assert.Equal([$"revoke {_old.Thumbprint} CessationOfOperation"], _steps);
        Assert.Null(result.NewThumbprint);
        Assert.Contains("browsers will refuse it", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARevocationThatFailsAfterTheReplacement_KeepsTheOldCertificateToTryAgain()
    {
        _managed.Add(Record());
        _protocol.Setup(value => value.RevokeAsync(It.IsAny<string>(), It.IsAny<CertificateAuthority>(), It.IsAny<byte[]>(), It.IsAny<CertificateRevocationReason>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new HttpRequestException("connection reset"));
        string? savedPath = null;
        byte[]? saved = null;
        _files.Setup(value => value.WriteAllBytesAsync(It.IsAny<string>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .Callback<string, byte[], CancellationToken>((path, bytes, _) => (savedPath, saved) = (path, bytes))
            .Returns(Task.CompletedTask);

        var exception = await Assert.ThrowsAsync<SSLense.Core.Errors.SslenseException>(() =>
            Service().RevokeAsync("Shop", CertificateRevocationReason.KeyCompromise, replace: true));

        Assert.Equal("SSL2030", exception.Code);
        Assert.Equal(_old.RawData, saved);
        Assert.Contains($"revoke --file \"{savedPath}\" --ca {Staging.Id} --reason key-compromise", exception.Message, StringComparison.Ordinal);
        Assert.Equal("NEW", Assert.Single(_managed).Thumbprint);
    }

    [Fact]
    public async Task ABoughtCertificate_IsRevokedByItsProvider_NotSslense()
    {
        _managed.Add(Record() with { Source = CertificateSource.Imported, Issuer = "Sectigo RSA DV" });

        var exception = await Assert.ThrowsAsync<SSLense.Core.Errors.SslenseException>(() =>
            Service().RevokeAsync("Shop", CertificateRevocationReason.KeyCompromise, replace: true));

        Assert.Equal("SSL4051", exception.Code);
        Assert.Contains("Sectigo RSA DV", exception.Message, StringComparison.Ordinal);
        Assert.Empty(_steps);
    }

    [Fact]
    public async Task AManualDnsCertificate_CannotBeReplacedAutomatically_ButCanBeRevoked()
    {
        _managed.Add(Record() with { ValidationMethod = ValidationMethod.Dns01Manual });

        var exception = await Assert.ThrowsAsync<SSLense.Core.Errors.SslenseException>(() =>
            Service().RevokeAsync("Shop", CertificateRevocationReason.KeyCompromise, replace: true));
        Assert.Equal("SSL4052", exception.Code);
        Assert.Empty(_steps);

        await Service().RevokeAsync("Shop", CertificateRevocationReason.KeyCompromise, replace: false);
        Assert.Equal([$"revoke {_old.Thumbprint} KeyCompromise"], _steps);
    }

    [Fact]
    public async Task ChangingTheAccountKey_HoldsTheCasExclusiveLock()
    {
        _protocol.Setup(value => value.ChangeAccountKeyAsync(It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
            .Callback(() => Assert.Equal([$"removal {Staging.Id}"], _caLock.Held))
            .Returns(Task.CompletedTask);

        var message = await Service().ChangeAccountKeyAsync(Staging.Id);

        Assert.Contains("old key no longer works", message, StringComparison.Ordinal);
        _protocol.Verify(value => value.ChangeAccountKeyAsync(It.Is<CertificateAuthority>(authority => authority.Id == Staging.Id), It.IsAny<CancellationToken>()), Times.Once);
    }

    public void Dispose() => _old.Dispose();

    private RevocationService Service() => new(
        _store.Object, _certificates.Object, _acme.Object, _protocol.Object, CertificateAuthorityRegistry.BuiltInOnly, _files.Object, _caLock);

    private sealed class RecordingCaLock : ICertificateAuthorityLock
    {
        public List<string> Held { get; } = [];

        public Task<IAsyncDisposable> AcquireUseAsync(string authorityId, CancellationToken cancellationToken) => Hold($"use {authorityId}");

        public Task<IAsyncDisposable> AcquireRemovalAsync(string authorityId, CancellationToken cancellationToken) => Hold($"removal {authorityId}");

        private Task<IAsyncDisposable> Hold(string what)
        {
            Held.Add(what);
            return Task.FromResult<IAsyncDisposable>(new Release(() => Held.Remove(what)));
        }

        private sealed class Release(Action release) : IAsyncDisposable
        {
            public ValueTask DisposeAsync() { release(); return ValueTask.CompletedTask; }
        }
    }

    private ManagedCertificate Record() =>
        new("Shop", ["shop.example.com"], "ops@example.com", _old.Thumbprint, _old.NotBefore, _old.NotAfter,
            AuthorityId: Staging.Id, Source: CertificateSource.Acme, ValidationMethod: ValidationMethod.Dns01Provider);

    private static X509Certificate2 SelfSigned(string host)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
    }
}

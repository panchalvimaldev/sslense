using Moq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core;
using SSLense.Core.Config;
using SSLense.Core.Deployment;
using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Acme;

public sealed class AcmeServiceTests
{
    [Fact]
    public async Task IssueAsync_ValidRequest_CompletesChallengeAndSavesArtifacts()
    {
        var challenge = new AcmeHttpChallenge("example.com", "token", "key-authorization");
        var site = CreateSite("example.com");
        var iis = MockIis(site);
        var order = new Mock<IAcmeOrderSession>(MockBehavior.Strict);
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        order.Setup(value => value.FinalizeAsync(
                "example.com",
                It.Is<string>(password => password.Length > 20),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                "admin@example.com",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                It.Is<CertificateAuthority>(authority => authority.Id == CertificateAuthorities.LetsEncryptStagingId),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var cleanup = new TrackingCleanup();
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        handler.Setup(value => value.PrepareAsync("My Site", "C:\\inetpub\\site", challenge, It.IsAny<CancellationToken>()))
            .ReturnsAsync(cleanup);
        var probe = new Mock<IChallengeProbe>(MockBehavior.Strict);
        probe.Setup(value => value.VerifyAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var expected = new AcmeIssueResult("certificate.pem", "certificate.pfx", ["example.com"]);
        var artifacts = new Mock<ICertificateArtifactStore>(MockBehavior.Strict);
        artifacts.Setup(value => value.SaveAsync(
                "My Site",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                It.IsAny<CertificateBundle>(),
                null,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(expected);
        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(90);
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.ImportPfxAsync(
                It.IsAny<byte[]>(),
                It.Is<string>(password => password.Length > 20),
                It.Is<string>(name => name.StartsWith("SSLense: example.com", StringComparison.Ordinal)),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", notBefore, notAfter, true));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                "My Site",
                It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "example.com" })),
                "AABBCC",
                "My",
                It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var managedStore = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managedStore.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        managedStore.Setup(value => value.UpsertAsync(
                It.Is<ManagedCertificate>(record =>
                    record.SiteName == "My Site" &&
                    record.Thumbprint == "AABBCC" &&
                    record.Hosts.SequenceEqual(new[] { "example.com" }) &&
                    record.LastRenewalSucceeded == true),
                CancellationToken.None))
            .Returns(Task.CompletedTask);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            handler.Object,
            probe.Object,
            artifacts.Object,
            certificateStore.Object,
            managedStore.Object);

        var result = await service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["EXAMPLE.com."], "admin@example.com"));

        Assert.Equal(expected.CertificatePemPath, result.CertificatePemPath);
        Assert.Equal("AABBCC", result.CertificateThumbprint);
        Assert.Equal(notAfter, result.NotAfter);
        Assert.True(cleanup.WasDisposed);
        protocol.VerifyAll();
        order.VerifyAll();
        handler.VerifyAll();
        probe.VerifyAll();
        artifacts.VerifyAll();
        certificateStore.VerifyAll();
        managedStore.VerifyAll();
    }

    [Fact]
    public async Task IssueAsync_MissingPort80Binding_StopsBeforeAcmeOrder()
    {
        var site = new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", []);
        var iis = MockIis(site);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            EmptyManagedStore());

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.Contains("HTTP binding on port 80", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task IssueAsync_ValidationFails_StillRemovesChallengeFiles()
    {
        var challenge = new AcmeHttpChallenge("example.com", "token", "key-authorization");
        var iis = MockIis(CreateSite("example.com"));
        var order = new Mock<IAcmeOrderSession>(MockBehavior.Strict);
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("rejected"));
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<CertificateAuthority>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var cleanup = new TrackingCleanup();
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        handler.Setup(value => value.PrepareAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                challenge,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(cleanup);
        var probe = new Mock<IChallengeProbe>(MockBehavior.Strict);
        probe.Setup(value => value.VerifyAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            handler.Object,
            probe.Object,
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            EmptyManagedStore());

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.True(cleanup.WasDisposed);
    }

    [Fact]
    public async Task IssueAsync_ValidCertificateAlreadyBound_RequiresForceBeforeCreatingOrder()
    {
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC",
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(60),
                true,
                DnsNames: ["example.com"]));
        var site = new IisSite(
            1,
            "My Site",
            "Started",
            "C:\\inetpub\\site",
            [
                new IisBinding("http", "*", 80, "example.com", null, null, false),
                new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true)
            ]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            MockIis(site).Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            certificateStore.Object,
            EmptyManagedStore());

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task IssueAsync_ABindingWithoutAHostName_DoesNotCountAsCoverageForANameItsCertificateLacks()
    {
        // Codex's case on #79: the site's host-less binding holds a valid certificate for shop.example.com only.
        var certificateStore = new Mock<ICertificateStore>();
        certificateStore.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60), true, DnsNames: ["shop.example.com"]));
        var site = new IisSite(1, "My Site", "Started", "C:\\inetpub\\site",
        [
            new IisBinding("http", "*", 80, "", null, null, false),
            new IisBinding("https", "*", 443, "", "AABBCC", "My", false)
        ]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("order reached"));
        var service = new AcmeService(
            MockIis(site).Object, protocol.Object, Mock.Of<IChallengeHandler>(), Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(), certificateStore.Object, EmptyManagedStore());

        var exception = await Assert.ThrowsAnyAsync<Exception>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["admin.example.com"], "admin@example.com")));

        Assert.Contains("order reached", exception.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssueAsync_AnIpAddressItsBoundCertificateCovers_RequiresForce()
    {
        // Codex's case on #79: the store lists DNS names only, so the certificate's IP address is read from the certificate.
        using var key = System.Security.Cryptography.ECDsa.Create();
        var request = new CertificateRequest("CN=example.com", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("example.com");
        names.AddIpAddress(System.Net.IPAddress.Parse("203.0.113.7"));
        request.CertificateExtensions.Add(names.Build());
        using var bound = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60));
        var certificateStore = new Mock<ICertificateStore>();
        certificateStore.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60), true, DnsNames: ["example.com"]));
        certificateStore.Setup(value => value.OpenAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadCertificate(bound.RawData));
        var site = new IisSite(1, "My Site", "Started", "C:\\inetpub\\site",
            [new IisBinding("https", "203.0.113.7", 443, "", "AABBCC", "My", false)]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            MockIis(site).Object, protocol.Object, Mock.Of<IChallengeHandler>(), Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(), certificateStore.Object, EmptyManagedStore());
        using var addresses = LocalAddress.UseAddressesForTesting(System.Net.IPAddress.Parse("203.0.113.7"));

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["203.0.113.7"], "admin@example.com", SelfHostedHttp: true)));

        Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task IssueAsync_AnIpAddressThatCannotBePlacedOnThisServer_IsRefusedBeforeOrdering()
    {
        // Behind NAT with several addresses of the same kind, SSLense cannot tell which one receives the traffic.
        var site = new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [new IisBinding("http", "*", 80, "", null, null, false)]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            MockIis(site).Object, protocol.Object, Mock.Of<IChallengeHandler>(), Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(), Mock.Of<ICertificateStore>(), EmptyManagedStore());
        using var addresses = LocalAddress.UseAddressesForTesting(System.Net.IPAddress.Parse("10.0.0.4"), System.Net.IPAddress.Parse("10.0.1.4"));

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["203.0.113.7"], "admin@example.com", SelfHostedHttp: true)));

        Assert.StartsWith("SSL6035", exception.Message, StringComparison.Ordinal);
        Assert.Contains("10.0.0.4, 10.0.1.4", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData("CN=(STAGING) Pseudo Plum E5, O=(STAGING) Let's Encrypt, C=US", CertificateAuthorities.LetsEncryptId, true)]
    [InlineData("CN=E5, O=Let's Encrypt, C=US", CertificateAuthorities.LetsEncryptStagingId, true)]
    [InlineData("CN=E5, O=Let's Encrypt, C=US", CertificateAuthorities.LetsEncryptId, false)]
    public async Task IssueAsync_ProductionRequest_DoesNotTreatStagingCertificateAsCoverage(
        string issuer,
        string managedAuthorityId,
        bool expectOrder)
    {
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.FindByThumbprintAsync("AABBCC", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC",
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(60),
                true,
                issuer,
                DnsNames: ["example.com"]));
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new ManagedCertificate(
                "My Site", ["example.com"], "admin@example.com", "AABBCC",
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(60),
                AuthorityId: managedAuthorityId)]);
        var site = new IisSite(
            1,
            "My Site",
            "Started",
            "C:\\inetpub\\site",
            [
                new IisBinding("http", "*", 80, "example.com", null, null, false),
                new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true)
            ]);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                "admin@example.com",
                It.IsAny<IReadOnlyList<string>>(),
                It.Is<CertificateAuthority>(authority => authority.Id == CertificateAuthorities.LetsEncryptId),
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("order requested"));
        var service = new AcmeService(
            MockIis(site).Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            certificateStore.Object,
            managed.Object);

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest(
                "My Site", ["example.com"], "admin@example.com",
                AuthorityId: CertificateAuthorities.LetsEncryptId,
                AcceptProductionRisk: true)));

        if (expectOrder)
        {
            Assert.Equal("order requested", exception.Message);
        }
        else
        {
            Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
            protocol.VerifyNoOtherCalls();
        }
    }

    [Theory]
    [InlineData(CertificateAuthorities.LetsEncryptId)]
    [InlineData("zerossl")]
    public async Task IssueAsync_TrustedCa_WithoutConfirmation_IsRefusedBeforeAnyOrder(string authorityId)
    {
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        var zeroSsl = new CertificateAuthority("zerossl", "ZeroSSL", new Uri("https://acme.zerossl.com/v2/DV90"), IsTest: false);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            MockIis(CreateSite("example.com")).Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            managed.Object,
            authorities: new CertificateAuthorityRegistry(new SSLense.Tests.DnsValidation.FakeConfigStore(new AppConfig { CertificateAuthorities = [zeroSsl] })));

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", AuthorityId: authorityId)));

        Assert.Contains("--accept-production-risk", exception.Message, StringComparison.Ordinal);
        protocol.VerifyNoOtherCalls();
    }

    [Fact]
    public void ManualRenewalCommand_NamesTheCa_AndConfirmsProduction()
    {
        var certificate = new ManagedCertificate(
            "Shop", ["shop.example.com"], "admin@example.com", "AA", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60),
            AuthorityId: "zerossl", ValidationMethod: ValidationMethod.Dns01Manual);

        var command = SSLense.Core.Renewal.ManualDnsRenewal.Command(certificate);

        Assert.EndsWith(" --ca zerossl --accept-production-risk", command, StringComparison.Ordinal);
        Assert.DoesNotContain("--production", SSLense.Core.Renewal.ManualDnsRenewal.Command(certificate with { AuthorityId = CertificateAuthorities.LetsEncryptStagingId }), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("urn:ietf:params:acme:error:rateLimited", true)]
    [InlineData("urn:ietf:params:acme:error:unauthorized", false)]
    public void IsRateLimited_RecognizesOnlyTheRateLimitProblemType(string problemType, bool expected)
    {
        var exception = new Certes.AcmeRequestException(
            "request failed",
            new Certes.Acme.AcmeError { Type = problemType, Detail = "too many certificates" });

        Assert.Equal(expected, CertesAcmeProtocolClient.IsRateLimited(exception));
        if (expected)
        {
            var mapped = CertesAcmeProtocolClient.ToRateLimitedException(exception, CertificateAuthorities.LetsEncryptStaging);
            Assert.Contains("too many certificates", mapped.Message, StringComparison.Ordinal);
            Assert.Contains("will not retry", mapped.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task IssueAsync_ExpectedCertificateChanged_StopsBeforeIisOrAcme()
    {
        var managed = new Mock<IManagedCertificateStore>(MockBehavior.Strict);
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([new ManagedCertificate(
                "My Site", ["example.com"], "admin@example.com", "NEW",
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(45))]);
        var scope = new Mock<IAsyncDisposable>(MockBehavior.Strict);
        scope.Setup(value => value.DisposeAsync()).Returns(ValueTask.CompletedTask);
        var operationLock = new Mock<ICertificateOperationLock>(MockBehavior.Strict);
        operationLock.Setup(value => value.AcquireAsync("My Site", It.IsAny<CancellationToken>()))
            .ReturnsAsync(scope.Object);
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(),
            Mock.Of<ICertificateArtifactStore>(),
            Mock.Of<ICertificateStore>(),
            managed.Object,
            operationLock.Object);

        var exception = await Assert.ThrowsAsync<CertificateStateChangedException>(() => service.IssueAsync(
            new AcmeIssueRequest(
                "My Site", ["example.com"], "admin@example.com",
                Force: true, ExpectedCurrentThumbprint: "OLD")));

        Assert.Contains("changed", exception.Message, StringComparison.OrdinalIgnoreCase);
        iis.VerifyNoOtherCalls();
        protocol.VerifyNoOtherCalls();
        managed.VerifyAll();
        operationLock.VerifyAll();
        scope.VerifyAll();
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task IssueAsync_BindingFails_RemovesCertificateOnlyWhenBindingsWereRestored(
        bool previousBindingsRestored,
        bool expectRemoval)
    {
        var challenge = new AcmeHttpChallenge("example.com", "token", "key-authorization");
        var iis = MockIis(CreateSite("example.com"));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                "AABBCC",
                "My",
                It.IsAny<CancellationToken>()))
            .ThrowsAsync(new IisBindingException(
                "binding failed",
                previousBindingsRestored,
                new InvalidOperationException("IIS error")));
        var order = new Mock<IAcmeOrderSession>(MockBehavior.Strict);
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        order.Setup(value => value.FinalizeAsync(
                "example.com",
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>(MockBehavior.Strict);
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<CertificateAuthority>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        handler.Setup(value => value.PrepareAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                challenge,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TrackingCleanup());
        var probe = new Mock<IChallengeProbe>(MockBehavior.Strict);
        probe.Setup(value => value.VerifyAsync(challenge, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var artifacts = new Mock<ICertificateArtifactStore>(MockBehavior.Strict);
        artifacts.Setup(value => value.SaveAsync(
                It.IsAny<string>(),
                It.IsAny<IReadOnlyList<string>>(),
                It.IsAny<CertificateBundle>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", "certificate.pfx", ["example.com"]));
        var certificateStore = new Mock<ICertificateStore>(MockBehavior.Strict);
        certificateStore.Setup(value => value.ImportPfxAsync(
                It.IsAny<byte[]>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate(
                "AABBCC",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddDays(90),
                true));
        if (expectRemoval)
        {
            certificateStore.Setup(value => value.RemoveAsync("AABBCC", CancellationToken.None))
                .Returns(Task.CompletedTask);
        }

        var service = new AcmeService(
            iis.Object,
            protocol.Object,
            handler.Object,
            probe.Object,
            artifacts.Object,
            certificateStore.Object,
            EmptyManagedStore());

        await Assert.ThrowsAsync<IisBindingException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        certificateStore.Verify(
            value => value.RemoveAsync("AABBCC", CancellationToken.None),
            expectRemoval ? Times.Once() : Times.Never());
    }

    [Fact]
    public async Task IssueAsync_Dns_NeedsNoPort80Binding_AndCleansUpBeforeFinalizing()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        Assert.Equal(["check example.com", "publish 1", "validate example.com", "cleanup", "finalize"], harness.Steps);
        harness.Protocol.Verify(value => value.CreateOrderAsync(
            It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()), Times.Never);
        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.ValidationMethod == ValidationMethod.Dns01Provider),
            CancellationToken.None));
    }

    [Fact]
    public async Task IssueAsync_Dns_NoHostsGiven_UsesNamedHttpAndHttpsBindings()
    {
        var harness = new DnsHarness(
            new IisBinding("https", "*", 8443, "secure.example.com", null, null, true),
            new IisBinding("http", "*", 8080, "app.example.com", null, null, false),
            new IisBinding("ftp", "*", 21, "ftp.example.com", null, null, false));
        harness.Order.SetupGet(value => value.DnsChallenges).Returns([]);

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Protocol.Verify(value => value.CreateDnsOrderAsync(
            "admin@example.com",
            It.Is<IReadOnlyList<string>>(names => names.SequenceEqual(new[] { "secure.example.com", "app.example.com" })),
            It.IsAny<CertificateAuthority>(),
            It.IsAny<CancellationToken>()));
    }

    [Fact]
    public async Task IssueAsync_NoHostsGiven_LeavesOutTheHostNamesOfTheSitesOtherCertificates()
    {
        var harness = new DnsHarness(
            new IisBinding("https", "*", 443, "a.example.com", "OLD", "My", true),
            new IisBinding("https", "*", 443, "b.example.com", "BOUGHT", "My", true));
        harness.SetManaged(new ManagedCertificate("My Site/b.example.com", ["b.example.com"], string.Empty, "BOUGHT",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(300), Source: CertificateSource.Imported));
        harness.Order.SetupGet(value => value.DnsChallenges).Returns([]);

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Protocol.Verify(value => value.CreateDnsOrderAsync(
            "admin@example.com",
            It.Is<IReadOnlyList<string>>(names => names.SequenceEqual(new[] { "a.example.com" })),
            It.IsAny<CertificateAuthority>(),
            It.IsAny<CancellationToken>()));
    }

    [Fact]
    public async Task IssueAsync_NoHostsGiven_AndOnlyOtherCertificatesHostNames_IsRefusedBeforeAnOrder()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "b.example.com", "BOUGHT", "My", true));
        harness.SetManaged(new ManagedCertificate("My Site/b.example.com", ["b.example.com"], string.Empty, "BOUGHT",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(300), Source: CertificateSource.Imported));

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.Empty(harness.Steps);
        harness.Protocol.Verify(value => value.CreateDnsOrderAsync(
            It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_Dns_AHostNotOnTheSite_IsRefusedBeforeAnOrder()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["other.example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.Contains("HTTP or HTTPS binding", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_Dns_ProviderCheckFails_CreatesNoOrder()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.Dns.FailCheck = new InvalidOperationException("no provider");

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider)));

        harness.Protocol.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task IssueAsync_Dns_PublishFails_NeverAsksTheCaToValidate()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.Dns.FailPublish = new TimeoutException("not visible");

        await Assert.ThrowsAsync<TimeoutException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.DoesNotContain(harness.Steps, step => step.StartsWith("validate", StringComparison.Ordinal));
        Assert.DoesNotContain("finalize", harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_Dns_ValidationFails_StillCleansUp()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.Order.Setup(value => value.ValidateAsync(It.IsAny<AcmeDnsChallenge>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("rejected"));

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.Contains("cleanup", harness.Steps);
        Assert.DoesNotContain("finalize", harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_DnsManual_WithoutSomeoneToConfirm_IsRefused()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        await Assert.ThrowsAsync<ArgumentException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Manual)));

        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_Wildcard_OrdersTheNames_BindsTheHosts_AndRecordsBoth()
    {
        var harness = WildcardHarness();

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site",
            ["shop.example.com", "example.com"],
            "admin@example.com",
            ValidationMethod: ValidationMethod.Dns01Provider,
            CertificateNames: ["*.example.com", "Example.com."]));

        Assert.Equal("check *.example.com,example.com", harness.Steps[0]);
        Assert.Equal("publish 2", harness.Steps[1]);
        harness.Protocol.Verify(value => value.CreateDnsOrderAsync(
            "admin@example.com",
            It.Is<IReadOnlyList<string>>(names => names.SequenceEqual(new[] { "*.example.com", "example.com" })),
            It.IsAny<CertificateAuthority>(),
            It.IsAny<CancellationToken>()));
        harness.Order.Verify(value => value.FinalizeAsync("*.example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()));
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync(
            "My Site",
            It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "shop.example.com", "example.com" })),
            "AABBCC",
            "My",
            It.IsAny<CancellationToken>()));
        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record =>
                record.Hosts.SequenceEqual(new[] { "shop.example.com", "example.com" }) &&
                record.CertificateNames!.SequenceEqual(new[] { "*.example.com", "example.com" })),
            CancellationToken.None));
    }

    [Fact]
    public async Task IssueAsync_NamesWithoutHosts_BindsOnlyTheBindingsTheNamesCover()
    {
        var harness = WildcardHarness(
            new IisBinding("http", "*", 80, "shop.example.com", null, null, false),
            new IisBinding("http", "*", 80, "deep.shop.example.com", null, null, false),
            new IisBinding("http", "*", 80, "example.net", null, null, false));
        harness.Order.SetupGet(value => value.DnsChallenges).Returns(
            [new AcmeDnsChallenge("example.com", true, "_acme-challenge.example.com", "wild-value")]);

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["*.example.com"]));

        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync(
            "My Site",
            It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "shop.example.com" })),
            It.IsAny<string>(),
            It.IsAny<string>(),
            It.IsAny<CancellationToken>()));
    }

    [Fact]
    public async Task IssueAsync_NoBindingIsCoveredByTheNames_IsRefusedBeforeAnOrder()
    {
        var harness = WildcardHarness(new IisBinding("http", "*", 80, "example.net", null, null, false));

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["*.example.com"])));

        Assert.Contains("*.example.com", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_AHostTheNamesDoNotCover_IsRefusedBeforeAnOrder()
    {
        var harness = WildcardHarness();

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site",
            ["example.com"],
            "admin@example.com",
            ValidationMethod: ValidationMethod.Dns01Provider,
            CertificateNames: ["*.example.com"])));

        Assert.Contains("not covered", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_NamesOverHttp_AreRefused()
    {
        var harness = new DnsHarness("C:\\inetpub\\site", new IisBinding("http", "*", 80, "shop.example.com", null, null, false));

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["shop.example.com"], "admin@example.com", CertificateNames: ["*.example.com"])));

        Assert.Contains("DNS validation", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("*.com")]
    [InlineData("*.*.example.com")]
    [InlineData("shop.*.example.com")]
    [InlineData("*example.com")]
    [InlineData("not a name")]
    public async Task IssueAsync_InvalidCertificateName_IsRefused(string name)
    {
        var harness = WildcardHarness();

        await Assert.ThrowsAsync<ArgumentException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: [name])));

        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_ANameTheWildcardAlreadyCovers_IsRefused()
    {
        var harness = WildcardHarness();

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site",
            ["shop.example.com"],
            "admin@example.com",
            ValidationMethod: ValidationMethod.Dns01Provider,
            CertificateNames: ["*.example.com", "shop.example.com"])));

        Assert.Contains("already covered", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssueAsync_ALiteralWildcardHost_IsRefusedWithAnExplanation()
    {
        var harness = WildcardHarness();

        var exception = await Assert.ThrowsAsync<ArgumentException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["*.example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.Contains("--names", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssueAsync_AnAuthorizationForAWildcardNotRequested_IsRefused()
    {
        var harness = WildcardHarness();

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["example.com"])));

        Assert.Contains("*.example.com", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("finalize", harness.Steps);
    }

    [Theory]
    [InlineData("Other Site", CertificateAuthorities.LetsEncryptStagingId, CertificateSource.Acme, true)]
    [InlineData("OTHER SITE", CertificateAuthorities.LetsEncryptStagingId, CertificateSource.Acme, true)]
    [InlineData("Other Site", CertificateAuthorities.LetsEncryptId, CertificateSource.Acme, false)]
    [InlineData("Other Site", CertificateAuthorities.LetsEncryptStagingId, CertificateSource.Imported, false)]
    public async Task IssueAsync_AWildcardManagedForAnotherSite_IsRefusedEvenWithForce(
        string site,
        string authorityId,
        CertificateSource source,
        bool refused)
    {
        var harness = WildcardHarness();
        harness.SetManaged(new ManagedCertificate(
            site,
            ["other.example.com"],
            "admin@example.com",
            "OLD",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(60),
            AuthorityId: authorityId,
            Source: source,
            CertificateNames: ["*.EXAMPLE.com"]));
        var request = new AcmeIssueRequest(
            "My Site",
            ["shop.example.com", "example.com"],
            "admin@example.com",
            Force: true,
            ValidationMethod: ValidationMethod.Dns01Provider,
            CertificateNames: ["*.example.com", "example.com"]);

        if (refused)
        {
            var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(request));
            Assert.Contains("share add", exception.Message, StringComparison.Ordinal);
            Assert.Empty(harness.Steps);
        }
        else
        {
            await harness.Service.IssueAsync(request);
            Assert.Contains("finalize", harness.Steps);
        }
    }

    [Fact]
    public async Task IssueAsync_TheWildcardOfAnotherCertificateOnTheSameSite_IsRefused_WithAdviceToAddTheHostsToIt()
    {
        var harness = WildcardHarness(
            new IisBinding("http", "*", 80, "other.example.com", null, null, false),
            new IisBinding("http", "*", 80, "shop.example.com", null, null, false),
            new IisBinding("http", "*", 80, "example.com", null, null, false));
        harness.SetManaged(new ManagedCertificate(
            "My Site", ["other.example.com"], "admin@example.com", "OLD", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60),
            AuthorityId: CertificateAuthorities.LetsEncryptStagingId, Source: CertificateSource.Acme, CertificateNames: ["*.EXAMPLE.com"]));

        // New host names only: a second certificate on the site, which cannot have the same wildcard.
        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["shop.example.com", "example.com"], "admin@example.com", Force: true,
            ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["*.example.com", "example.com"])));
        Assert.Contains("Add the host names to that certificate", exception.Message, StringComparison.Ordinal);
        Assert.Contains("'My Site'", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Steps);

        // With the certificate's own host name: that certificate, replaced with the new ones added.
        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["other.example.com", "shop.example.com", "example.com"], "admin@example.com", Force: true,
            ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["*.example.com", "example.com"]));
        Assert.Contains("finalize", harness.Steps);
    }

    // Several ACME certificates on one IIS site (docs/design/multiple-certificates-per-site.md, section 9).
    private static readonly IisBinding FirstHostHttps = new("https", "*", 443, "a.example.com", "AAAA", "My", true);
    private static readonly IisBinding SecondHostHttp = new("http", "*", 80, "b.example.com", null, null, false);

    /// <summary>The DNS harness, ordering for b.example.com.</summary>
    private static DnsHarness SecondHostHarness(params IisBinding[] bindings)
    {
        var harness = new DnsHarness(bindings);
        var challenge = new AcmeDnsChallenge("b.example.com", false, "_acme-challenge.b.example.com", "txt-value");
        harness.Order.SetupGet(value => value.DnsChallenges).Returns([challenge]);
        harness.Order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>())).Returns(Task.CompletedTask);
        return harness;
    }

    private static ManagedCertificate OnMySite(string name, string host, string thumbprint, CertificateSource source = CertificateSource.Acme) =>
        new(name, [host], "admin@example.com", thumbprint, DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(30),
            AuthorityId: CertificateAuthorities.LetsEncryptStagingId, Source: source, ValidationMethod: ValidationMethod.Dns01Provider);

    [Fact]
    public async Task IssueAsync_NewHostsOnASiteWithACertificate_AddASecondCertificate_BoundOnlyOnItsHosts()
    {
        var harness = SecondHostHarness(FirstHostHttps, SecondHostHttp);
        harness.SetManaged(OnMySite("My Site", "a.example.com", "AAAA"));

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["b.example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.SiteName == "My Site/b.example.com" && record.Hosts.SequenceEqual(new[] { "b.example.com" })),
            CancellationToken.None));
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync(
            "My Site", It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "b.example.com" })), "AABBCC", "My", It.IsAny<CancellationToken>()));
        Assert.Equal([("My Site/b.example.com", (string?)null)], harness.Deployment.Calls);
        harness.Store.Verify(value => value.RemoveAsync("AAAA", It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_RenewingASecondCertificate_KeepsItsName_AndReplacesOnlyItsOwnCertificate()
    {
        var harness = SecondHostHarness(FirstHostHttps, new IisBinding("https", "*", 443, "b.example.com", "BBBB", "My", true));
        harness.SetManaged(OnMySite("My Site", "a.example.com", "AAAA"), OnMySite("My Site/b.example.com", "b.example.com", "BBBB"));

        // As the renewal service asks for it.
        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site/b.example.com", ["b.example.com"], "admin@example.com", Force: true, ExpectedCurrentThumbprint: "BBBB",
            ValidationMethod: ValidationMethod.Dns01Provider, AcceptProductionRisk: true));

        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.SiteName == "My Site/b.example.com" && record.Thumbprint == "AABBCC"),
            CancellationToken.None));
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync(
            "My Site", It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "b.example.com" })), "AABBCC", "My", It.IsAny<CancellationToken>()));
        Assert.Equal([("My Site/b.example.com", (string?)"BBBB")], harness.Deployment.Calls);
        harness.Store.Verify(value => value.RemoveAsync("AAAA", It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_ForTheHostsOfABoughtSecondCertificate_ReplacesIt_AndKeepsTheBoughtOneInTheStore()
    {
        var harness = SecondHostHarness(FirstHostHttps, new IisBinding("https", "*", 443, "b.example.com", "BBBB", "My", true));
        harness.SetManaged(
            OnMySite("My Site", "a.example.com", "AAAA"),
            OnMySite("My Site/b.example.com", "b.example.com", "BBBB", CertificateSource.Imported));

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["b.example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.SiteName == "My Site/b.example.com" && record.Source == CertificateSource.Acme),
            CancellationToken.None));
        Assert.Equal([("My Site/b.example.com", (string?)null)], harness.Deployment.Calls);
        harness.Store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_AnAuthorizationTheCaReused_IsNotValidatedAgain()
    {
        // The CA kept the host's authorization valid from an earlier order, so the order has no challenge for it.
        var iis = MockIis(CreateSite("example.com"));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var order = new Mock<IAcmeOrderSession>();
        order.SetupGet(value => value.Challenges).Returns([]);
        order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>();
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var handler = new Mock<IChallengeHandler>(MockBehavior.Strict);
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.ImportPfxAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
        var artifacts = new Mock<ICertificateArtifactStore>();
        artifacts.Setup(value => value.SaveAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, ["example.com"]));
        var service = new AcmeService(iis.Object, protocol.Object, handler.Object, Mock.Of<IChallengeProbe>(), artifacts.Object, store.Object, EmptyManagedStoreMock().Object);

        await service.IssueAsync(new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com"));

        order.Verify(value => value.ValidateAsync(It.IsAny<AcmeHttpChallenge>(), It.IsAny<CancellationToken>()), Times.Never);
        order.Verify(value => value.FinalizeAsync("example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        handler.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task IssueAsync_ASecondCertificateWithHttpValidation_ServesTheChallengeFromTheSitesFolder()
    {
        var challenge = new AcmeHttpChallenge("b.example.com", "token", "key-authorization");
        var iis = MockIis(new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [FirstHostHttps, SecondHostHttp]));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var order = new Mock<IAcmeOrderSession>();
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>();
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var handler = new Mock<IChallengeHandler>();
        handler.Setup(value => value.PrepareAsync(It.IsAny<string>(), It.IsAny<string>(), challenge, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TrackingCleanup());
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.ImportPfxAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
        var artifacts = new Mock<ICertificateArtifactStore>();
        artifacts.Setup(value => value.SaveAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, ["b.example.com"]));
        var managed = EmptyManagedStoreMock();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([OnMySite("My Site", "a.example.com", "AAAA")]);
        var service = new AcmeService(iis.Object, protocol.Object, handler.Object, Mock.Of<IChallengeProbe>(), artifacts.Object, store.Object, managed.Object);

        await service.IssueAsync(new AcmeIssueRequest("My Site", ["b.example.com"], "admin@example.com"));

        handler.Verify(value => value.PrepareAsync("My Site", "C:\\inetpub\\site", challenge, It.IsAny<CancellationToken>()));
        artifacts.Verify(value => value.SaveAsync(
            "My Site/b.example.com", It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()));
        managed.Verify(value => value.UpsertAsync(It.Is<ManagedCertificate>(record => record.SiteName == "My Site/b.example.com"), CancellationToken.None));
    }

    [Fact]
    public async Task IssueAsync_InAWebFarm_CopiesEachChallengeToTheOtherServers_AndKeepsTheFolders()
    {
        var farm = Directory.CreateTempSubdirectory("sslense-farm-").FullName;
        try
        {
            var challenge = new AcmeHttpChallenge("b.example.com", "token", "key-authorization");
            var iis = MockIis(new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [FirstHostHttps, SecondHostHttp]));
            iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            var order = new Mock<IAcmeOrderSession>();
            order.SetupGet(value => value.Challenges).Returns([challenge]);
            order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateBundle());
            var protocol = new Mock<IAcmeProtocolClient>();
            protocol.Setup(value => value.CreateOrderAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(order.Object);
            var handler = new Mock<IChallengeHandler>();
            var copied = new TrackingCleanup();
            handler.Setup(value => value.PrepareAsync("My Site", "C:\\inetpub\\site", challenge, It.IsAny<CancellationToken>())).ReturnsAsync(new TrackingCleanup());
            handler.Setup(value => value.PrepareAsync("My Site", farm, challenge, It.IsAny<CancellationToken>())).ReturnsAsync(copied);
            var store = new Mock<ICertificateStore>();
            store.Setup(value => value.ImportPfxAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
            var artifacts = new Mock<ICertificateArtifactStore>();
            artifacts.Setup(value => value.SaveAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, ["b.example.com"]));
            var managed = EmptyManagedStoreMock();
            managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([OnMySite("My Site", "a.example.com", "AAAA")]);
            var service = new AcmeService(iis.Object, protocol.Object, handler.Object, Mock.Of<IChallengeProbe>(), artifacts.Object, store.Object, managed.Object);

            await service.IssueAsync(new AcmeIssueRequest("My Site", ["b.example.com"], "admin@example.com", FarmFolders: [farm + "\\"]));

            handler.Verify(value => value.PrepareAsync("My Site", farm, challenge, It.IsAny<CancellationToken>()), Times.Once);
            Assert.True(copied.WasDisposed);
            managed.Verify(value => value.UpsertAsync(It.Is<ManagedCertificate>(record => record.FarmFolders!.Single() == farm), CancellationToken.None));
        }
        finally
        {
            Directory.Delete(farm);
        }
    }

    [Theory]
    [InlineData(CertificateSource.Acme, CertificateAuthorities.LetsEncryptStagingId, true)]
    [InlineData(CertificateSource.Acme, CertificateAuthorities.LetsEncryptId, false)]
    [InlineData(CertificateSource.Imported, CertificateAuthorities.LetsEncryptStagingId, false)]
    public async Task IssueAsync_ARenewal_TellsTheCaWhichCertificateItReplaces_OnlyForItsOwnCertificate(
        CertificateSource source, string previousAuthority, bool replaces)
    {
        using var ca = new SSLense.Tests.Certificates.TestCertificateAuthority();
        var (current, key) = ca.IssueWithNewKey("example.com");
        key.Dispose();
        using var currentCertificate = current;
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", current.Thumbprint, "My", true));
        harness.SetManaged(new ManagedCertificate(
            "My Site", ["example.com"], "admin@example.com", current.Thumbprint, current.NotBefore, current.NotAfter,
            AuthorityId: previousAuthority, Source: source, ValidationMethod: ValidationMethod.Dns01Provider));
        harness.Store.Setup(value => value.OpenAsync(current.Thumbprint, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadCertificate(current.RawData));
        AcmeOrderOptions? sent = null;
        harness.Protocol.Setup(value => value.CreateDnsOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<AcmeOrderOptions>(), It.IsAny<CancellationToken>()))
            .Callback<string, IReadOnlyList<string>, CertificateAuthority, AcmeOrderOptions, CancellationToken>((_, _, _, options, _) => sent = options)
            .ReturnsAsync(harness.Order.Object);

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        if (replaces)
        {
            Assert.Equal(SSLense.Core.Renewal.AcmeRenewalInfoProvider.CreateCertificateId(current), sent!.Replaces);
        }
        else
        {
            Assert.Null(sent?.Replaces);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IssueAsync_HttpAnsweredBySslense_NeedsNoPort80BindingOrFolder_AndIsRemembered(bool noSite)
    {
        // docs/design/self-hosted-http-validation.md: the site has only an HTTPS binding and no physical path.
        var challenge = new AcmeHttpChallenge("b.example.com", "token", "key-authorization");
        var iis = MockIis(new IisSite(1, "My Site", "Started", null, [new IisBinding("https", "*", 443, "b.example.com", null, null, true)]));
        iis.Setup(value => value.ConfigureHttpsBindingsAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);
        var order = new Mock<IAcmeOrderSession>();
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>();
        protocol.Setup(value => value.CreateOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var served = new List<string>();
        var selfHosted = new Mock<ISelfHostedChallengeServer>();
        selfHosted.Setup(value => value.ServeAsync(It.IsAny<AcmeHttpChallenge>(), It.IsAny<CancellationToken>()))
            .Callback<AcmeHttpChallenge, CancellationToken>((value, _) => served.Add(value.Token))
            .ReturnsAsync(new TrackingCleanup());
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.ImportPfxAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
        var artifacts = new Mock<ICertificateArtifactStore>();
        artifacts.Setup(value => value.SaveAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, ["b.example.com"]));
        var managed = EmptyManagedStoreMock();
        var service = new AcmeService(iis.Object, protocol.Object, new Mock<IChallengeHandler>(MockBehavior.Strict).Object, Mock.Of<IChallengeProbe>(),
            artifacts.Object, store.Object, managed.Object, selfHosted: selfHosted.Object);

        await service.IssueAsync(noSite
            ? new AcmeIssueRequest("Remote Desktop", [], "admin@example.com", CertificateNames: ["b.example.com"], NoSite: true, SelfHostedHttp: true)
            : new AcmeIssueRequest("My Site", ["b.example.com"], "admin@example.com", SelfHostedHttp: true));

        Assert.Equal(["token"], served);
        managed.Verify(value => value.UpsertAsync(It.Is<ManagedCertificate>(record => record.SelfHostedHttp && record.ValidationMethod == ValidationMethod.Http01), CancellationToken.None));
    }

    [Fact]
    public async Task IssueAsync_HttpWithoutSslenseAnswering_StillNeedsAPort80Binding()
    {
        var iis = MockIis(new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [new IisBinding("https", "*", 443, "b.example.com", null, null, true)]));
        var service = new AcmeService(iis.Object, new Mock<IAcmeProtocolClient>(MockBehavior.Strict).Object, Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(), Mock.Of<ICertificateArtifactStore>(), Mock.Of<ICertificateStore>(), EmptyManagedStore());

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            service.IssueAsync(new AcmeIssueRequest("My Site", ["b.example.com"], "admin@example.com")));

        Assert.Contains("HTTP binding on port 80", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssueAsync_AnIpAddress_NeedsHttpAnsweredBySslense()
    {
        // docs/design/ip-certificates.md
        var iis = MockIis(new IisSite(1, "My Site", "Started", "C:\\inetpub\\site", [new IisBinding("http", "*", 80, "www.example.com", null, null, false)]));
        var service = new AcmeService(iis.Object, new Mock<IAcmeProtocolClient>(MockBehavior.Strict).Object, Mock.Of<IChallengeHandler>(),
            Mock.Of<IChallengeProbe>(), Mock.Of<ICertificateArtifactStore>(), Mock.Of<ICertificateStore>(), EmptyManagedStore());

        var exception = await Assert.ThrowsAnyAsync<SSLense.Core.Errors.SslenseException>(() =>
            service.IssueAsync(new AcmeIssueRequest("My Site", ["192.0.2.10"], "admin@example.com")));

        Assert.Equal("SSL6027", exception.Code);
    }

    [Fact]
    public async Task IssueAsync_AnIpAddressAnsweredBySslense_NeedsNoBinding_AndIsBoundByAddress()
    {
        var challenge = new AcmeHttpChallenge("2001:db8::10", "token", "key-authorization");
        var iis = MockIis(new IisSite(1, "My Site", "Started", null, []));
        IReadOnlyList<string>? bound = null;
        iis.Setup(value => value.ConfigureHttpsBindingsAsync("My Site", It.IsAny<IReadOnlyList<string>>(), "AABBCC", "My", It.IsAny<CancellationToken>()))
            .Callback<string, IReadOnlyList<string>, string, string, CancellationToken>((_, hosts, _, _, _) => bound = hosts)
            .Returns(Task.CompletedTask);
        var order = new Mock<IAcmeOrderSession>();
        order.SetupGet(value => value.Challenges).Returns([challenge]);
        order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync(CreateBundle());
        var protocol = new Mock<IAcmeProtocolClient>();
        protocol.Setup(value => value.CreateOrderAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(order.Object);
        var selfHosted = new Mock<ISelfHostedChallengeServer>();
        selfHosted.Setup(value => value.ServeAsync(challenge, It.IsAny<CancellationToken>())).ReturnsAsync(new TrackingCleanup());
        var store = new Mock<ICertificateStore>();
        store.Setup(value => value.ImportPfxAsync(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(6), true));
        var artifacts = new Mock<ICertificateArtifactStore>();
        artifacts.Setup(value => value.SaveAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, []));
        var service = new AcmeService(iis.Object, protocol.Object, Mock.Of<IChallengeHandler>(), Mock.Of<IChallengeProbe>(),
            artifacts.Object, store.Object, EmptyManagedStore(), selfHosted: selfHosted.Object);

        await service.IssueAsync(new AcmeIssueRequest("My Site", ["[2001:DB8:0::10]"], "admin@example.com", SelfHostedHttp: true));

        protocol.Verify(value => value.CreateOrderAsync(It.IsAny<string>(), It.Is<IReadOnlyList<string>>(hosts => hosts.SequenceEqual(new[] { "2001:db8::10" })),
            It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()));
        Assert.Equal(["2001:db8::10"], bound);
    }

    [Fact]
    public void ARequestSslenseSigns_PutsAnIpAddressInAsOne()
    {
        using var key = System.Security.Cryptography.ECDsa.Create();
        var request = ImportedCertificateService.BuildRequest(key, ["192.0.2.10", "www.example.com"]);

        var names = new System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension(request.CertificateExtensions.Single(extension => extension.Oid?.Value == "2.5.29.17").RawData);
        Assert.Equal([System.Net.IPAddress.Parse("192.0.2.10")], names.EnumerateIPAddresses());
        Assert.Equal(["www.example.com"], names.EnumerateDnsNames());
    }

    [Fact]
    public async Task IssueAsync_HostsOnly_RecordsNoCertificateNames()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.CertificateNames == null),
            CancellationToken.None));
    }

    [Theory]
    [InlineData(ValidationMethod.Dns01Provider)]
    [InlineData(ValidationMethod.Dns01Manual)]
    public async Task IssueAsync_ReplacingAnAcmeCertificate_RemovesTheOldOne_AfterTheRecordIsSaved(ValidationMethod method)
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous());
        var order = new List<string>();
        harness.Managed.Setup(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .Callback(() => order.Add("saved"))
            .Returns(Task.CompletedTask);
        harness.Store.Setup(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()))
            .Callback(() => order.Add("removed"))
            .Returns(Task.CompletedTask);

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site",
            ["example.com"],
            "admin@example.com",
            Force: true,
            ExpectedCurrentThumbprint: "OLD",
            ValidationMethod: method,
            ConfirmManualDns: (_, _) => Task.FromResult(true),
            KeepReplacedForRollback: false));

        Assert.Equal(["saved", "removed"], order);
    }

    [Fact]
    public async Task IssueAsync_TheOldCertificateIsStillBound_KeepsItAndNamesTheSite()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.SetManaged(Previous());
        var lines = new List<string>();

        await harness.Service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider, KeepReplacedForRollback: false),
            new SynchronousProgress(value => lines.Add(value.Message)));

        harness.Store.Verify(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()), Times.Never);
        Assert.Contains(lines, line => line.Contains("'My Site'", StringComparison.Ordinal) && line.Contains("retained", StringComparison.Ordinal));
    }

    [Fact]
    public async Task IssueAsync_ReplacingAValidCertificate_KeepsItForRollback()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous());

        var result = await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        Assert.True(result.PreviousCertificateKept);
        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.Thumbprint == "AABBCC" && record.PreviousThumbprint == "OLD"),
            CancellationToken.None));
        harness.Store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_ReplacingAgain_RemovesTheCertificateKeptBefore()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous() with { PreviousThumbprint = "OLDER" });

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Store.Verify(value => value.RemoveAsync("OLDER", It.IsAny<CancellationToken>()), Times.Once);
        harness.Store.Verify(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_ReplacingAnExpiredCertificate_RemovesIt_AndKeepsNothing()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous() with { NotAfter = DateTimeOffset.UtcNow.AddHours(-1) });

        var result = await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        Assert.False(result.PreviousCertificateKept);
        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.PreviousThumbprint == null),
            CancellationToken.None));
        harness.Store.Verify(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task IssueAsync_DeploymentStepsPending_KeepsTheReplacedCertificate()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous());
        harness.Deployment.Next = new DeploymentAfterInstall(
            new DeploymentRunResult("My Site", "AABBCC", false, 0, 1, "Step 1 failed"), KeepReplaced: true);

        var result = await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        Assert.Equal([("My Site", "OLD")], harness.Deployment.Calls);
        Assert.True(result.PreviousCertificateKept);
        Assert.False(result.Deployment!.Succeeded);
        harness.Store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_DeploymentStepsCannotRun_KeepsTheReplacedCertificate_AndStillSucceeds()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous());
        harness.Deployment.Fail = new IOException("The state file is locked.");

        var result = await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        Assert.Equal("AABBCC", result.CertificateThumbprint);
        Assert.True(result.PreviousCertificateKept);
        harness.Store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_ReuseKey_SignsWithTheCurrentKey_AndLinksTheNewCertificateToIt()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.SetManaged(Previous());
        using var currentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var current = new CertificateRequest("CN=example.com", currentKey, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(4));
        harness.Store.Setup(value => value.OpenAsync("OLD", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadPkcs12(current.Export(X509ContentType.Pkcs12, "pw"), "pw", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable));
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        harness.Order.Setup(value => value.FinalizeWithRequestAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .Returns<byte[], CancellationToken>((csr, _) =>
            {
                using var leaf = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256)
                    .Create(ca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(60), [1, 2, 3, 4]);
                return Task.FromResult(leaf.ExportCertificatePem() + "\n" + ca.ExportCertificatePem());
            });
        byte[]? linkedKey = null;
        harness.Store.Setup(value => value.AddAsync(It.IsAny<X509Certificate2>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .Callback<X509Certificate2, string, CancellationToken>((certificate, _, _) =>
            {
                Assert.True(certificate.HasPrivateKey);
                linkedKey = certificate.GetECDsaPublicKey()!.ExportSubjectPublicKeyInfo();
            })
            .ReturnsAsync(new InstalledCertificate("REUSED", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));

        var result = await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider, ReuseKey: true));

        Assert.Equal("REUSED", result.CertificateThumbprint);
        Assert.True(result.KeyReused);
        Assert.Equal(currentKey.ExportSubjectPublicKeyInfo(), linkedKey);
        Assert.DoesNotContain("finalize", harness.Steps);
        harness.Store.Verify(value => value.ImportPfxAsync(
            It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        harness.Managed.Verify(value => value.UpsertAsync(It.Is<ManagedCertificate>(record => record.ReuseKey), CancellationToken.None));
    }

    [Fact]
    public async Task IssueAsync_ReuseKey_WithAKeyOfAnotherType_UsesANewKey_AndSaysSo()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.SetManaged(Previous());
        using var currentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var current = new CertificateRequest("CN=example.com", currentKey, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(4));
        harness.Store.Setup(value => value.OpenAsync("OLD", It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadPkcs12(current.Export(X509ContentType.Pkcs12, "pw"), "pw", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable));
        harness.Protocol.Setup(value => value.CreateDnsOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<AcmeOrderOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(harness.Order.Object);
        var lines = new List<string>();

        var result = await harness.Service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider,
                KeyType: CertificateKeyType.Rsa2048, ReuseKey: true),
            new SynchronousProgress(value => lines.Add(value.Message)));

        Assert.Contains("finalize", harness.Steps);
        Assert.Contains(lines, line => line.Contains("is not rsa-2048", StringComparison.Ordinal));
        Assert.False(result.KeyReused);
    }

    [Theory]
    [InlineData(CertificateKeyType.EcdsaP256, true)]
    [InlineData(CertificateKeyType.EcdsaP384, false)]
    [InlineData(CertificateKeyType.Rsa2048, false)]
    public void KeyMatches_OnlyTheSameFamilyAndSize(CertificateKeyType type, bool expected)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.Equal(expected, AcmeService.Matches(key, type));
    }

    [Fact]
    public async Task IssueAsync_KeyChainAndProfile_GoToTheOrder_AndAreSavedWithTheCertificate()

    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.Directory.Profiles = new Dictionary<string, string> { ["shortlived"] = "Six days" };
        AcmeOrderOptions? used = null;
        harness.Protocol.Setup(value => value.CreateDnsOrderAsync(
                It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<AcmeOrderOptions>(), It.IsAny<CancellationToken>()))
            .Callback<string, IReadOnlyList<string>, CertificateAuthority, AcmeOrderOptions, CancellationToken>((_, _, _, options, _) => used = options)
            .ReturnsAsync(harness.Order.Object);

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider,
            KeyType: CertificateKeyType.Rsa3072, PreferredChain: "ISRG Root X1", Profile: "shortlived"));

        Assert.Equal(new AcmeOrderOptions(CertificateKeyType.Rsa3072, "ISRG Root X1", "shortlived"), used);
        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.KeyType == CertificateKeyType.Rsa3072 && record.PreferredChain == "ISRG Root X1" && record.Profile == "shortlived"),
            CancellationToken.None));
    }

    [Fact]
    public async Task IssueAsync_AProfileTheCaDoesNotOffer_IsRefusedBeforeOrdering_WithTheOnesItDoes()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.Directory.Profiles = new Dictionary<string, string> { ["classic"] = "", ["tlsserver"] = "" };

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider, Profile: "shortlived")));

        Assert.Contains("classic, tlsserver", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("finalize", harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_NoSite_InstallsWithoutBindingAnything_AndSavesANoSiteRecord()

    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        var result = await harness.Service.IssueAsync(new AcmeIssueRequest(
            "RDP", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["Example.com"], NoSite: true));

        Assert.Equal("AABBCC", result.CertificateThumbprint);
        harness.Iis.Verify(value => value.ConfigureHttpsBindingsAsync(
            It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        harness.Managed.Verify(value => value.UpsertAsync(
            It.Is<ManagedCertificate>(record => record.NoSite && record.SiteName == "RDP" && record.Hosts.SequenceEqual(new[] { "example.com" })),
            CancellationToken.None));
        Assert.Contains("validate example.com", harness.Steps);
    }

    [Theory]
    [InlineData("My Site", ValidationMethod.Dns01Provider, "is the name of an IIS site")]
    [InlineData("RDP", ValidationMethod.Http01, "needs DNS validation")]
    [InlineData("RDP: host", ValidationMethod.Dns01Provider, "cannot name a certificate")]
    public async Task IssueAsync_NoSite_RefusesASiteNameHttpValidationAndUnsafeNames(string name, ValidationMethod method, string expected)
    {
        var harness = new DnsHarness();

        var exception = await Assert.ThrowsAnyAsync<Exception>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            name, [], "admin@example.com", ValidationMethod: method, CertificateNames: ["example.com"], NoSite: true)));

        Assert.Contains(expected, exception.Message, StringComparison.Ordinal);
        harness.Protocol.Verify(value => value.CreateDnsOrderAsync(
            It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_ForASite_RefusesANameUsedByANoSiteCertificate()
    {
        var harness = new DnsHarness();
        harness.SetManaged(Previous() with { NoSite = true });

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.Contains("no IIS site", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssueAsync_NoSite_AnExistingCertificateNeedsForce()
    {
        var harness = new DnsHarness();
        harness.SetManaged(Previous() with { SiteName = "RDP", NoSite = true });

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "RDP", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["example.com"], NoSite: true)));

        Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssueAsync_AnImportedCertificateIsReplaced_IsNeverRemoved()


    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous() with { Source = CertificateSource.Imported });

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_ACertificateOfAnotherSite_IsNeverRemoved()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous() with { SiteName = "Other Site" });

        await harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider));

        harness.Store.Verify(value => value.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task IssueAsync_RemovingTheOldCertificateFails_StillSucceedsAndSaysSo()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "AABBCC", "My", true));
        harness.SetManaged(Previous());
        harness.Store.Setup(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("store is locked"));
        var lines = new List<string>();

        var result = await harness.Service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider, KeepReplacedForRollback: false),
            new SynchronousProgress(value => lines.Add(value.Message)));

        Assert.Equal("AABBCC", result.CertificateThumbprint);
        Assert.Contains(lines, line => line.Contains("store is locked", StringComparison.Ordinal));
    }

    private static ManagedCertificate Previous() => new(
        "My Site", ["example.com"], "admin@example.com", "OLD", DateTimeOffset.UtcNow.AddDays(-60), DateTimeOffset.UtcNow.AddDays(4));

    private sealed class SynchronousProgress(Action<ProgressEvent> report) : IProgress<ProgressEvent>
    {
        public void Report(ProgressEvent value) => report(value);
    }

    private static DnsHarness WildcardHarness(params IisBinding[] bindings)
    {
        var harness = new DnsHarness(bindings.Length > 0
            ? bindings
            : [
                new IisBinding("http", "*", 80, "shop.example.com", null, null, false),
                new IisBinding("http", "*", 80, "example.com", null, null, false)
            ]);
        harness.Order.SetupGet(value => value.DnsChallenges).Returns(
        [
            new AcmeDnsChallenge("example.com", true, "_acme-challenge.example.com", "wild-value"),
            new AcmeDnsChallenge("example.com", false, "_acme-challenge.example.com", "base-value")
        ]);
        harness.SetManaged();
        return harness;
    }

    [Fact]
    public async Task IssueAsync_Http_StillNeedsAPort80Binding()
    {
        var harness = new DnsHarness(
            "C:\\inetpub\\site",
            new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true)));

        Assert.Contains("port 80", exception.Message, StringComparison.Ordinal);
    }

    private sealed class FakeDirectoryReader : IAcmeDirectoryReader
    {
        public IReadOnlyDictionary<string, string>? Profiles { get; set; }

        public Task<AcmeDirectoryInfo> ReadAsync(Uri directoryUri, CancellationToken cancellationToken) =>
            Task.FromResult(new AcmeDirectoryInfo(false, [], true, null, Profiles));
    }

    private sealed class FakeDeploymentRunner : IDeploymentRunner

    {
        public List<(string Site, string? Replaced)> Calls { get; } = [];

        public DeploymentAfterInstall Next { get; set; } = new(null, false);

        public Exception? Fail { get; set; }

        public Task<DeploymentAfterInstall> RunAfterInstallAsync(
            string site,
            string? replacedThumbprint,
            IReadOnlyList<string> sitesLeftOut,
            IProgress<ProgressEvent>? progress,
            CancellationToken cancellationToken)
        {
            Calls.Add((site, replacedThumbprint));
            return Fail is null ? Task.FromResult(Next) : Task.FromException<DeploymentAfterInstall>(Fail);
        }
    }

    private sealed class DnsHarness

    {
        public DnsHarness(params IisBinding[] bindings)
            : this(null, bindings)
        {
        }

        public DnsHarness(string? physicalPath, params IisBinding[] bindings)
        {
            var challenge = new AcmeDnsChallenge("example.com", false, "_acme-challenge.example.com", "txt-value");
            Dns = new FakeDnsChallengeService(Steps);
            Order.SetupGet(value => value.DnsChallenges).Returns([challenge]);
            Order.Setup(value => value.ValidateAsync(challenge, It.IsAny<CancellationToken>()))
                .Callback(() => Steps.Add("validate example.com"))
                .Returns(Task.CompletedTask);
            Order.Setup(value => value.FinalizeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Callback(() => Steps.Add("finalize"))
                .ReturnsAsync(CreateBundle());
            Protocol.Setup(value => value.CreateDnsOrderAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateAuthority>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Order.Object);
            Iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync([new IisSite(1, "My Site", "Started", physicalPath, bindings)]);
            var artifacts = new Mock<ICertificateArtifactStore>();
            artifacts.Setup(value => value.SaveAsync(
                    It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CertificateBundle>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new AcmeIssueResult("certificate.pem", null, ["example.com"]));
            Store.Setup(value => value.ImportPfxAsync(
                    It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new InstalledCertificate("AABBCC", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(60), true));
            Service = new AcmeService(
                Iis.Object,
                Protocol.Object,
                Mock.Of<IChallengeHandler>(MockBehavior.Strict),
                Mock.Of<IChallengeProbe>(MockBehavior.Strict),
                artifacts.Object,
                Store.Object,
                Managed.Object,
                dnsChallenges: Dns,
                deployment: Deployment,
                directoryReader: Directory);
        }

        public FakeDirectoryReader Directory { get; } = new();

        public FakeDeploymentRunner Deployment { get; } = new();

        public List<string> Steps { get; } = [];

        public Mock<IIisService> Iis { get; } = new();

        public Mock<ICertificateStore> Store { get; } = new();

        public void SetManaged(params ManagedCertificate[] records) =>
            Managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(records);

        public Mock<IAcmeOrderSession> Order { get; } = new();

        public Mock<IAcmeProtocolClient> Protocol { get; } = new();

        public Mock<IManagedCertificateStore> Managed { get; } = EmptyManagedStoreMock();

        public FakeDnsChallengeService Dns { get; }

        public AcmeService Service { get; }
    }

    private sealed class FakeDnsChallengeService(List<string> steps) : IDnsChallengeService
    {
        public Exception? FailCheck { get; set; }

        public Exception? FailPublish { get; set; }

        public Task CheckBeforeOrderAsync(ValidationMethod method, IReadOnlyList<string> certificateNames, string authorityId, CancellationToken cancellationToken)
        {
            if (FailCheck is not null)
            {
                return Task.FromException(FailCheck);
            }

            steps.Add($"check {string.Join(",", certificateNames)}");
            return Task.CompletedTask;
        }

        public Task<IAsyncDisposable> PublishAsync(
            ValidationMethod method,
            IReadOnlyList<AcmeDnsChallenge> challenges,
            ManualDnsConfirmation? confirmManual,
            IProgress<ProgressEvent>? progress,
            CancellationToken cancellationToken)
        {
            if (FailPublish is not null)
            {
                return Task.FromException<IAsyncDisposable>(FailPublish);
            }

            steps.Add($"publish {challenges.Count}");
            return Task.FromResult<IAsyncDisposable>(new StepCleanup(steps));
        }

        public Task<IReadOnlyList<string>> CleanUpAbandonedAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>([]);
    }

    private sealed class StepCleanup(List<string> steps) : IAsyncDisposable
    {
        public ValueTask DisposeAsync()
        {
            steps.Add("cleanup");
            return ValueTask.CompletedTask;
        }
    }

    private static Mock<IManagedCertificateStore> EmptyManagedStoreMock()
    {
        var managed = new Mock<IManagedCertificateStore>();
        managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        return managed;
    }

    private static IManagedCertificateStore EmptyManagedStore() => EmptyManagedStoreMock().Object;

    private static Mock<IIisService> MockIis(IisSite site)
    {
        var iis = new Mock<IIisService>(MockBehavior.Strict);
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync([site]);
        return iis;
    }

    private static IisSite CreateSite(string host) => new(
        1,
        "My Site",
        "Started",
        "C:\\inetpub\\site",
        [new IisBinding("http", "*", 80, host, null, null, false)]);

    private static CertificateBundle CreateBundle()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=example.com",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        return new CertificateBundle(certificate.ExportCertificatePem(), [1, 2, 3]);
    }

    private sealed class TrackingCleanup : IAsyncDisposable
    {
        public bool WasDisposed { get; private set; }

        public ValueTask DisposeAsync()
        {
            WasDisposed = true;
            return ValueTask.CompletedTask;
        }
    }
}

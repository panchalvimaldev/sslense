using Moq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core;
using SSLense.Core.Config;
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
        handler.Setup(value => value.PrepareAsync("C:\\inetpub\\site", challenge, It.IsAny<CancellationToken>()))
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
            Mock.Of<IManagedCertificateStore>());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
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
            Mock.Of<IManagedCertificateStore>());

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
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
                true));
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
            Mock.Of<IManagedCertificateStore>());

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com")));

        Assert.Contains("--force", exception.Message, StringComparison.Ordinal);
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
                issuer));
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

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(
            new AcmeIssueRequest(
                "My Site", ["example.com"], "admin@example.com",
                AuthorityId: CertificateAuthorities.LetsEncryptId)));

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
            Mock.Of<IManagedCertificateStore>());

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
    public async Task IssueAsync_Dns_AHostNotOnTheSite_IsRefusedBeforeAnOrder()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["other.example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider)));

        Assert.Contains("HTTP or HTTPS binding", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_Dns_ProviderCheckFails_CreatesNoOrder()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.Dns.FailCheck = new InvalidOperationException("no provider");

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
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

        await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
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

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", [], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["*.example.com"])));

        Assert.Contains("*.example.com", exception.Message, StringComparison.Ordinal);
        Assert.Empty(harness.Steps);
    }

    [Fact]
    public async Task IssueAsync_AHostTheNamesDoNotCover_IsRefusedBeforeAnOrder()
    {
        var harness = WildcardHarness();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
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

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", ValidationMethod: ValidationMethod.Dns01Provider, CertificateNames: ["example.com"])));

        Assert.Contains("*.example.com", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("finalize", harness.Steps);
    }

    [Theory]
    [InlineData("Other Site", CertificateAuthorities.LetsEncryptStagingId, CertificateSource.Acme, true)]
    [InlineData("OTHER SITE", CertificateAuthorities.LetsEncryptStagingId, CertificateSource.Acme, true)]
    [InlineData("My Site", CertificateAuthorities.LetsEncryptStagingId, CertificateSource.Acme, false)]
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
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(request));
            Assert.Contains("only one site", exception.Message, StringComparison.Ordinal);
            Assert.Empty(harness.Steps);
        }
        else
        {
            await harness.Service.IssueAsync(request);
            Assert.Contains("finalize", harness.Steps);
        }
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
            ConfirmManualDns: (_, _) => Task.FromResult(true)));

        Assert.Equal(["saved", "removed"], order);
    }

    [Fact]
    public async Task IssueAsync_TheOldCertificateIsStillBound_KeepsItAndNamesTheSite()
    {
        var harness = new DnsHarness(new IisBinding("https", "*", 443, "example.com", "OLD", "My", true));
        harness.SetManaged(Previous());
        var lines = new List<string>();

        await harness.Service.IssueAsync(
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider),
            new SynchronousProgress(value => lines.Add(value.Message)));

        harness.Store.Verify(value => value.RemoveAsync("OLD", It.IsAny<CancellationToken>()), Times.Never);
        Assert.Contains(lines, line => line.Contains("'My Site'", StringComparison.Ordinal) && line.Contains("retained", StringComparison.Ordinal));
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
            new AcmeIssueRequest("My Site", ["example.com"], "admin@example.com", Force: true, ValidationMethod: ValidationMethod.Dns01Provider),
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

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => harness.Service.IssueAsync(new AcmeIssueRequest(
            "My Site", ["example.com"], "admin@example.com", Force: true)));

        Assert.Contains("port 80", exception.Message, StringComparison.Ordinal);
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
                dnsChallenges: Dns);
        }

        public List<string> Steps { get; } = [];

        public Mock<IIisService> Iis { get; } = new();

        public Mock<ICertificateStore> Store { get; } = new();

        public void SetManaged(params ManagedCertificate[] records) =>
            Managed.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(records);

        public Mock<IAcmeOrderSession> Order { get; } = new();

        public Mock<IAcmeProtocolClient> Protocol { get; } = new();

        public Mock<IManagedCertificateStore> Managed { get; } = new();

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

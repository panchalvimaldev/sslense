using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Moq;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using SSLense.Core.Config;
using SSLense.Core.Iis;
using SSLense.Core.Notifications;
using SSLense.Core.Reminders;
using SSLense.Core.Renewal;
using Xunit;

namespace SSLense.Tests.Certificates;

/// <summary>Certificates on other machines (docs/design/remote-certificates.md).</summary>
public sealed class RemoteCertificateTests
{
    [Fact]
    public async Task TheReader_ReadsTheServedCertificate_EvenAnUntrustedOne()
    {
        using var certificate = SelfSigned("lb.example.com", 30);
        await using var server = await TlsServer.StartAsync(certificate);

        using var served = await new RemoteCertificateReader().ReadAsync("localhost", server.Port, CancellationToken.None);

        Assert.Equal(certificate.Thumbprint, served.Thumbprint);
    }

    [Fact]
    public async Task TheReader_ReportsAHostThatDoesNotAnswer()
    {
        var exception = await Assert.ThrowsAsync<SSLense.Core.Errors.SslenseException>(() =>
            new RemoteCertificateReader().ReadAsync("localhost", FreePort(), CancellationToken.None));

        Assert.Equal("SSL4053", exception.Code);
    }

    [Fact]
    public async Task Watching_RecordsTheCertificate_AsOneOnAnotherMachine()
    {
        using var certificate = SelfSigned("lb.example.com", 30);
        var store = new List<ManagedCertificate>();
        var service = new RemoteCertificateService(Store(store).Object, NoSites().Object, Reader(certificate).Object);

        var record = await service.WatchAsync("Load balancer", "LB.example.com.", 8443);

        Assert.Same(record, Assert.Single(store));
        Assert.Equal(CertificateSource.Remote, record.Source);
        Assert.True(record.NoSite);
        Assert.Equal(["lb.example.com"], record.Hosts);
        Assert.Equal(8443, record.RemotePort);
        Assert.Equal(certificate.Thumbprint, record.Thumbprint);
    }

    [Fact]
    public async Task Watching_UnderANameAlreadyUsed_IsRefused()
    {
        using var certificate = SelfSigned("lb.example.com", 30);
        var store = new List<ManagedCertificate> { new("Shop", ["shop.example.com"], "", "AA", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(30)) };
        var service = new RemoteCertificateService(Store(store).Object, NoSites().Object, Reader(certificate).Object);

        var exception = await Assert.ThrowsAsync<SSLense.Core.Errors.SslenseException>(() => service.WatchAsync("shop", "lb.example.com"));

        Assert.Equal("SSL6028", exception.Code);
    }

    [Fact]
    public async Task TheDailyCheck_TakesOverAReplacedCertificate_AndReportsAnUnreachableHost()
    {
        using var old = SelfSigned("lb.example.com", 5);
        using var renewed = SelfSigned("lb.example.com", 90);
        var store = new List<ManagedCertificate>
        {
            RemoteCertificateService.Describe("Load balancer", "lb.example.com", 443, old),
            RemoteCertificateService.Describe("Firewall", "fw.example.com", 443, old)
        };
        var reader = new Mock<IRemoteCertificateReader>();
        reader.Setup(value => value.ReadAsync("lb.example.com", 443, It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadCertificate(renewed.RawData));
        reader.Setup(value => value.ReadAsync("fw.example.com", 443, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new SSLense.Core.Errors.SslenseException(SSLense.Core.Errors.ErrorCodes.RemoteUnreachable, "Could not read the certificate served by fw.example.com:443."));
        var detector = new OutsideRenewalDetector(Store(store).Object, NoSites().Object, Mock.Of<ICertificateStore>(), Mock.Of<INotifier>(),
            Mock.Of<ICertificateOperationLock>(), reader.Object);

        var changes = await detector.DetectAsync();

        var loadBalancer = store.Single(record => record.SiteName == "Load balancer");
        Assert.Equal(renewed.Thumbprint, loadBalancer.Thumbprint);
        Assert.Equal(renewed.NotAfter.ToUniversalTime(), loadBalancer.NotAfter);
        Assert.Contains(changes, change => change.Contains("lb.example.com:443", StringComparison.Ordinal) && change.Contains("was replaced", StringComparison.Ordinal));
        Assert.Contains(changes, change => change.Contains("SSL4053", StringComparison.Ordinal) && change.Contains("'Firewall'", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Renewal_SkipsACertificateOnAnotherMachine()
    {
        using var certificate = SelfSigned("lb.example.com", 3);
        var store = new List<ManagedCertificate> { RemoteCertificateService.Describe("Load balancer", "lb.example.com", 443, certificate) };
        var config = new Mock<IConfigStore>();
        config.Setup(value => value.LoadAsync(It.IsAny<CancellationToken>())).ReturnsAsync(new AppConfig());
        var service = new RenewalService(Store(store).Object, config.Object, new Mock<IAcmeService>(MockBehavior.Strict).Object,
            Mock.Of<IIisService>(), Mock.Of<ICertificateStore>(), Mock.Of<INotifier>());

        var result = Assert.Single(await service.RenewAsync(new RenewalRequest(All: true, Scheduled: true)));

        Assert.False(result.Attempted);
        Assert.Contains("another machine", result.Message, StringComparison.Ordinal);
    }

    private static Mock<IManagedCertificateStore> Store(List<ManagedCertificate> records)
    {
        var store = new Mock<IManagedCertificateStore>();
        store.Setup(value => value.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => records.ToArray());
        store.Setup(value => value.UpsertAsync(It.IsAny<ManagedCertificate>(), It.IsAny<CancellationToken>()))
            .Callback<ManagedCertificate, CancellationToken>((record, _) => { records.RemoveAll(value => value.SiteName == record.SiteName); records.Add(record); })
            .Returns(Task.CompletedTask);
        return store;
    }

    private static Mock<IIisService> NoSites()
    {
        var iis = new Mock<IIisService>();
        iis.Setup(value => value.GetSitesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        return iis;
    }

    private static Mock<IRemoteCertificateReader> Reader(X509Certificate2 certificate)
    {
        var reader = new Mock<IRemoteCertificateReader>();
        reader.Setup(value => value.ReadAsync(It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => X509CertificateLoader.LoadCertificate(certificate.RawData));
        return reader;
    }

    private static X509Certificate2 SelfSigned(string host, int days)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(days));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    /// <summary>One TLS handshake on a localhost port, serving the certificate.</summary>
    private sealed class TlsServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly Task _serving;

        private TlsServer(TcpListener listener, X509Certificate2 certificate)
        {
            _listener = listener;
            _serving = Task.Run(async () =>
            {
                using var client = await listener.AcceptTcpClientAsync();
                await using var stream = new SslStream(client.GetStream());
                try { await stream.AuthenticateAsServerAsync(certificate); }
                catch (Exception exception) when (exception is IOException or System.Security.Authentication.AuthenticationException) { }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public static Task<TlsServer> StartAsync(X509Certificate2 certificate)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return Task.FromResult(new TlsServer(listener, certificate));
        }

        public async ValueTask DisposeAsync()
        {
            await Task.WhenAny(_serving, Task.Delay(TimeSpan.FromSeconds(5)));
            _listener.Stop();
        }
    }
}

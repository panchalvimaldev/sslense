using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Iis;

public sealed class TlsBindingProbeTests
{
    [Fact]
    public async Task GetServedThumbprintAsync_ReturnsCertificateServedForSniHost()
    {
        using var certificate = CreateServerCertificate("example.com");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? requestedHost = null;
        var server = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            await using var stream = new SslStream(client.GetStream());
            await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificateSelectionCallback = (_, hostName) =>
                {
                    requestedHost = hostName;
                    return certificate;
                }
            });
        });

        var thumbprint = await new TlsBindingProbe()
            .GetServedThumbprintAsync("127.0.0.1", "example.com", port, CancellationToken.None);
        await server;

        Assert.Equal(certificate.Thumbprint, thumbprint);
        Assert.Equal("example.com", requestedHost);
    }

    private static X509Certificate2 CreateServerCertificate(string host)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={host}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));

        // SChannel cannot use an ephemeral key, so round-trip through PFX into a temporary user key.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.UserKeySet);
    }
}

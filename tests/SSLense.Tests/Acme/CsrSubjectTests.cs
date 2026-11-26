using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certes;
using SSLense.Core.Acme;
using SSLense.Core.Certificates;
using Xunit;

namespace SSLense.Tests.Acme;

/// <summary>Let's Encrypt refused "CSR contains IP address in Common Name" in the combined test (docs/design/ip-certificates.md).</summary>
public sealed class CsrSubjectTests
{
    [Theory]
    [InlineData("shop.example.com", "shop.example.com")]
    [InlineData("203.0.113.10,shop.example.com", "shop.example.com")]
    [InlineData("2001:db8::10,shop.example.com", "shop.example.com")]
    [InlineData("[2001:db8::10]", null)]
    [InlineData("203.0.113.10", null)]
    [InlineData("203.0.113.10,198.51.100.7", null)]
    public void TheCommonName_IsTheFirstDnsName_NeverAnIpAddress(string names, string? expected)
    {
        Assert.Equal(expected, CsrSubject.CommonNameFor(names.Split(',')));
    }

    [Fact]
    public void ANameLongerThan64Characters_IsNotTheCommonName()
    {
        var longName = new string('a', 60) + ".example.com";

        Assert.Equal("short.example.com", CsrSubject.CommonNameFor([longName, "short.example.com"]));
        Assert.Null(CsrSubject.CommonNameFor([longName]));
    }

    [Fact]
    public void TheCertesRequest_ForAnIpAddressOnly_HasNoCommonName_AndTheAddressAsAnIpName()
    {
        var request = Load(CertesAcmeProtocolClient.BuildRequest(KeyFactory.NewKey(KeyAlgorithm.ES256), ["203.0.113.10"]));

        Assert.DoesNotContain("CN=", request.SubjectName.Name, StringComparison.Ordinal);
        var names = Names(request);
        Assert.Equal([IPAddress.Parse("203.0.113.10")], names.EnumerateIPAddresses());
        Assert.Empty(names.EnumerateDnsNames());
    }

    [Fact]
    public void TheCertesRequest_WithANameAndAnAddress_UsesTheNameAsCommonName()
    {
        var request = Load(CertesAcmeProtocolClient.BuildRequest(KeyFactory.NewKey(KeyAlgorithm.ES256), ["203.0.113.10", "shop.example.com"]));

        Assert.Equal("CN=shop.example.com", request.SubjectName.Name);
        Assert.Equal(["shop.example.com"], Names(request).EnumerateDnsNames());
        Assert.Equal([IPAddress.Parse("203.0.113.10")], Names(request).EnumerateIPAddresses());
    }

    [Fact]
    public void TheReusedKeyRequest_ForAnIpAddressOnly_HasNoCommonName()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = Load(ImportedCertificateService.BuildRequest(key, ["203.0.113.10"]).CreateSigningRequest());

        Assert.Equal(string.Empty, request.SubjectName.Name);
        Assert.Equal([IPAddress.Parse("203.0.113.10")], Names(request).EnumerateIPAddresses());
    }

    private static CertificateRequest Load(byte[] der) =>
        CertificateRequest.LoadSigningRequest(der, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

    private static X509SubjectAlternativeNameExtension Names(CertificateRequest request) =>
        request.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Single();
}

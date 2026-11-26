using System.Security.Cryptography.X509Certificates;
using SSLense.Core.Iis;
using Xunit;

namespace SSLense.Tests.Iis;

/// <summary>Which bindings serve a host, and which may move to a new certificate (docs/design/other-bindings.md).</summary>
public sealed class BindingCoverageTests
{
    [Theory]
    // A binding with a host name follows only a certificate that names it.
    [InlineData("shop.example.com", "shop.example.com,admin.example.com", "admin.example.com", false)]
    [InlineData("shop.example.com", "admin.example.com", "shop.example.com", true)]
    [InlineData("shop.example.com,admin.example.com", "shop.example.com,admin.example.com", "admin.example.com", true)]
    [InlineData("*.example.com", "shop.example.com,admin.example.com", "admin.example.com", true)]
    // One without a host name answered for every name of the old certificate, so the new one must cover them all.
    [InlineData("shop.example.com", "shop.example.com,admin.example.com", "", false)]
    [InlineData("shop.example.com,admin.example.com", "shop.example.com", "", true)]
    [InlineData("*.example.com", "*.example.com", "", true)]
    [InlineData("*.example.com", "shop.example.com,www.example.com", "", true)]
    public void ABinding_FollowsOnlyACertificateThatCoversItsNames(string newNames, string oldNames, string bindingHost, bool follows)
    {
        Assert.Equal(follows, BindingCoverage.CanFollow(newNames.Split(','), oldNames.Split(','), bindingHost));
    }

    [Theory]
    [InlineData("*", "shop.example.com", true)]
    [InlineData("*", "SHOP.example.com", true)]
    [InlineData("*", "", true)]
    [InlineData("127.0.0.2", "", true)]
    [InlineData("*", "admin.example.com", false)]
    public void Removing_TakesTheHostsBindingsOnAnyPort_AndOnesWithoutAHostName(string bindingAddress, string bindingHost, bool removed)
    {
        Assert.Equal(removed, BindingCoverage.BelongsTo(bindingAddress, bindingHost, ["shop.example.com", "www.example.com"]));
    }

    [Theory]
    [InlineData("203.0.113.7", true)]
    [InlineData("203.0.113.8", false)]
    [InlineData("*", true)]
    public void Removing_AnIpAddress_TakesOnlyThatAddressesBinding(string bindingAddress, bool removed)
    {
        Assert.Equal(removed, BindingCoverage.BelongsTo(bindingAddress, "", ["203.0.113.7"]));
    }

    [Fact]
    public void ACertificatesIdentities_IncludeItsIpAddresses_SoCoverageCountsThem()
    {
        using var key = System.Security.Cryptography.ECDsa.Create();
        X509Certificate2 Create(params string[] names)
        {
            var request = new CertificateRequest("CN=test", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
            var alternative = new SubjectAlternativeNameBuilder();
            foreach (var name in names)
            {
                if (System.Net.IPAddress.TryParse(name, out var address)) alternative.AddIpAddress(address); else alternative.AddDnsName(name);
            }

            request.CertificateExtensions.Add(alternative.Build());
            return request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        }

        using var old = Create("shop.example.com", "203.0.113.7");
        using var dnsOnly = Create("shop.example.com");
        using var both = Create("shop.example.com", "203.0.113.7");

        Assert.Equal(["shop.example.com", "203.0.113.7"], BindingCoverage.IdentitiesOf(old));
        Assert.False(BindingCoverage.CanFollow(BindingCoverage.IdentitiesOf(dnsOnly), BindingCoverage.IdentitiesOf(old), ""));
        Assert.True(BindingCoverage.CanFollow(BindingCoverage.IdentitiesOf(both), BindingCoverage.IdentitiesOf(old), ""));
    }

    [Theory]
    [InlineData("*:8443:shop.example.com", "shop.example.com", "shop.example.com")]
    [InlineData("*:8443:", "shop.example.com", "")]
    [InlineData("127.0.0.2:443:", "shop.example.com", "")]
    [InlineData("203.0.113.7:443:", "203.0.113.7", "203.0.113.7")]
    public void ABindingWithoutAHostName_IsCheckedWithoutSni(string bindingInformation, string host, string expected)
    {
        Assert.Equal(expected, IisService.SniFor(bindingInformation, host));
    }

    [Theory]
    [InlineData("shop.example.com", "shop.example.com", true)]
    [InlineData("SHOP.example.com.", "shop.example.com", true)]
    [InlineData("", "shop.example.com", true)]
    [InlineData("admin.example.com", "shop.example.com", false)]
    public void ABinding_AnswersForItsHost_OrForEveryHostWithoutAHostName(string bindingHost, string host, bool answers)
    {
        Assert.Equal(answers, new IisBinding("http", "*", 80, bindingHost, null, null, false).AnswersFor(host));
    }

    [Fact]
    public void UnknownNames_NeverFollow()
    {
        Assert.False(BindingCoverage.CanFollow(null, ["shop.example.com"], "shop.example.com"));
        Assert.False(BindingCoverage.CanFollow(["shop.example.com"], null, ""));
        Assert.False(BindingCoverage.CanFollow([], ["shop.example.com"], "shop.example.com"));
    }

    [Fact]
    public void AHostIsServedByItsOwnBinding_ElseByTheSitesBindingWithoutAHostName()
    {
        var site = new IisSite(1, "Shop", "Started", null,
        [
            new IisBinding("https", "*", 443, "shop.example.com", "OWN", "My", true),
            new IisBinding("https", "*", 443, "", "HOSTLESS", "My", false),
            new IisBinding("https", "*", 8443, "admin.example.com", "OTHERPORT", "My", true),
            new IisBinding("http", "*", 80, "www.example.com", null, null, false)
        ]);

        Assert.Equal(["OWN"], site.ServingBindings("SHOP.example.com").Select(binding => binding.CertificateThumbprint));
        Assert.Equal(["HOSTLESS"], site.ServingBindings("www.example.com").Select(binding => binding.CertificateThumbprint));
        Assert.Equal(["HOSTLESS"], site.ServingBindings("admin.example.com").Select(binding => binding.CertificateThumbprint));
    }

    [Fact]
    public void AnIpAddress_IsServedOnlyByItsAddressBinding()
    {
        var site = new IisSite(1, "Shop", "Started", null,
        [
            new IisBinding("https", "*", 443, "", "HOSTLESS", "My", false),
            new IisBinding("https", "203.0.113.7", 443, "", "ADDRESS", "My", false)
        ]);

        Assert.Equal(["ADDRESS"], site.ServingBindings("203.0.113.7").Select(binding => binding.CertificateThumbprint));
        Assert.Empty(site.ServingBindings("198.51.100.1"));
    }

    [Theory]
    // The server has the address: bound there.
    [InlineData("203.0.113.7", "203.0.113.7,172.31.11.222", "203.0.113.7")]
    // Behind NAT (a cloud server): the public address is on no adapter, so the server's only IPv4 address receives it.
    [InlineData("203.0.113.7", "172.31.11.222", "172.31.11.222")]
    [InlineData("203.0.113.7", "172.31.11.222,fe80::1,2001:db8::5", "172.31.11.222")]
    // Several IPv4 addresses and none of them the public one: SSLense cannot tell.
    [InlineData("203.0.113.7", "10.0.0.4,10.0.1.4", null)]
    [InlineData("2001:db8::10", "172.31.11.222,2001:db8::5", "2001:db8::5")]
    public void AnIpAddress_IsBoundWhereItsTrafficArrives(string address, string serverAddresses, string? expected)
    {
        var server = serverAddresses.Split(',').Select(System.Net.IPAddress.Parse).ToArray();

        Assert.Equal(expected, LocalAddress.For(System.Net.IPAddress.Parse(address), server)?.ToString());
    }

    [Fact]
    public void BehindNat_ThePublicAddressIsServedAndRemoved_ThroughTheServersOwnAddress()
    {
        using var addresses = LocalAddress.UseAddressesForTesting(System.Net.IPAddress.Parse("172.31.11.222"));
        var site = new IisSite(1, "Shop", "Started", null,
        [
            new IisBinding("https", "172.31.11.222", 443, "", "NATTED", "My", false),
            new IisBinding("https", "*", 443, "shop.example.com", "OWN", "My", true)
        ]);

        Assert.Equal(["NATTED"], site.ServingBindings("203.0.113.7").Select(binding => binding.CertificateThumbprint));
        Assert.True(BindingCoverage.BelongsTo("172.31.11.222", "", ["203.0.113.7"]));
        Assert.False(BindingCoverage.BelongsTo("10.9.9.9", "", ["203.0.113.7"]));
    }

    [Fact]
    public void ASiteWithoutHttpsOn443_ServesNothing()
    {
        var site = new IisSite(1, "Shop", "Started", null, [new IisBinding("https", "*", 8443, "shop.example.com", "X", "My", true)]);

        Assert.Empty(site.ServingBindings("shop.example.com"));
    }
}

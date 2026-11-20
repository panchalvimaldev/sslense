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

    [Fact]
    public void ASiteWithoutHttpsOn443_ServesNothing()
    {
        var site = new IisSite(1, "Shop", "Started", null, [new IisBinding("https", "*", 8443, "shop.example.com", "X", "My", true)]);

        Assert.Empty(site.ServingBindings("shop.example.com"));
    }
}

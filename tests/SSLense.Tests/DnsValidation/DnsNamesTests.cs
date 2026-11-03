using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class DnsNamesTests
{
    [Theory]
    [InlineData("example.com", "_acme-challenge.example.com")]
    [InlineData("WWW.Example.com.", "_acme-challenge.www.example.com")]
    [InlineData("*.example.com", "_acme-challenge.example.com")]
    public void ChallengeRecord_UsesTheBaseNameOfAWildcard(string name, string expected) =>
        Assert.Equal(expected, DnsNames.ChallengeRecord(name));

    [Fact]
    public void SelectProfile_PrefersTheLongestMatchingZone()
    {
        var parent = Profile("Parent", "example.com");
        var child = Profile("Child", "dev.example.com");

        Assert.Equal(child, DnsNames.SelectProfile([parent, child], "_acme-challenge.app.dev.example.com"));
        Assert.Equal(parent, DnsNames.SelectProfile([parent, child], "_acme-challenge.www.example.com"));
    }

    [Theory]
    [InlineData("_acme-challenge.notexample.com")]
    [InlineData("_acme-challenge.example.com.evil.net")]
    [InlineData("com")]
    public void SelectProfile_MatchesWholeLabelsOnly(string record) =>
        Assert.Null(DnsNames.SelectProfile([Profile("Main", "example.com")], record));

    private static DnsProviderProfile Profile(string name, string zone) =>
        new(name, DnsProviderType.Cloudflare, zone, new string('a', 32), "protected");
}

using SSLense.Core.DnsValidation;
using Xunit;

namespace SSLense.Tests.DnsValidation;

public sealed class CaaPolicyTests
{
    private const string Ca = "letsencrypt.org";

    [Theory]
    [InlineData("example.com", "issue", "letsencrypt.org")]
    [InlineData("example.com", "ISSUE", "LetsEncrypt.org")]
    [InlineData("example.com", "issue", "letsencrypt.org; accounturi=https://example.net/1")]
    [InlineData("example.com", "iodef", "mailto:admin@example.com")]
    [InlineData("example.com", "issuewild", ";")]
    [InlineData("*.example.com", "issuewild", "letsencrypt.org")]
    [InlineData("*.example.com", "issue", "letsencrypt.org")]
    public void Allowed(string name, string tag, string value) =>
        Assert.Null(CaaPolicy.FindProblem(name, "example.com", [new DnsCaaRecord(0, tag, value)], Ca));

    [Theory]
    [InlineData("example.com", "issue", "other-ca.example")]
    [InlineData("example.com", "issue", ";")]
    [InlineData("*.example.com", "issue", "other-ca.example")]
    [InlineData("*.example.com", "issuewild", ";")]
    public void Refused(string name, string tag, string value) =>
        Assert.Contains(Ca, CaaPolicy.FindProblem(name, "example.com", [new DnsCaaRecord(0, tag, value)], Ca), StringComparison.Ordinal);

    [Fact]
    public void Wildcard_IssuewildTakesPrecedenceOverIssue()
    {
        var records = new[] { new DnsCaaRecord(0, "issue", Ca), new DnsCaaRecord(0, "issuewild", "other-ca.example") };

        Assert.NotNull(CaaPolicy.FindProblem("*.example.com", "example.com", records, Ca));
        Assert.Null(CaaPolicy.FindProblem("example.com", "example.com", records, Ca));
    }

    [Fact]
    public void OneAllowingRecordAmongSeveralIsEnough() =>
        Assert.Null(CaaPolicy.FindProblem(
            "example.com",
            "example.com",
            [new DnsCaaRecord(0, "issue", "other-ca.example"), new DnsCaaRecord(0, "issue", Ca)],
            Ca));

    [Fact]
    public void UnknownCriticalTag_IsRefused()
    {
        var problem = CaaPolicy.FindProblem(
            "example.com",
            "example.com",
            [new DnsCaaRecord(128, "future", "x"), new DnsCaaRecord(0, "issue", Ca)],
            Ca);

        Assert.Contains("critical", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownTagThatIsNotCritical_IsIgnored() =>
        Assert.Null(CaaPolicy.FindProblem("example.com", "example.com", [new DnsCaaRecord(0, "future", "x")], Ca));
}

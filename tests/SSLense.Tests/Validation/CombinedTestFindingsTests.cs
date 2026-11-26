using SSLense.Core.DnsValidation;
using SSLense.Core.Iis;
using SSLense.Core.Validation;
using Xunit;

namespace SSLense.Tests.Validation;

/// <summary>Small messages and checks improved after the combined test on a real server (November 2026).</summary>
public sealed class CombinedTestFindingsTests
{
    [Theory]
    [InlineData(401, "IUSR and IIS_IUSRS need read access")]
    [InlineData(403, "anonymous access")]
    [InlineData(404, "Default Web Site")]
    [InlineData(500, @"C:\inetpub\history")]
    [InlineData(502, "web.config")]
    [InlineData(301, "Host header")]
    public void TheSelfCheckStatus_SaysWhatItUsuallyMeans(int status, string expected)
    {
        Assert.Contains(expected, HttpChallengeProbe.StatusHint(status), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(@"%SystemDrive%\inetpub\history", true)]
    [InlineData(@"%SystemDrive%\inetpub\history\", true)]
    [InlineData(@"%SystemDrive%\inetpub\HISTORY\CFGHISTORY_0000000001", true)]
    [InlineData(@"%SystemDrive%\inetpub\historytest", false)]
    [InlineData(@"%SystemDrive%\inetpub\wwwroot", false)]
    public void IisConfigurationHistory_IsNeverASitesFolder(string path, bool expected)
    {
        Assert.Equal(expected, IisFolders.IsConfigHistory(path));
    }

    [Fact]
    public void AServicesXmlError_ShowsItsMessage_NotTheDocument()
    {
        const string route53 = """
            <?xml version="1.0"?>
            <ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User: arn:aws:iam::123456789012:user/sslense is not authorized to perform: route53:GetHostedZone</Message></Error><RequestId>abc</RequestId></ErrorResponse>
            """;

        var excerpt = HttpDnsProvider.Excerpt(route53);

        Assert.Equal("User: arn:aws:iam::123456789012:user/sslense is not authorized to perform: route53:GetHostedZone.", excerpt);
    }

    [Theory]
    [InlineData("""{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization."}}""", "The client does not have authorization.")]
    [InlineData("""{"id":"unauthorized","message":"Unable to authenticate you"}""", "Unable to authenticate you.")]
    [InlineData("""{"errors":[{"message":"zone not found"}]}""", "zone not found.")]
    [InlineData("plain text answer", "plain text answer.")]
    [InlineData("<html><body>Bad gateway", "<html><body>Bad gateway.")]
    public void AServicesJsonOrTextError_ShowsItsMessage(string body, string expected)
    {
        Assert.Equal(expected, HttpDnsProvider.Excerpt(body));
    }
}

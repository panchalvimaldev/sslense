using SSLense.Core.Acme;

namespace SSLense.Core.Validation;

public interface IChallengeHandler
{
    Task<IAsyncDisposable> PrepareAsync(
        string sitePhysicalPath,
        AcmeHttpChallenge challenge,
        CancellationToken cancellationToken);
}

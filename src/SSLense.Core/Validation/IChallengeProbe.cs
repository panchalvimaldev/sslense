using SSLense.Core.Acme;

namespace SSLense.Core.Validation;

public interface IChallengeProbe
{
    Task VerifyAsync(AcmeHttpChallenge challenge, CancellationToken cancellationToken);
}

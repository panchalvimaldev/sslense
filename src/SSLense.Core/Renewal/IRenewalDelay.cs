namespace SSLense.Core.Renewal;

public interface IRenewalDelay
{
    Task WaitAsync(TimeSpan delay, CancellationToken cancellationToken);
}

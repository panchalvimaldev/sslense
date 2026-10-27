namespace SSLense.Core.Renewal;

internal sealed class RenewalDelay : IRenewalDelay
{
    public Task WaitAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

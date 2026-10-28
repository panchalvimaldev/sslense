namespace SSLense.Core.Renewal;

/// <summary>
/// Warns about approaching expiry independently of renewal scheduling, so a broken schedule,
/// ARI outage, or repeated renewal failure still produces an alert.
/// </summary>
public interface IExpiryMonitor
{
    /// <summary>
    /// Sends each certificate's highest newly reached warning level once. Returns a message for each
    /// notification sent or failed; failed sends are retried on the next check.
    /// </summary>
    Task<IReadOnlyList<string>> CheckAsync(CancellationToken cancellationToken = default);
}

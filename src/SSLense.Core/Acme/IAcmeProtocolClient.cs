namespace SSLense.Core.Acme;

public interface IAcmeProtocolClient
{
    Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken);

    Task<IAcmeOrderSession> CreateOrderAsync(
        string email,
        IReadOnlyList<string> hosts,
        AcmeEnvironment environment,
        CancellationToken cancellationToken);
}

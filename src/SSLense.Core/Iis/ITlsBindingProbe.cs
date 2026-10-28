namespace SSLense.Core.Iis;

public interface ITlsBindingProbe
{
    /// <summary>
    /// Connects to <paramref name="ipAddress"/>:<paramref name="port"/> with SNI set to
    /// <paramref name="host"/> and returns the thumbprint of the certificate actually served.
    /// </summary>
    Task<string> GetServedThumbprintAsync(
        string ipAddress,
        string host,
        int port,
        CancellationToken cancellationToken);
}

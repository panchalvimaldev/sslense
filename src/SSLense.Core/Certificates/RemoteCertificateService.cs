using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using SSLense.Core.Config;
using SSLense.Core.Errors;
using SSLense.Core.Iis;

namespace SSLense.Core.Certificates;

/// <summary>Reads the certificate a host serves over TLS, without trusting or changing anything.</summary>
public interface IRemoteCertificateReader
{
    Task<X509Certificate2> ReadAsync(string host, int port, CancellationToken cancellationToken);
}

/// <summary>
/// Certificates on other machines, such as load balancers and appliances (docs/design/remote-certificates.md): SSLense
/// reads them over TLS, reminds before they expire, and notices when they are replaced. It never changes them.
/// </summary>
public interface IRemoteCertificateService
{
    /// <summary>Starts watching the certificate <paramref name="host"/> serves on <paramref name="port"/>, under <paramref name="name"/>.</summary>
    Task<ManagedCertificate> WatchAsync(string name, string host, int port = 443, CancellationToken cancellationToken = default);
}

internal sealed class RemoteCertificateReader : IRemoteCertificateReader
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public async Task<X509Certificate2> ReadAsync(string host, int port, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        X509Certificate2? served = null;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, port, timeout.Token).ConfigureAwait(false);
            await using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, certificate, _, _) =>
            {
                // Read, not trusted: an expired or untrusted certificate is exactly what the reminder is for.
                if (certificate is not null)
                {
                    served = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                }

                return true;
            });
            await stream.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions { TargetHost = Uri.CheckHostName(host) == UriHostNameType.Dns ? host : null },
                    timeout.Token)
                .ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is SocketException or IOException or System.Security.Authentication.AuthenticationException ||
                                          exception is OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            served?.Dispose();
            throw new SslenseException(ErrorCodes.RemoteUnreachable,
                $"Could not read the certificate served by {host}:{port}: {(exception is OperationCanceledException ? "it did not answer within 10 seconds" : exception.Message)}",
                exception);
        }

        return served ?? throw new SslenseException(ErrorCodes.RemoteUnreachable, $"{host}:{port} served no certificate.");
    }
}

internal sealed partial class RemoteCertificateService(
    IManagedCertificateStore managedStore,
    IIisService iisService,
    IRemoteCertificateReader reader) : IRemoteCertificateService
{
    public async Task<ManagedCertificate> WatchAsync(string name, string host, int port = 443, CancellationToken cancellationToken = default)
    {
        name = name?.Trim() ?? string.Empty;
        host = host?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
        if (!Name().IsMatch(name))
        {
            throw new ArgumentException(ErrorCodes.InvalidCertificateName.Format(
                $"'{name}' cannot name a certificate. Use letters, digits, spaces, dots, hyphens, underscores, and brackets, up to 100 characters."));
        }

        if (Uri.CheckHostName(host) is not (UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6) || port is < 1 or > 65535)
        {
            throw new ArgumentException(ErrorCodes.InvalidHostName.Format($"'{host}:{port}' is not a host name or address with a port."));
        }

        var records = await managedStore.GetAllAsync(cancellationToken).ConfigureAwait(false);
        var sites = await iisService.GetSitesAsync(cancellationToken).ConfigureAwait(false);
        if (records.Any(record => string.Equals(record.SiteName, name, StringComparison.OrdinalIgnoreCase)) || sites.FindSite(name) is not null)
        {
            throw new SslenseException(ErrorCodes.RemoteNameTaken,
                $"'{name}' already names a certificate or an IIS site. Choose another name for the certificate on {host}.");
        }

        using var certificate = await reader.ReadAsync(host, port, cancellationToken).ConfigureAwait(false);
        var record = Describe(name, host, port, certificate);
        await managedStore.UpsertAsync(record, cancellationToken).ConfigureAwait(false);
        return record;
    }

    internal static ManagedCertificate Describe(string name, string host, int port, X509Certificate2 certificate) =>
        new(
            name,
            [host],
            string.Empty,
            certificate.Thumbprint,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            LastRenewalMessage: $"Watched on {host}:{port}.",
            Source: CertificateSource.Remote,
            Issuer: certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
            NoSite: true,
            RemotePort: port == 443 ? null : port);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}$")]
    private static partial Regex Name();
}

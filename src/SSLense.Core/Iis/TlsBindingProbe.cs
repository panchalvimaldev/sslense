using SSLense.Core.Errors;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace SSLense.Core.Iis;

internal sealed class TlsBindingProbe : ITlsBindingProbe
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    public async Task<string> GetServedThumbprintAsync(
        string ipAddress,
        string host,
        int port,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ipAddress);
        // An empty host sends no SNI, as a client reaching a binding without a host name would (docs/design/other-bindings.md).
        ArgumentNullException.ThrowIfNull(host);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        using var client = new TcpClient(ipAddress.Contains(':') ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork);
        await client.ConnectAsync(ipAddress, port, timeout.Token).ConfigureAwait(false);

        string? thumbprint = null;
        await using var stream = new SslStream(
            client.GetStream(),
            leaveInnerStreamOpen: false,
            (_, certificate, _, _) =>
            {
                // Only the served certificate's identity is compared; staging chains are untrusted by design.
                if (certificate is not null)
                {
                    using var served = new X509Certificate2(certificate);
                    thumbprint = served.Thumbprint;
                }

                return true;
            });
        await stream.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = host },
                timeout.Token)
            .ConfigureAwait(false);

        return thumbprint
            ?? throw new SslenseException(ErrorCodes.NoCertificateServed, $"No certificate was served for '{(host.Length > 0 ? host : ipAddress)}' on port {port}.");
    }
}

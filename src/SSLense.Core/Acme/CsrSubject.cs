using System.Net;

namespace SSLense.Core.Acme;

/// <summary>
/// The common name a certificate request carries. Let's Encrypt refuses an IP address there ("CSR contains IP address in
/// Common Name") and a name longer than 64 characters, the RFC 5280 limit; every name, IP addresses included, is in the
/// subject alternative names anyway (docs/design/ip-certificates.md).
/// </summary>
internal static class CsrSubject
{
    private const int MaxCommonNameLength = 64;

    /// <summary>The first DNS name that fits, or null for a request with no common name, such as one for IP addresses only.</summary>
    public static string? CommonNameFor(IEnumerable<string> names) =>
        names.FirstOrDefault(name => !IPAddress.TryParse(name.Trim('[', ']'), out _) && name.Length <= MaxCommonNameLength);
}

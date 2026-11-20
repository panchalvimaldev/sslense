using SSLense.Core.Certificates;

namespace SSLense.Core.Iis;

/// <summary>
/// Which HTTPS bindings serve a host, and which may move to a new certificate (docs/design/other-bindings.md). One place,
/// so switching certificates and checking them afterwards always agree.
/// </summary>
public static class BindingCoverage
{
    /// <summary>
    /// The bindings on port 443 that serve the host: its own (an SNI binding by name, or an IP address bound by address),
    /// or else the site's bindings without a host name, which serve every name that reaches them.
    /// </summary>
    public static IReadOnlyList<IisBinding> ServingBindings(this IisSite site, string host)
    {
        ArgumentNullException.ThrowIfNull(site);
        var https = site.Bindings
            .Where(binding => string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase) && binding.Port == 443)
            .ToArray();
        var isAddress = System.Net.IPAddress.TryParse(host, out var address);
        var own = https
            .Where(binding => isAddress
                ? binding.HostName.Length == 0 && System.Net.IPAddress.TryParse(binding.IpAddress.Trim('[', ']'), out var bound) && bound.Equals(address)
                : string.Equals(binding.HostName, host, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        return own.Length > 0 || isAddress ? own : [.. https.Where(binding => binding.HostName.Length == 0)];
    }

    /// <summary>
    /// Whether a binding that served the replaced certificate may take the new one: a binding with a host name when the new
    /// certificate covers it; one without a host name when the new certificate covers every name the old one did, since
    /// that binding answered for all of them. Unknown names never qualify, so a binding stays on its certificate rather
    /// than serve one without its name.
    /// </summary>
    internal static bool CanFollow(IReadOnlyList<string>? newNames, IReadOnlyList<string>? oldNames, string bindingHost) =>
        newNames is { Count: > 0 } &&
        (bindingHost.Length > 0
            ? CertificateInspector.Covers(newNames, bindingHost)
            : oldNames is { Count: > 0 } && oldNames.All(name => CertificateInspector.Covers(newNames, name)));
}

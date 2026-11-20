using SSLense.Core.Errors;
using System.Globalization;
using System.Net;

namespace SSLense.Core.Iis;

/// <summary>
/// Where HTTP.sys binds a certificate outside IIS (docs/design/httpsys-bindings.md): an IP address and port, such as
/// <c>0.0.0.0:8443</c> or <c>[::]:8443</c>, or a host name and port for SNI, such as <c>api.example.com:8443</c>.
/// </summary>
public sealed record HttpSysEndpoint(string Address, int Port, bool IsHostName)
{
    /// <summary>The netsh parameter that names it: <c>ipport=…</c> or <c>hostnameport=…</c>.</summary>
    public string NetshParameter => IsHostName ? $"hostnameport={this}" : $"ipport={this}";

    public override string ToString() =>
        !IsHostName && Address.Contains(':', StringComparison.Ordinal) ? $"[{Address}]:{Port}" : $"{Address}:{Port}";

    public static HttpSysEndpoint Parse(string value)
    {
        var text = value.Trim();
        var colon = text.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(text[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
        {
            throw Invalid(value);
        }

        var address = text[..colon].Trim('[', ']');
        if (IPAddress.TryParse(address, out var ip))
        {
            return new HttpSysEndpoint(ip.ToString(), port, IsHostName: false);
        }

        if (Uri.CheckHostName(address) != UriHostNameType.Dns || address.StartsWith('*'))
        {
            throw Invalid(value);
        }

        return new HttpSysEndpoint(address.ToLowerInvariant(), port, IsHostName: true);
    }

    private static ArgumentException Invalid(string value) => new(ErrorCodes.DeploymentStepInvalid.Format(
        $"'{value}' is not an HTTP.sys endpoint. Use an IP address and port, such as 0.0.0.0:8443, or a host name and port, such as api.example.com:8443."));
}

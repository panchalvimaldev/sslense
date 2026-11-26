using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace SSLense.Core.Iis;

/// <summary>
/// Where traffic for an IP address arrives on this server (docs/design/ip-certificates.md). Usually the address itself; behind
/// NAT, as on a cloud server, the public address is not on any network adapter and its traffic arrives at the server's own
/// address, so a certificate for the public address is bound there.
/// </summary>
internal static class LocalAddress
{
    private static readonly AsyncLocal<IReadOnlyList<IPAddress>?> TestAddresses = new();

    /// <summary>Tests choose the server's addresses for the code they run, so the result never depends on the machine running them.</summary>
    internal static IDisposable UseAddressesForTesting(params IPAddress[] addresses)
    {
        var previous = TestAddresses.Value;
        TestAddresses.Value = addresses;
        return new Restore(() => TestAddresses.Value = previous);
    }

    private sealed class Restore(Action restore) : IDisposable
    {
        public void Dispose() => restore();
    }

    /// <summary>
    /// The address itself when this server has it; otherwise this server's only address of the same family (IPv4 or IPv6);
    /// otherwise null, because it cannot tell which one receives the traffic.
    /// </summary>
    public static IPAddress? For(IPAddress address) => For(address, ServerAddresses());

    internal static IPAddress? For(IPAddress address, IReadOnlyList<IPAddress> serverAddresses)
    {
        if (serverAddresses.Contains(address))
        {
            return address;
        }

        var sameFamily = serverAddresses
            .Where(candidate => candidate.AddressFamily == address.AddressFamily && Usable(candidate))
            .Distinct()
            .ToArray();
        return sameFamily.Length == 1 ? sameFamily[0] : null;
    }

    /// <summary>Whether a binding on <paramref name="bindingAddress"/> receives the traffic for <paramref name="address"/>.</summary>
    public static bool Receives(string bindingAddress, IPAddress address) =>
        IPAddress.TryParse(bindingAddress.Trim('[', ']'), out var bound) &&
        (bound.Equals(address) || bound.Equals(For(address)));

    /// <summary>This server's addresses that can receive traffic, for messages and the check before ordering.</summary>
    public static IReadOnlyList<IPAddress> ServerAddresses()
    {
        if (TestAddresses.Value is { } chosen)
        {
            return chosen;
        }

        try
        {
            return
            [
                .. NetworkInterface.GetAllNetworkInterfaces()
                    .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up && adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .SelectMany(adapter => adapter.GetIPProperties().UnicastAddresses)
                    .Select(unicast => unicast.Address)
                    .Where(Usable)
            ];
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    private static bool Usable(IPAddress candidate) =>
        !IPAddress.IsLoopback(candidate) &&
        !(candidate.AddressFamily == AddressFamily.InterNetworkV6 && (candidate.IsIPv6LinkLocal || candidate.IsIPv6Multicast)) &&
        !(candidate.AddressFamily == AddressFamily.InterNetwork && candidate.GetAddressBytes() is [169, 254, ..]);
}

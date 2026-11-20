using Microsoft.Win32;
using SSLense.Core.Errors;

namespace SSLense.Core.Deployment;

/// <summary>
/// Where Remote Desktop and SQL Server read their certificate (docs/design/service-targets.md). Both keep it in the
/// registry, so no PowerShell, WMI package or SQL Server tool is needed.
/// </summary>
internal interface IServiceCertificateSettings
{
    bool HasRemoteDesktopListener();

    /// <summary>The RDP-Tcp listener's certificate. New connections use it at once.</summary>
    void SetRemoteDesktopCertificate(string thumbprint);

    string? GetRemoteDesktopCertificate();

    /// <summary>The instance's Windows service name, such as MSSQLSERVER or MSSQL$SQLEXPRESS; null when it is not installed.</summary>
    string? FindSqlServerService(string instanceName);

    /// <summary>The certificate SQL Server encrypts connections with, read when it starts.</summary>
    void SetSqlServerCertificate(string instanceName, string thumbprint);

    string? GetSqlServerCertificate(string instanceName);
}

internal sealed class RegistryServiceCertificateSettings : IServiceCertificateSettings
{
    private const string RdpListenerKey = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
    private const string RdpValue = "SSLCertificateSHA1Hash";
    private const string SqlInstancesKey = @"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";

    public bool HasRemoteDesktopListener()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RdpListenerKey);
        return key is not null;
    }

    public void SetRemoteDesktopCertificate(string thumbprint)
    {
        using var key = Registry.LocalMachine.OpenSubKey(RdpListenerKey, writable: true)
            ?? throw new SslenseException(ErrorCodes.ServiceTargetMissing, "The Remote Desktop listener RDP-Tcp was not found. Turn on Remote Desktop first.");
        key.SetValue(RdpValue, Convert.FromHexString(thumbprint), RegistryValueKind.Binary);
    }

    public string? GetRemoteDesktopCertificate()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RdpListenerKey);
        return key?.GetValue(RdpValue) is byte[] hash ? Convert.ToHexString(hash) : null;
    }

    public string? FindSqlServerService(string instanceName) =>
        InstanceId(instanceName) is null
            ? null
            : string.Equals(instanceName, "MSSQLSERVER", StringComparison.OrdinalIgnoreCase) ? "MSSQLSERVER" : $"MSSQL${instanceName.ToUpperInvariant()}";

    public void SetSqlServerCertificate(string instanceName, string thumbprint)
    {
        using var key = SqlNetworkKey(instanceName, writable: true)
            ?? throw new SslenseException(ErrorCodes.ServiceTargetMissing, $"No SQL Server instance named '{instanceName}' is installed.");

        // SQL Server Configuration Manager writes the thumbprint in lower case, and some versions compare it as text.
        key.SetValue("Certificate", thumbprint.ToLowerInvariant(), RegistryValueKind.String);
    }

    public string? GetSqlServerCertificate(string instanceName)
    {
        using var key = SqlNetworkKey(instanceName, writable: false);
        return key?.GetValue("Certificate") as string is { Length: > 0 } value ? value.ToUpperInvariant() : null;
    }

    private static string? InstanceId(string instanceName)
    {
        using var key = Registry.LocalMachine.OpenSubKey(SqlInstancesKey);
        return key?.GetValue(instanceName) as string;
    }

    private static RegistryKey? SqlNetworkKey(string instanceName, bool writable) =>
        InstanceId(instanceName) is { } id
            ? Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Microsoft\Microsoft SQL Server\{id}\MSSQLServer\SuperSocketNetLib", writable)
            : null;
}

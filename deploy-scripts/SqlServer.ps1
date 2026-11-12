<#
.SYNOPSIS
    Makes a SQL Server instance on this server encrypt connections with the certificate.

        SSLense.Cli deploy add --site "Shop" --grant-key-access "NT Service\MSSQLSERVER"
        SSLense.Cli deploy add --site "Shop" --script "C:\Program Files\SSLense\deploy-scripts\SqlServer.ps1"
        SSLense.Cli deploy add --site "Shop" --restart-service MSSQLSERVER
        SSLense.Cli deploy run --site "Shop"

.DESCRIPTION
    Writes the certificate's thumbprint where SQL Server reads it, for the instance named in $InstanceName below. SQL
    Server reads it only when it starts, so the service is restarted by the third step: plan for a short interruption
    at every renewal, or leave that step out and restart SQL Server yourself.

    For a named instance, copy this script, change $InstanceName (for example to 'SQLEXPRESS'), and use the instance's
    account and service: 'NT Service\MSSQL$SQLEXPRESS' and 'MSSQL$SQLEXPRESS'.

    The certificate must include the server's fully qualified name, or SQL Server will not start with it. Check the
    SQL Server error log after the first run.
#>
param(
    [Parameter(Mandatory)][string]$Thumbprint,
    [string]$PreviousThumbprint,
    [string]$Hosts,
    [string]$NotAfter,
    [string]$Site
)

# The instance to configure: MSSQLSERVER for the default instance.
$InstanceName = 'MSSQLSERVER'

$ErrorActionPreference = 'Stop'

try {
    if (-not (Test-Path "Cert:\LocalMachine\My\$Thumbprint")) {
        throw "The certificate $Thumbprint is not in LocalMachine\My."
    }

    $instances = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    $instanceId = $instances.$InstanceName
    if (-not $instanceId) {
        throw "No SQL Server instance named '$InstanceName' is installed. Change `$InstanceName in this script."
    }

    $key = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer\SuperSocketNetLib"
    $current = (Get-ItemProperty $key -Name Certificate -ErrorAction SilentlyContinue).Certificate

    # SQL Server expects the thumbprint in lower case.
    $wanted = $Thumbprint.ToLowerInvariant()
    if ($current -eq $wanted) {
        Write-Output "SQL Server '$InstanceName' already uses $Thumbprint."
        exit 0
    }

    Set-ItemProperty $key -Name Certificate -Value $wanted
    Write-Output "SQL Server '$InstanceName' will use $Thumbprint from its next start (was '$current')."
    exit 0
}
catch {
    Write-Output "SQL Server was not updated: $($_.Exception.Message)"
    exit 1
}

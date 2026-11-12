<#
.SYNOPSIS
    Makes Remote Desktop on this server use the certificate, so connecting by its name shows no warning.

        SSLense.Cli deploy add --site "Shop" --grant-key-access "NT AUTHORITY\NETWORK SERVICE"
        SSLense.Cli deploy add --site "Shop" --script "C:\Program Files\SSLense\deploy-scripts\RemoteDesktop.ps1"
        SSLense.Cli deploy run --site "Shop"

.DESCRIPTION
    Sets the certificate of the RDP-Tcp listener. The Remote Desktop service runs as NETWORK SERVICE and must be able to
    read the private key, which the first step above gives it. New connections use the certificate at once; no restart
    is needed, and open sessions stay connected.

    The certificate must include the name people connect to. A certificate that does not is used anyway, and they see
    a name mismatch warning instead of an unknown-certificate one.

    For a Remote Desktop Services deployment with a gateway, web access, or connection broker, use Set-RDCertificate
    on the connection broker instead; this script sets only this server's own listener.
#>
param(
    [Parameter(Mandatory)][string]$Thumbprint,
    [string]$PreviousThumbprint,
    [string]$Hosts,
    [string]$NotAfter,
    [string]$Site
)

$ErrorActionPreference = 'Stop'

try {
    if (-not (Test-Path "Cert:\LocalMachine\My\$Thumbprint")) {
        throw "The certificate $Thumbprint is not in LocalMachine\My."
    }

    $listener = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName 'Win32_TSGeneralSetting' -Filter "TerminalName='RDP-Tcp'"
    if ($null -eq $listener) {
        throw 'The RDP-Tcp listener was not found. Is Remote Desktop enabled?'
    }

    if ($listener.SSLCertificateSHA1Hash -eq $Thumbprint) {
        Write-Output "Remote Desktop already uses $Thumbprint."
        exit 0
    }

    Set-CimInstance -InputObject $listener -Property @{ SSLCertificateSHA1Hash = $Thumbprint }
    Write-Output "Remote Desktop now uses $Thumbprint (was $($listener.SSLCertificateSHA1Hash))."
    exit 0
}
catch {
    Write-Output "Remote Desktop was not updated: $($_.Exception.Message)"
    exit 1
}

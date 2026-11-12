<#
.SYNOPSIS
    Makes Exchange Server use the certificate for the services listed in $Services below.

        SSLense.Cli deploy add --site "Default Web Site" --script "C:\Program Files\SSLense\deploy-scripts\Exchange.ps1" --timeout 600
        SSLense.Cli deploy run --site "Default Web Site"

.DESCRIPTION
    Runs Enable-ExchangeCertificate in the Exchange Management Shell on this server. SSLense already binds the
    certificate in IIS for Outlook on the web and ActiveSync; this script hands it to the other services, SMTP by
    default.

    The renewal service runs this script as SYSTEM through the Exchange snap-in. Test it with 'deploy run' first; if
    your Exchange version refuses, run the same command from a scheduled task under an Exchange administrator instead.

    The certificate must include every name clients and other mail servers use, such as mail.example.com and
    autodiscover.example.com.
#>
param(
    [Parameter(Mandatory)][string]$Thumbprint,
    [string]$PreviousThumbprint,
    [string]$Hosts,
    [string]$NotAfter,
    [string]$Site
)

# The Exchange services to use the certificate for: any of SMTP, IMAP, POP, IIS.
$Services = 'SMTP'

$ErrorActionPreference = 'Stop'

try {
    if (-not (Get-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) {
        Add-PSSnapin 'Microsoft.Exchange.Management.PowerShell.SnapIn'
    }

    $certificate = Get-ExchangeCertificate -Thumbprint $Thumbprint
    if ($null -eq $certificate) {
        throw "Exchange does not see the certificate $Thumbprint in LocalMachine\My."
    }

    # -Force also replaces the default SMTP certificate without asking, which a script cannot answer.
    Enable-ExchangeCertificate -Thumbprint $Thumbprint -Services $Services -Force
    Write-Output "Exchange uses $Thumbprint for $Services."
    exit 0
}
catch {
    Write-Output "Exchange was not updated: $($_.Exception.Message)"
    exit 1
}
